use crate::config::RateLimitConfig;
use crate::screener::RequestScreener;
use crate::types::{OnBlocked, RateLimitEntry, SecurityContext};
use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;

pub struct RateLimiter<B: OnBlocked> {
    rate_limit_cache: Arc<DashMap<String, RateLimitEntry>>,
    config: RateLimitConfig,
    on_blocked: Arc<B>,
    screener: Option<Arc<RequestScreener>>,
}

impl<B: OnBlocked + 'static> RateLimiter<B> {
    pub fn new(config: RateLimitConfig, on_blocked: B) -> Self {
        Self {
            rate_limit_cache: Arc::new(DashMap::new()),
            config,
            on_blocked: Arc::new(on_blocked),
            screener: None,
        }
    }

    pub fn with_screener(mut self, screener: RequestScreener) -> Self {
        self.screener = Some(Arc::new(screener));
        self
    }

    pub fn screener(&self) -> Option<&RequestScreener> {
        self.screener.as_deref()
    }

    pub async fn check_rate_limit(
        &self,
        key: &str,
        context: &SecurityContext,
        path: &str,
    ) -> (bool, bool, f64) {
        let now = Utc::now();

        if let Some(entry) = self.rate_limit_cache.get(key) {
            if let Some(blocked_until) = entry.blocked_until {
                if now < blocked_until {
                    return (false, false, 0.0);
                }
            }
        }

        let max_tokens = self.config.max_tokens();
        let mut entry = self
            .rate_limit_cache
            .entry(key.to_string())
            .or_insert_with(|| RateLimitEntry::new(max_tokens));

        let entry_age = now.signed_duration_since(entry.created_at);
        if entry_age.num_seconds() < self.config.grace_period_seconds as i64 {
            return (true, false, max_tokens);
        }

        let elapsed = now
            .signed_duration_since(entry.last_refill)
            .num_seconds()
            .max(0) as f64;
        let refill_rate = self.config.refill_rate_per_second();
        entry.tokens = (entry.tokens + elapsed * refill_rate).min(max_tokens);
        entry.last_refill = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            let remaining_tokens = entry.tokens;
            (true, false, remaining_tokens)
        } else {
            if entry.blocked_until.is_none() {
                let block_duration_chrono = chrono::Duration::from_std(self.config.block_duration)
                    .unwrap_or(chrono::Duration::minutes(15));
                entry.blocked_until = Some(now + block_duration_chrono);

                tracing::warn!(
                    "IP exceeded rate limit: {} (path: {}, tokens: {:.2})",
                    context.ip_address,
                    path,
                    entry.tokens
                );

                // Call on_blocked directly - spawn a task to avoid blocking the rate limit check
                let on_blocked = self.on_blocked.clone();
                let ip = context.ip_address.clone();
                let path = path.to_string();
                let context = context.clone();

                tokio::spawn(async move {
                    on_blocked.on_blocked(&ip, &path, &context).await;
                });

                (false, true, 0.0)
            } else {
                (false, false, 0.0)
            }
        }
    }

    pub fn cleanup_cache(&self) {
        let now = Utc::now();
        let cache_retention = chrono::Duration::from_std(self.config.block_duration)
            .unwrap_or(chrono::Duration::minutes(15))
            * 2;

        let before_count = self.rate_limit_cache.len();

        self.rate_limit_cache.retain(|_, entry| {
            if let Some(blocked_until) = entry.blocked_until {
                if now < blocked_until {
                    return true;
                }
            }

            let inactive_duration = now.signed_duration_since(entry.last_refill);
            inactive_duration < cache_retention
        });

        let after_count = self.rate_limit_cache.len();

        if before_count > after_count {
            tracing::info!(
                "Cleaned up {} old rate limit cache entries ({} -> {} entries)",
                before_count - after_count,
                before_count,
                after_count
            );
        }
    }

    pub fn refund_tokens(&self, key: &str, amount: f64) {
        if let Some(mut entry) = self.rate_limit_cache.get_mut(key) {
            let max_tokens = self.config.max_tokens();
            entry.tokens = (entry.tokens + amount).min(max_tokens);

            tracing::debug!(
                "Refunded {:.2} tokens to {} (new balance: {:.2})",
                amount,
                key,
                entry.tokens
            );
        }
    }

    pub fn consume_additional_tokens(&self, key: &str, amount: f64) {
        if let Some(mut entry) = self.rate_limit_cache.get_mut(key) {
            entry.tokens -= amount;

            tracing::debug!(
                "Consumed additional {:.2} tokens from {} (new balance: {:.2})",
                amount,
                key,
                entry.tokens
            );
        }
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Immediately block an IP address, draining all tokens and setting blocked_until.
    /// Caller should ensure the IP is not already blocked before calling this.
    pub fn block_immediately(&self, key: &str) {
        let now = Utc::now();
        let max_tokens = self.config.max_tokens();

        let mut entry = self
            .rate_limit_cache
            .entry(key.to_string())
            .or_insert_with(|| RateLimitEntry::new(max_tokens));

        entry.tokens = 0.0;
        let block_duration_chrono = chrono::Duration::from_std(self.config.block_duration)
            .unwrap_or(chrono::Duration::minutes(15));
        entry.blocked_until = Some(now + block_duration_chrono);
    }

    pub fn get_cache_stats(&self) -> (usize, usize) {
        let now = Utc::now();
        let total_size = self.rate_limit_cache.len();
        let blocked_count = self
            .rate_limit_cache
            .iter()
            .filter(|entry| {
                if let Some(blocked_until) = entry.blocked_until {
                    now < blocked_until
                } else {
                    false
                }
            })
            .count();

        (total_size, blocked_count)
    }

    #[cfg(feature = "metrics")]
    pub fn update_metrics(&self) {
        let (cache_size, blocked_ips) = self.get_cache_stats();
        crate::metrics::update_cache_size(cache_size);
        crate::metrics::update_blocked_ips(blocked_ips);
    }
}

impl<B: OnBlocked> Clone for RateLimiter<B> {
    fn clone(&self) -> Self {
        Self {
            rate_limit_cache: self.rate_limit_cache.clone(),
            config: self.config.clone(),
            on_blocked: self.on_blocked.clone(),
            screener: self.screener.clone(),
        }
    }
}
