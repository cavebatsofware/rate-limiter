use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub tokens: f64,
    pub last_refill: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub blocked_until: Option<DateTime<Utc>>,
}

impl RateLimitEntry {
    pub fn new(initial_tokens: f64) -> Self {
        let now = Utc::now();
        Self {
            tokens: initial_tokens,
            last_refill: now,
            created_at: now,
            blocked_until: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub ip_address: String,
    pub user_agent: String,
}

impl SecurityContext {
    pub fn new(ip_address: String, user_agent: String) -> Self {
        Self {
            ip_address,
            user_agent,
        }
    }
}

#[async_trait::async_trait]
pub trait OnBlocked: Send + Sync {
    async fn on_blocked(&self, ip: &str, path: &str, context: &SecurityContext);
}

#[async_trait::async_trait]
pub trait ActionChecker: Send + Sync {
    async fn check_recent_action(
        &self,
        ip: &str,
        action: &str,
        within: std::time::Duration,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

pub struct NoOpOnBlocked;

#[async_trait::async_trait]
impl OnBlocked for NoOpOnBlocked {
    async fn on_blocked(&self, _ip: &str, _path: &str, _context: &SecurityContext) {}
}

pub struct NoOpActionChecker;

#[async_trait::async_trait]
impl ActionChecker for NoOpActionChecker {
    async fn check_recent_action(
        &self,
        _ip: &str,
        _action: &str,
        _within: std::time::Duration,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false)
    }
}
