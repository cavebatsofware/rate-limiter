/*  This file is part of basic-axum-rate-limit
 *  Copyright (C) 2025  Grant DeFayette
 *
 *  basic-axum-rate-limit is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  basic-axum-rate-limit is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with basic-axum-rate-limit.  If not, see <https://www.gnu.org/licenses/>.
 */

#[cfg(test)]
mod tests {
    use crate::{
        config::RateLimitConfig,
        limiter::RateLimiter,
        types::{NoOpOnBlocked, SecurityContext},
    };
    use std::time::Duration;

    #[tokio::test]
    async fn test_token_bucket_basic_consumption() {
        let config = RateLimitConfig::new(10, Duration::from_secs(60)).with_grace_period(0);
        let limiter = RateLimiter::new(config, NoOpOnBlocked);
        let ctx = SecurityContext::new("192.168.1.1".to_string(), "test-agent".to_string());

        // First 10 requests should succeed
        for i in 1..=10 {
            let (allowed, newly_blocked, _tokens) =
                limiter.check_rate_limit("192.168.1.1", &ctx, "/test").await;
            assert!(allowed, "Request {} should be allowed", i);
            assert!(!newly_blocked, "Request {} should not trigger block", i);
        }

        // 11th request should be blocked
        let (allowed, newly_blocked, _tokens) =
            limiter.check_rate_limit("192.168.1.1", &ctx, "/test").await;
        assert!(!allowed, "11th request should be blocked");
        assert!(newly_blocked, "11th request should trigger new block");
    }

    #[tokio::test]
    async fn test_grace_period_allows_burst() {
        let config = RateLimitConfig::new(10, Duration::from_secs(60)).with_grace_period(2);
        let limiter = RateLimiter::new(config, NoOpOnBlocked);
        let ctx = SecurityContext::new("192.168.1.2".to_string(), "test-agent".to_string());

        // Within grace period, should allow many requests without consuming tokens
        for i in 1..=20 {
            let (allowed, _, _) = limiter.check_rate_limit("192.168.1.2", &ctx, "/test").await;
            assert!(
                allowed,
                "Request {} should be allowed during grace period",
                i
            );
        }

        // Wait for grace period to expire
        tokio::time::sleep(Duration::from_secs(3)).await;

        // After grace period, normal rate limiting applies
        for i in 1..=10 {
            let (allowed, _, _) = limiter.check_rate_limit("192.168.1.2", &ctx, "/test").await;
            assert!(allowed, "Request {} after grace should be allowed", i);
        }

        // 11th should block
        let (allowed, _, _) = limiter.check_rate_limit("192.168.1.2", &ctx, "/test").await;
        assert!(!allowed, "Should be blocked after consuming 10 tokens");
    }

    #[tokio::test]
    async fn test_token_refund() {
        let config = RateLimitConfig::new(10, Duration::from_secs(2)).with_grace_period(0);
        let limiter = RateLimiter::new(config, NoOpOnBlocked);
        let ctx = SecurityContext::new("192.168.1.3".to_string(), "test-agent".to_string());

        // Consume 10 tokens
        for _ in 1..=10 {
            limiter.check_rate_limit("192.168.1.3", &ctx, "/test").await;
        }

        // Should be blocked now
        let (allowed, _, _) = limiter.check_rate_limit("192.168.1.3", &ctx, "/test").await;
        assert!(!allowed, "Should be blocked after 10 requests");

        // Wait for block to expire
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Refund 9 tokens
        limiter.refund_tokens("192.168.1.3", 9.0);

        // Should be able to make 9 more requests (had 0 tokens after block, refunded 9, plus some natural refill)
        for i in 1..=9 {
            let (allowed, _, _) = limiter.check_rate_limit("192.168.1.3", &ctx, "/test").await;
            assert!(
                allowed,
                "Request {} should succeed after refund and block expiry",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_additional_token_consumption() {
        let config = RateLimitConfig::new(10, Duration::from_secs(60)).with_grace_period(0);
        let limiter = RateLimiter::new(config, NoOpOnBlocked);
        let ctx = SecurityContext::new("192.168.1.4".to_string(), "test-agent".to_string());

        // Consume 5 tokens normally
        for _ in 1..=5 {
            limiter.check_rate_limit("192.168.1.4", &ctx, "/test").await;
        }

        // Consume 5 additional tokens as penalty
        limiter.consume_additional_tokens("192.168.1.4", 5.0);

        // Should be blocked now (5 + 5 = 10)
        let (allowed, _, _) = limiter.check_rate_limit("192.168.1.4", &ctx, "/test").await;
        assert!(
            !allowed,
            "Should be blocked after consuming all tokens via penalty"
        );
    }

    #[tokio::test]
    async fn test_token_refill_over_time() {
        let config = RateLimitConfig::new(10, Duration::from_secs(5)) // 2 tokens per second, 5 sec block
            .with_grace_period(0);
        let limiter = RateLimiter::new(config, NoOpOnBlocked);
        let ctx = SecurityContext::new("192.168.1.5".to_string(), "test-agent".to_string());

        // Consume all 10 tokens
        for _ in 1..=10 {
            limiter.check_rate_limit("192.168.1.5", &ctx, "/test").await;
        }

        // Should be blocked
        let (allowed, _, _) = limiter.check_rate_limit("192.168.1.5", &ctx, "/test").await;
        assert!(!allowed, "Should be blocked");

        // Wait 6 seconds (block expires at 5s, plus 1s for refill)
        tokio::time::sleep(Duration::from_secs(6)).await;

        // Should be able to make 1-2 requests (natural refill after block expires)
        let (allowed1, _, _) = limiter.check_rate_limit("192.168.1.5", &ctx, "/test").await;
        assert!(allowed1, "First request after refill should succeed");

        // Second might succeed depending on exact timing (2 tokens/sec = 2 tokens in 1 sec after block)
        // But we'll just verify the first one worked, showing refill is working
    }

    #[tokio::test]
    async fn test_different_ips_independent_limits() {
        let config = RateLimitConfig::new(5, Duration::from_secs(60)).with_grace_period(0);
        let limiter = RateLimiter::new(config, NoOpOnBlocked);
        let ctx1 = SecurityContext::new("192.168.1.6".to_string(), "test-agent".to_string());
        let ctx2 = SecurityContext::new("192.168.1.7".to_string(), "test-agent".to_string());

        // IP1: consume all tokens
        for _ in 1..=5 {
            limiter
                .check_rate_limit("192.168.1.6", &ctx1, "/test")
                .await;
        }

        // IP1 should be blocked
        let (allowed, _, _) = limiter
            .check_rate_limit("192.168.1.6", &ctx1, "/test")
            .await;
        assert!(!allowed, "IP1 should be blocked");

        // IP2 should still have full quota
        for i in 1..=5 {
            let (allowed, _, _) = limiter
                .check_rate_limit("192.168.1.7", &ctx2, "/test")
                .await;
            assert!(allowed, "IP2 request {} should succeed", i);
        }
    }

    #[tokio::test]
    async fn test_config_refill_rate_calculation() {
        let config = RateLimitConfig::new(60, Duration::from_secs(60));
        assert_eq!(
            config.refill_rate_per_second(),
            1.0,
            "60/min should be 1/sec"
        );

        let config2 = RateLimitConfig::new(30, Duration::from_secs(60));
        assert_eq!(
            config2.refill_rate_per_second(),
            0.5,
            "30/min should be 0.5/sec"
        );

        let config3 = RateLimitConfig::new(120, Duration::from_secs(60));
        assert_eq!(
            config3.refill_rate_per_second(),
            2.0,
            "120/min should be 2/sec"
        );
    }

    #[tokio::test]
    async fn test_config_max_tokens() {
        let config = RateLimitConfig::new(50, Duration::from_secs(60));
        assert_eq!(config.max_tokens(), 50.0);

        let config2 = RateLimitConfig::new(100, Duration::from_secs(60));
        assert_eq!(config2.max_tokens(), 100.0);
    }

    #[tokio::test]
    async fn test_refund_capped_at_max_tokens() {
        let config = RateLimitConfig::new(10, Duration::from_secs(60)).with_grace_period(0);
        let limiter = RateLimiter::new(config, NoOpOnBlocked);
        let ctx = SecurityContext::new("192.168.1.8".to_string(), "test-agent".to_string());

        // Consume 5 tokens
        for _ in 1..=5 {
            limiter.check_rate_limit("192.168.1.8", &ctx, "/test").await;
        }

        // Refund 20 tokens (should cap at max 10)
        limiter.refund_tokens("192.168.1.8", 20.0);

        // Should be able to make exactly 10 requests, not 15
        for i in 1..=10 {
            let (allowed, _, _) = limiter.check_rate_limit("192.168.1.8", &ctx, "/test").await;
            assert!(allowed, "Request {} should succeed", i);
        }

        let (allowed, _, _) = limiter.check_rate_limit("192.168.1.8", &ctx, "/test").await;
        assert!(
            !allowed,
            "Should be blocked after 10 requests (cap at max tokens)"
        );
    }

    #[tokio::test]
    async fn test_cache_refund_ratio_config() {
        let config = RateLimitConfig::new(10, Duration::from_secs(60)).with_cache_refund_ratio(0.9);
        assert_eq!(config.cache_refund_ratio, 0.9);

        let config2 = config.with_cache_refund_ratio(1.5); // Should clamp to 1.0
        assert_eq!(config2.cache_refund_ratio, 1.0);

        let config3 =
            RateLimitConfig::new(10, Duration::from_secs(60)).with_cache_refund_ratio(-0.5); // Should clamp to 0.0
        assert_eq!(config3.cache_refund_ratio, 0.0);
    }

    #[tokio::test]
    async fn test_error_penalty_config() {
        let config = RateLimitConfig::new(10, Duration::from_secs(60)).with_error_penalty(1.0);
        assert_eq!(config.error_penalty_tokens, 1.0);

        let config2 = config.with_error_penalty(2.5);
        assert_eq!(config2.error_penalty_tokens, 2.5);

        let config3 = RateLimitConfig::new(10, Duration::from_secs(60)).with_error_penalty(-1.0); // Should clamp to 0.0
        assert_eq!(config3.error_penalty_tokens, 0.0);
    }
}
