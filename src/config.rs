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

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub rate_limit_per_minute: u32,
    pub block_duration: Duration,
    pub grace_period_seconds: u64,
    pub cache_refund_ratio: f64,
    pub error_penalty_tokens: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: 50,
            block_duration: Duration::from_secs(15 * 60),
            grace_period_seconds: 1,
            cache_refund_ratio: 0.5,
            error_penalty_tokens: 2.0,
        }
    }
}

impl RateLimitConfig {
    pub fn new(rate_limit_per_minute: u32, block_duration: Duration) -> Self {
        Self {
            rate_limit_per_minute,
            block_duration,
            ..Default::default()
        }
    }

    pub fn with_grace_period(mut self, seconds: u64) -> Self {
        self.grace_period_seconds = seconds;
        self
    }

    pub fn with_cache_refund_ratio(mut self, ratio: f64) -> Self {
        self.cache_refund_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    pub fn with_error_penalty(mut self, penalty: f64) -> Self {
        self.error_penalty_tokens = penalty.max(0.0);
        self
    }

    pub fn max_tokens(&self) -> f64 {
        self.rate_limit_per_minute as f64
    }

    pub fn refill_rate_per_second(&self) -> f64 {
        self.rate_limit_per_minute as f64 / 60.0
    }
}
