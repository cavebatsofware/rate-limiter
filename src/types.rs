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
