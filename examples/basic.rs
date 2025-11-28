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

use axum::{extract::Extension, response::Json, routing::get, Router};
use basic_axum_rate_limit::{
    rate_limit_middleware, security_context_middleware, ActionChecker, OnBlocked, RateLimitConfig,
    RateLimiter, RequestScreener, ScreeningConfig, SecurityContext,
};
use std::time::Duration;

#[derive(Clone)]
struct SimpleCallbacks;

#[async_trait::async_trait]
impl OnBlocked for SimpleCallbacks {
    async fn on_blocked(&self, ip: &str, path: &str, _context: &SecurityContext) {
        println!("Rate limit exceeded: {} attempted {}", ip, path);
    }
}

#[async_trait::async_trait]
impl ActionChecker for SimpleCallbacks {
    async fn check_recent_action(
        &self,
        _ip: &str,
        _action: &str,
        _within: Duration,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false)
    }
}

async fn handler(Extension(ctx): Extension<SecurityContext>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ip": ctx.ip_address,
        "user_agent": ctx.user_agent,
        "message": "Request successful"
    }))
}

#[tokio::main]
async fn main() {
    // Configure rate limiting: 10 requests per minute, 15 minute block duration
    let config = RateLimitConfig::new(10, Duration::from_secs(15 * 60));

    // Configure request screening to block common attack patterns
    let screening_config = ScreeningConfig::new()
        .with_path_patterns(vec![
            r"\.php\d?$".to_string(),
            r"/\.git/".to_string(),
            r"/\.env".to_string(),
        ])
        .with_user_agent_patterns(vec!["zgrab".to_string(), "nuclei".to_string()]);

    let screener =
        RequestScreener::new(&screening_config).expect("Failed to compile screening patterns");

    let rate_limiter = RateLimiter::new(config, SimpleCallbacks).with_screener(screener);

    let app = Router::new()
        .route("/", get(handler))
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(security_context_middleware));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    println!("Server running on http://127.0.0.1:3000");
    println!("Rate limit: 10 requests per minute");

    axum::serve(listener, app).await.unwrap();
}
