use axum::{extract::Extension, response::Json, routing::get, Router};
use basic_axum_rate_limit::{
    rate_limit_middleware, security_context_middleware, ActionChecker, OnBlocked, RateLimitConfig,
    RateLimiter, SecurityContext,
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
    let config = RateLimitConfig::builder()
        .max_requests(10)
        .time_window(Duration::from_secs(60))
        .cleanup_interval(Duration::from_secs(300))
        .build();

    let rate_limiter = RateLimiter::new(config, SimpleCallbacks);

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
