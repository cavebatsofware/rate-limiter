pub mod config;
pub mod context;
pub mod limiter;
pub mod middleware;
pub mod screener;
pub mod types;

#[cfg(feature = "metrics")]
pub mod metrics;

#[cfg(feature = "metrics")]
pub mod routes;

pub use config::RateLimitConfig;
pub use context::security_context_middleware;
pub use limiter::RateLimiter;
pub use middleware::rate_limit_middleware;
pub use screener::{RequestScreener, ScreeningConfig, ScreeningReason, ScreeningResult};
pub use types::{ActionChecker, NoOpActionChecker, NoOpOnBlocked, OnBlocked, SecurityContext};

#[cfg(feature = "metrics")]
pub use routes::metrics_handler;

#[cfg(test)]
mod tests;
