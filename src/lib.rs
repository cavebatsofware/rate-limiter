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
pub use context::{
    security_context_middleware, security_context_middleware_with_config, IpExtractionError,
    IpExtractionStrategy, SecurityContextConfig,
};
pub use limiter::RateLimiter;
pub use middleware::rate_limit_middleware;
pub use screener::{RequestScreener, ScreeningConfig, ScreeningReason, ScreeningResult};
pub use types::{ActionChecker, NoOpActionChecker, NoOpOnBlocked, OnBlocked, SecurityContext};

#[cfg(feature = "metrics")]
pub use routes::metrics_handler;

#[cfg(test)]
mod tests;
