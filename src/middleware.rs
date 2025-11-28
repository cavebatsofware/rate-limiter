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

use crate::{
    limiter::RateLimiter,
    types::{OnBlocked, SecurityContext},
};
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
#[cfg(feature = "metrics")]
use std::time::Instant;

/// HTTP 418 I'm a teapot - used to indicate obviously malicious requests
const IM_A_TEAPOT: StatusCode = StatusCode::IM_A_TEAPOT;

pub async fn rate_limit_middleware<B: OnBlocked + 'static>(
    State(limiter): State<RateLimiter<B>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    #[cfg(feature = "metrics")]
    let start = Instant::now();

    let security_context = match request.extensions().get::<SecurityContext>() {
        Some(ctx) => ctx.clone(),
        None => {
            tracing::error!("SecurityContext not found in request extensions. security_context_middleware should run before rate_limit_middleware.");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let path = request.uri().path().to_string();
    let rate_limit_key = security_context.ip_address.clone();

    let (is_allowed, newly_blocked, tokens) = limiter
        .check_rate_limit(&rate_limit_key, &security_context, &path)
        .await;

    // Store tokens in request extensions for access logging
    let mut request = request;
    request.extensions_mut().insert(tokens);

    if !is_allowed {
        if newly_blocked {
            tracing::warn!(
                "IP blocked for rate limiting: {} (path: {})",
                security_context.ip_address,
                &path
            );
            #[cfg(feature = "metrics")]
            crate::metrics::record_block(&rate_limit_key);
        } else {
            tracing::debug!(
                "Blocked IP attempted access: {}",
                security_context.ip_address
            );
        }

        #[cfg(feature = "metrics")]
        {
            let duration = start.elapsed().as_secs_f64();
            crate::metrics::record_http_request(429, duration);
        }

        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // Screen request for malicious patterns (only if not already blocked)
    if let Some(screener) = limiter.screener() {
        if let Some(result) = screener.check(&path, &security_context.user_agent) {
            tracing::warn!(
                "Malicious request screened: {} from {} (user-agent: {}, reason: {})",
                path,
                security_context.ip_address,
                security_context.user_agent,
                result.reason
            );

            limiter.block_immediately(&rate_limit_key);

            #[cfg(feature = "metrics")]
            {
                crate::metrics::record_screening_block(&rate_limit_key, &result.reason.to_string());
                let duration = start.elapsed().as_secs_f64();
                crate::metrics::record_http_request(418, duration);
            }

            return IM_A_TEAPOT.into_response();
        }
    }

    let response = next.run(request).await;

    let status = response.status();

    if status == StatusCode::NOT_MODIFIED {
        let refund_amount = limiter.config().cache_refund_ratio;
        limiter.refund_tokens(&rate_limit_key, refund_amount);
        #[cfg(feature = "metrics")]
        crate::metrics::record_cache_refund(&rate_limit_key);
    } else if status.is_client_error() || status.is_server_error() {
        let penalty_amount = limiter.config().error_penalty_tokens;
        limiter.consume_additional_tokens(&rate_limit_key, penalty_amount);
        #[cfg(feature = "metrics")]
        crate::metrics::record_error_penalty(&rate_limit_key, status.as_u16());
    }

    #[cfg(feature = "metrics")]
    {
        let duration = start.elapsed().as_secs_f64();
        crate::metrics::record_http_request(status.as_u16(), duration);
    }

    response
}
