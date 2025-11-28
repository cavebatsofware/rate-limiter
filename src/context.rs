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

use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
};
use std::net::{IpAddr, SocketAddr};

use crate::types::SecurityContext;

pub async fn security_context_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip_address = extract_client_ip(&headers, addr.ip());

    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| sanitize_user_agent(s))
        .unwrap_or_default();

    tracing::debug!(
        "Incoming request: method={} uri={} ip={} user_agent={}",
        request.method(),
        request.uri(),
        ip_address,
        user_agent
    );

    let security_context = SecurityContext::new(ip_address.to_string(), user_agent);

    request.extensions_mut().insert(security_context);

    next.run(request).await
}

fn extract_client_ip(headers: &HeaderMap, fallback_ip: IpAddr) -> IpAddr {
    if let Some(forwarded_for) = headers.get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    tracing::debug!("Using X-Forwarded-For IP: {}", ip);
                    return ip;
                }
            }
        }
    }

    tracing::debug!("Using socket IP (no proxy headers): {}", fallback_ip);
    fallback_ip
}

fn sanitize_user_agent(user_agent: &str) -> String {
    const MAX_LENGTH: usize = 500;

    let sanitized: String = user_agent
        .chars()
        .filter(|c| !c.is_control() || *c == ' ' || *c == '\t')
        .take(MAX_LENGTH)
        .collect();

    sanitized
}
