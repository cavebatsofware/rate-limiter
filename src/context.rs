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
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};

use crate::types::SecurityContext;

/// Error returned when client IP extraction fails.
#[derive(Debug, Clone)]
pub enum IpExtractionError {
    /// The required header is missing.
    MissingHeader { header_name: String },
    /// The header value is not valid UTF-8.
    InvalidHeaderEncoding { header_name: String },
    /// The header contains an unexpected number of IPs.
    ProxyDepthMismatch {
        header_name: String,
        expected: usize,
        actual: usize,
    },
    /// The IP address in the header could not be parsed.
    InvalidIpAddress { header_name: String, value: String },
}

impl std::fmt::Display for IpExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader { header_name } => {
                write!(f, "Missing required header: {}", header_name)
            }
            Self::InvalidHeaderEncoding { header_name } => {
                write!(f, "Invalid encoding in header: {}", header_name)
            }
            Self::ProxyDepthMismatch {
                header_name,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Proxy depth mismatch in {}: expected {} IPs, found {}",
                    header_name, expected, actual
                )
            }
            Self::InvalidIpAddress { header_name, value } => {
                write!(f, "Invalid IP address in {}: '{}'", header_name, value)
            }
        }
    }
}

impl IntoResponse for IpExtractionError {
    fn into_response(self) -> Response {
        tracing::warn!("IP extraction failed: {}", self);
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

/// Strategy for extracting the client IP address from incoming requests.
///
/// Different proxy configurations require different IP extraction strategies:
/// - Behind trusted proxies: use `ForwardedHeader` with appropriate `proxy_depth`
/// - Direct connections: use `SocketAddr`
#[derive(Debug, Clone)]
pub enum IpExtractionStrategy {
    /// Extract client IP from a forwarded header with proxy depth validation.
    ///
    /// The client IP is always the **leftmost** value in the header. The `proxy_depth`
    /// parameter validates that the header contains exactly that many IPs, rejecting
    /// headers that don't match your known proxy topology (to prevent spoofing).
    ///
    /// Examples with header value "client, proxy1, proxy2":
    /// - proxy_depth=3: valid, returns "client"
    /// - proxy_depth=1: rejected (header has 3 IPs, expected 1)
    /// - proxy_depth=2: rejected (header has 3 IPs, expected 2)
    ForwardedHeader {
        /// The header name to extract the IP from.
        /// Common values: "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"
        header_name: String,
        /// Expected number of IPs in the header (your proxy chain depth).
        /// Header is rejected if it doesn't contain exactly this many IPs.
        proxy_depth: usize,
    },

    /// Use the direct socket address (no proxy headers).
    /// **Use when**: Clients connect directly without any proxy.
    SocketAddr,
}

impl Default for IpExtractionStrategy {
    fn default() -> Self {
        Self::ForwardedHeader {
            header_name: "X-Forwarded-For".to_string(),
            proxy_depth: 1,
        }
    }
}

impl IpExtractionStrategy {
    /// Create an X-Forwarded-For strategy with the specified proxy depth.
    pub fn x_forwarded_for(proxy_depth: usize) -> Self {
        Self::ForwardedHeader {
            header_name: "X-Forwarded-For".to_string(),
            proxy_depth,
        }
    }

    /// Create an X-Real-IP strategy (proxy depth of 1).
    pub fn x_real_ip() -> Self {
        Self::ForwardedHeader {
            header_name: "X-Real-IP".to_string(),
            proxy_depth: 1,
        }
    }

    /// Create a Cloudflare CF-Connecting-IP strategy (proxy depth of 1).
    pub fn cloudflare() -> Self {
        Self::ForwardedHeader {
            header_name: "CF-Connecting-IP".to_string(),
            proxy_depth: 1,
        }
    }

    /// Create a custom header strategy with the specified proxy depth.
    pub fn custom_header(header_name: impl Into<String>, proxy_depth: usize) -> Self {
        Self::ForwardedHeader {
            header_name: header_name.into(),
            proxy_depth,
        }
    }
}

/// Configuration for the security context middleware.
#[derive(Debug, Clone, Default)]
pub struct SecurityContextConfig {
    /// Strategy for extracting the client IP address.
    pub ip_extraction: IpExtractionStrategy,
}

impl SecurityContextConfig {
    /// Create a new configuration with the default IP extraction strategy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the IP extraction strategy.
    pub fn with_ip_extraction(mut self, strategy: IpExtractionStrategy) -> Self {
        self.ip_extraction = strategy;
        self
    }
}

/// Security context middleware with configurable IP extraction.
///
/// Returns a 400 Bad Request if the client IP cannot be extracted according
/// to the configured strategy. This prevents requests from being processed
/// with incorrect or spoofed IP addresses.
///
/// # Example
/// ```rust,ignore
/// use basic_axum_rate_limit::{SecurityContextConfig, IpExtractionStrategy, security_context_middleware_with_config};
///
/// let config = SecurityContextConfig::new()
///     .with_ip_extraction(IpExtractionStrategy::x_forwarded_for(1));
///
/// let app = Router::new()
///     .route("/", get(handler))
///     .layer(axum::middleware::from_fn_with_state(config, security_context_middleware_with_config));
/// ```
pub async fn security_context_middleware_with_config(
    State(config): State<SecurityContextConfig>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    match process_security_context(&config.ip_extraction, addr.ip(), &headers, &mut request) {
        Ok(()) => next.run(request).await,
        Err(e) => e.into_response(),
    }
}

/// Security context middleware with default IP extraction (X-Forwarded-For with depth 1).
///
/// Returns a 400 Bad Request if the X-Forwarded-For header is missing, invalid,
/// or contains an unexpected number of IPs.
///
/// For custom IP extraction, use `security_context_middleware_with_config`.
pub async fn security_context_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    match process_security_context(
        &IpExtractionStrategy::default(),
        addr.ip(),
        &headers,
        &mut request,
    ) {
        Ok(()) => next.run(request).await,
        Err(e) => e.into_response(),
    }
}

fn process_security_context(
    strategy: &IpExtractionStrategy,
    socket_ip: IpAddr,
    headers: &HeaderMap,
    request: &mut Request<axum::body::Body>,
) -> Result<(), IpExtractionError> {
    let ip_address = extract_client_ip(strategy, headers, socket_ip)?;

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
    Ok(())
}

fn extract_client_ip(
    strategy: &IpExtractionStrategy,
    headers: &HeaderMap,
    socket_ip: IpAddr,
) -> Result<IpAddr, IpExtractionError> {
    match strategy {
        IpExtractionStrategy::ForwardedHeader {
            header_name,
            proxy_depth,
        } => {
            let ip = parse_forwarded_header(headers, header_name, *proxy_depth)?;
            tracing::debug!("Extracted IP {} from {}", ip, header_name);
            Ok(ip)
        }
        IpExtractionStrategy::SocketAddr => {
            tracing::debug!("Using socket IP: {}", socket_ip);
            Ok(socket_ip)
        }
    }
}

/// Parse a forwarded header with proxy depth validation.
/// Returns the leftmost IP if the header contains exactly `proxy_depth` IPs.
fn parse_forwarded_header(
    headers: &HeaderMap,
    header_name: &str,
    proxy_depth: usize,
) -> Result<IpAddr, IpExtractionError> {
    let header_value =
        headers
            .get(header_name)
            .ok_or_else(|| IpExtractionError::MissingHeader {
                header_name: header_name.to_string(),
            })?;

    let header_str =
        header_value
            .to_str()
            .map_err(|_| IpExtractionError::InvalidHeaderEncoding {
                header_name: header_name.to_string(),
            })?;

    let ips: Vec<&str> = header_str.split(',').map(|s| s.trim()).collect();

    if ips.len() != proxy_depth {
        return Err(IpExtractionError::ProxyDepthMismatch {
            header_name: header_name.to_string(),
            expected: proxy_depth,
            actual: ips.len(),
        });
    }

    // Client IP is always the leftmost
    let client_ip_str = ips
        .first()
        .ok_or_else(|| IpExtractionError::MissingHeader {
            header_name: header_name.to_string(),
        })?;

    client_ip_str
        .parse()
        .map_err(|_| IpExtractionError::InvalidIpAddress {
            header_name: header_name.to_string(),
            value: client_ip_str.to_string(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::HeaderName::from_static(name),
                axum::http::HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    const SOCKET_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

    #[test]
    fn test_x_forwarded_for_single_ip() {
        let headers = make_headers(&[("x-forwarded-for", "1.2.3.4")]);
        let ip = extract_client_ip(
            &IpExtractionStrategy::x_forwarded_for(1),
            &headers,
            SOCKET_IP,
        );
        assert_eq!(ip.unwrap(), "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_x_forwarded_for_depth_mismatch_rejected() {
        // Header has 2 IPs but proxy_depth is 1, should return error
        let headers = make_headers(&[("x-forwarded-for", "1.2.3.4, 5.6.7.8")]);
        let result = extract_client_ip(
            &IpExtractionStrategy::x_forwarded_for(1),
            &headers,
            SOCKET_IP,
        );
        assert!(matches!(
            result,
            Err(IpExtractionError::ProxyDepthMismatch {
                expected: 1,
                actual: 2,
                ..
            })
        ));
    }

    #[test]
    fn test_x_forwarded_for_multiple_ips_with_correct_depth() {
        // Header has 3 IPs and proxy_depth is 3, should return leftmost
        let headers = make_headers(&[("x-forwarded-for", "1.2.3.4, 5.6.7.8, 9.10.11.12")]);
        let ip = extract_client_ip(
            &IpExtractionStrategy::x_forwarded_for(3),
            &headers,
            SOCKET_IP,
        );
        assert_eq!(ip.unwrap(), "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_x_real_ip() {
        let headers = make_headers(&[("x-real-ip", "10.20.30.40")]);
        let ip = extract_client_ip(&IpExtractionStrategy::x_real_ip(), &headers, SOCKET_IP);
        assert_eq!(ip.unwrap(), "10.20.30.40".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_cloudflare_connecting_ip() {
        let headers = make_headers(&[("cf-connecting-ip", "203.0.113.50")]);
        let ip = extract_client_ip(&IpExtractionStrategy::cloudflare(), &headers, SOCKET_IP);
        assert_eq!(ip.unwrap(), "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_custom_header() {
        let headers = make_headers(&[("x-client-ip", "192.168.1.100")]);
        let ip = extract_client_ip(
            &IpExtractionStrategy::custom_header("X-Client-IP", 1),
            &headers,
            SOCKET_IP,
        );
        assert_eq!(ip.unwrap(), "192.168.1.100".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_socket_addr_strategy() {
        let headers = make_headers(&[("x-forwarded-for", "1.2.3.4")]);
        let ip = extract_client_ip(&IpExtractionStrategy::SocketAddr, &headers, SOCKET_IP);
        assert_eq!(ip.unwrap(), SOCKET_IP);
    }

    #[test]
    fn test_error_when_header_missing() {
        let headers = HeaderMap::new();
        let result = extract_client_ip(
            &IpExtractionStrategy::x_forwarded_for(1),
            &headers,
            SOCKET_IP,
        );
        assert!(matches!(
            result,
            Err(IpExtractionError::MissingHeader { .. })
        ));
    }

    #[test]
    fn test_error_when_ip_invalid() {
        let headers = make_headers(&[("x-forwarded-for", "not-an-ip")]);
        let result = extract_client_ip(
            &IpExtractionStrategy::x_forwarded_for(1),
            &headers,
            SOCKET_IP,
        );
        assert!(matches!(
            result,
            Err(IpExtractionError::InvalidIpAddress { .. })
        ));
    }

    #[test]
    fn test_error_display() {
        let err = IpExtractionError::ProxyDepthMismatch {
            header_name: "X-Forwarded-For".to_string(),
            expected: 1,
            actual: 3,
        };
        assert_eq!(
            err.to_string(),
            "Proxy depth mismatch in X-Forwarded-For: expected 1 IPs, found 3"
        );
    }
}
