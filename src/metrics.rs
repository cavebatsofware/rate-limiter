#[cfg(feature = "metrics")]
use lazy_static::lazy_static;
#[cfg(feature = "metrics")]
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Gauge, HistogramVec,
};

#[cfg(feature = "metrics")]
lazy_static! {
    pub static ref RATE_LIMIT_BLOCKS: CounterVec = register_counter_vec!(
        "rate_limit_blocks_total",
        "Total number of rate limit blocks by IP",
        &["ip"]
    )
    .unwrap();
    pub static ref RATE_LIMIT_CACHE_REFUNDS: CounterVec = register_counter_vec!(
        "rate_limit_cache_refunds_total",
        "Total number of cache refunds (304 responses)",
        &["ip"]
    )
    .unwrap();
    pub static ref RATE_LIMIT_ERROR_PENALTIES: CounterVec = register_counter_vec!(
        "rate_limit_error_penalties_total",
        "Total number of error penalties applied",
        &["ip", "status"]
    )
    .unwrap();
    pub static ref RATE_LIMIT_CACHE_SIZE: Gauge = register_gauge!(
        "rate_limit_cache_size",
        "Current number of IPs in rate limit cache"
    )
    .unwrap();
    pub static ref RATE_LIMIT_BLOCKED_IPS: Gauge =
        register_gauge!("rate_limit_blocked_ips", "Current number of blocked IPs").unwrap();
    pub static ref HTTP_REQUESTS: CounterVec = register_counter_vec!(
        "http_requests_total",
        "Total HTTP requests by status code",
        &["status"]
    )
    .unwrap();
    pub static ref HTTP_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["status"]
    )
    .unwrap();
    pub static ref SCREENING_BLOCKS: CounterVec = register_counter_vec!(
        "screening_blocks_total",
        "Total number of requests blocked by malicious pattern screening",
        &["ip", "reason"]
    )
    .unwrap();
}

#[cfg(feature = "metrics")]
pub fn record_block(ip: &str) {
    RATE_LIMIT_BLOCKS.with_label_values(&[ip]).inc();
}

#[cfg(feature = "metrics")]
pub fn record_cache_refund(ip: &str) {
    RATE_LIMIT_CACHE_REFUNDS.with_label_values(&[ip]).inc();
}

#[cfg(feature = "metrics")]
pub fn record_error_penalty(ip: &str, status: u16) {
    RATE_LIMIT_ERROR_PENALTIES
        .with_label_values(&[ip, &status.to_string()])
        .inc();
}

#[cfg(feature = "metrics")]
pub fn update_cache_size(size: usize) {
    RATE_LIMIT_CACHE_SIZE.set(size as f64);
}

#[cfg(feature = "metrics")]
pub fn update_blocked_ips(count: usize) {
    RATE_LIMIT_BLOCKED_IPS.set(count as f64);
}

#[cfg(feature = "metrics")]
pub fn record_http_request(status: u16, duration_seconds: f64) {
    HTTP_REQUESTS
        .with_label_values(&[&status.to_string()])
        .inc();
    HTTP_REQUEST_DURATION
        .with_label_values(&[&status.to_string()])
        .observe(duration_seconds);
}

#[cfg(feature = "metrics")]
pub fn record_screening_block(ip: &str, reason: &str) {
    SCREENING_BLOCKS.with_label_values(&[ip, reason]).inc();
}

// No-op versions when metrics feature is disabled
#[cfg(not(feature = "metrics"))]
pub fn record_block(_ip: &str) {}

#[cfg(not(feature = "metrics"))]
pub fn record_cache_refund(_ip: &str) {}

#[cfg(not(feature = "metrics"))]
pub fn record_error_penalty(_ip: &str, _status: u16) {}

#[cfg(not(feature = "metrics"))]
pub fn update_cache_size(_size: usize) {}

#[cfg(not(feature = "metrics"))]
pub fn update_blocked_ips(_count: usize) {}

#[cfg(not(feature = "metrics"))]
pub fn record_http_request(_status: u16, _duration_seconds: f64) {}

#[cfg(not(feature = "metrics"))]
pub fn record_screening_block(_ip: &str, _reason: &str) {}
