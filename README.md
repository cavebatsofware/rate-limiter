# basic-axum-rate-limit

Rate limiting middleware for Axum using a callback pattern for (optional) database operations.

## Usage

### 1. Implement the callback traits

```rust
use basic_axum_rate_limit::{OnBlocked, ActionChecker, SecurityContext};
use async_trait::async_trait;
use std::time::Duration;

#[derive(Clone)]
pub struct MyCallbacks {
    db: DatabaseConnection,
}

#[async_trait]
impl OnBlocked for MyCallbacks {
    async fn on_blocked(&self, ip: &str, path: &str, context: &SecurityContext) {
        // Log the blocked attempt
    }
}

#[async_trait]
impl ActionChecker for MyCallbacks {
    async fn check_recent_action(
        &self,
        ip: &str,
        action: &str,
        within: Duration,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Query database for recent actions
        Ok(false)
    }
}
```

### 2. Create the rate limiter

```rust
use basic_axum_rate_limit::{RateLimiter, RateLimitConfig};
use std::time::Duration;

let config = RateLimitConfig::new(
    30,                              // 30 requests per minute
    Duration::from_secs(15 * 60),    // 15 minute block duration
);

let callbacks = MyCallbacks { db };
let rate_limiter = RateLimiter::new(config, callbacks);
```

### 3. Configure request screening (optional)

The screener immediately blocks requests matching malicious patterns before they consume rate limit tokens:

```rust
use basic_axum_rate_limit::{RequestScreener, ScreeningConfig};

let screening_config = ScreeningConfig::new()
    .with_path_patterns(vec![
        // PHP attacks
        r"\.php\d?$".to_string(),
        r"/vendor/".to_string(),
        // Git/config exposure
        r"/\.git/".to_string(),
        r"/\.env".to_string(),
        // WordPress
        r"/wp-admin".to_string(),
        r"/wp-content".to_string(),
    ])
    .with_user_agent_patterns(vec![
        "zgrab".to_string(),
        "masscan".to_string(),
        "nuclei".to_string(),
        "sqlmap".to_string(),
    ]);

let screener = RequestScreener::new(&screening_config)
    .expect("Failed to compile screening patterns");

let rate_limiter = RateLimiter::new(config, callbacks)
    .with_screener(screener);
```

### 4. Configure IP extraction (optional)

By default, the middleware uses `X-Forwarded-For` and expects exactly one IP (from your trusted proxy). For other setups, configure the extraction strategy:

```rust
use basic_axum_rate_limit::{SecurityContextConfig, IpExtractionStrategy};

// Cloudflare CF-Connecting-IP header
let config = SecurityContextConfig::new()
    .with_ip_extraction(IpExtractionStrategy::CloudflareConnectingIp);

// nginx with X-Real-IP
let config = SecurityContextConfig::new()
    .with_ip_extraction(IpExtractionStrategy::XRealIp);

// Direct connections (no proxy)
let config = SecurityContextConfig::new()
    .with_ip_extraction(IpExtractionStrategy::SocketAddr);

// Custom header
let config = SecurityContextConfig::new()
    .with_ip_extraction(IpExtractionStrategy::custom_header("X-Client-IP"));
```

### 5. Add middleware to router

```rust
use axum::Router;
use basic_axum_rate_limit::{security_context_middleware, rate_limit_middleware};

let app = Router::new()
    .route("/api/endpoint", post(handler))
    .layer(axum::middleware::from_fn_with_state(
        rate_limiter,
        rate_limit_middleware,
    ))
    /* Your application middleware should be placed in between these layers.
     * This allows the security_context_middleware to handle the post processing,
     * refunding tokens, or docking extra tokens after requests have been handled.
     */
    .layer(axum::middleware::from_fn(security_context_middleware));
```

For custom IP extraction strategies, use `security_context_middleware_with_config`:

```rust
use basic_axum_rate_limit::{
    security_context_middleware_with_config, SecurityContextConfig, IpExtractionStrategy,
};

let security_config = SecurityContextConfig::new()
    .with_ip_extraction(IpExtractionStrategy::CloudflareConnectingIp);

// ...
.layer(axum::middleware::from_fn_with_state(
    security_config,
    security_context_middleware_with_config,
));
```

### 6. Access security context in handlers

```rust
use axum::Extension;
use basic_axum_rate_limit::SecurityContext;

async fn handler(Extension(ctx): Extension<SecurityContext>) {
    let ip = ctx.ip_address;
    let user_agent = ctx.user_agent;
}
```

## Algorithm: Token Bucket with Grace Period

This crate uses a token bucket algorithm for efficient rate limiting:

- Each IP address gets a bucket with a maximum capacity of tokens (equal to `rate_limit_per_minute`)
- Tokens refill continuously at a rate of `rate_limit_per_minute / 60` per second
- Each request consumes 1 token
- When tokens are depleted, requests are blocked

### Grace Period for New Connections

To handle legitimate bursts (e.g., loading a page with many assets), new IP addresses get a **grace period**:

- Default: **1 second** after first request
- During grace period: requests don't consume tokens
- After grace period: normal rate limiting applies

This allows a browser to load 25+ assets quickly on initial page load without triggering rate limits, since assets are then cached.

## Configuration

```rust
let config = RateLimitConfig::new(
    50,                              // Max requests per minute
    Duration::from_secs(15 * 60),    // Block duration when limit exceeded
)
.with_grace_period(1)                // Grace period in seconds (default: 1)
.with_cache_refund_ratio(0.5)        // Refund 90% for cache hits (default: 0.5)
.with_error_penalty(2.0);            // Extra tokens for errors (default: 2.0)
```

Defaults:
- `rate_limit_per_minute`: 50
- `block_duration`: 15 minutes (900 seconds)
- `grace_period_seconds`: 1
- `cache_refund_ratio`: 0.5 (50% refund for 304 responses)
- `error_penalty_tokens`: 2.0 (additional token cost for 4xx/5xx)

### Configuration Methods

```rust
impl RateLimitConfig {
    // Create with custom rate limit and block duration
    pub fn new(rate_limit_per_minute: u32, block_duration: Duration) -> Self;
    
    // Set grace period in seconds
    pub fn with_grace_period(self, seconds: u64) -> Self;
    
    // Set cache refund ratio (0.0 to 1.0)
    pub fn with_cache_refund_ratio(self, ratio: f64) -> Self;
    
    // Set error penalty in tokens (>= 0.0)
    pub fn with_error_penalty(self, penalty: f64) -> Self;
    
    // Get maximum tokens (equals rate_limit_per_minute)
    pub fn max_tokens(&self) -> f64;
    
    // Get token refill rate per second
    pub fn refill_rate_per_second(&self) -> f64;
}
```

## Types

### SecurityContext

```rust
pub struct SecurityContext {
    pub ip_address: String,
    pub user_agent: String,
}
```

### OnBlocked

```rust
#[async_trait]
pub trait OnBlocked: Send + Sync {
    async fn on_blocked(&self, ip: &str, path: &str, context: &SecurityContext);
}
```

### ActionChecker

```rust
#[async_trait]
pub trait ActionChecker: Send + Sync {
    async fn check_recent_action(
        &self,
        ip: &str,
        action: &str,
        within: Duration,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}
```

## Rate Limiting Behavior

### Per-IP Rate Limiting

Rate limits are applied per IP address globally, not per endpoint. If an IP makes 30 (or whatever the limit is) requests to different endpoints, they will be rate limited. There is support for custom per-action limiting with callbacks but that is a different than the token bucket limiting.

### Burst Handling

The token bucket algorithm naturally allows bursts:
- Full bucket allows rapid requests
- After grace period, tokens refill at 0.5/second (30/minute)
- Example: Use all 30 tokens → wait 60 seconds → have 30 tokens again

### Cache Response Handling

HTTP cache validation requests (304 Not Modified) consume reduced tokens:

**How it works:**
1. Request arrives → consumes 1.0 token upfront
2. Handler executes and returns response
3. Middleware checks response status code
4. If `304 Not Modified` → refunds 0.5 tokens (default)
5. **Effective cost: 0.1 tokens** (10x more cache requests allowed)
6. Prevents abuse from spoofed `If-None-Match` headers

**Example:**
```
Full requests:  30 requests/minute (1.0 token each)
Cache requests: 60 requests/minute (0.5 token effective cost)
```

This naturally handles browser cache validation without creating security holes.

### Error Response Penalties

Failed requests (4xx and 5xx status codes) consume additional tokens to penalize malicious behavior:

**How it works:**
1. Request arrives → consumes 1.0 token upfront
2. Handler executes and returns response
3. Middleware checks response status code
4. If `4xx` or `5xx` → consumes 1.0 additional token (default)
5. **Effective cost: 2.0 tokens** (2x normal cost)

**Why this helps:**
- **Legitimate users**: Rarely hit errors
- **Scanners/bots**: Generate many 404s during path enumeration, get rate limited 2x faster
- **Server errors**: Also penalized, creating visibility into problems. If a user is generating lots of 500s that is something I'd like to shutdown. A better strategy for handling the block/backoff would be good for some cases but that isn't a concern for my application so I didn't worry about it.

**Example token costs:**
```
200 OK:           1.0 token
304 Not Modified: 0.5 token (with refund)
404 Not Found:    2.0 tokens (1.0 + 1.0 penalty)
403 Forbidden:    2.0 tokens (1.0 + 1.0 penalty)
500 Server Error: 2.0 tokens (1.0 + 1.0 penalty)
```

**Impact with 50 token bucket:**
```
Legitimate traffic (mostly 2xx):  ~50 requests/min
Scanner (all 404s):                25 requests/min (50 tokens / 2.0 cost)
Mixed (40 success, 10 failures):   ~45 requests/min
```

This creates a reputation-based system where well-behaved clients get more capacity while malicious traffic is throttled more aggressively.

## Request Screening

The `RequestScreener` identifies obviously malicious requests (vulnerability scanners, path enumeration). Screened requests consume exactly 1 token regardless of response status, bypassing error penalties.

### ScreeningConfig

```rust
pub struct ScreeningConfig {
    /// Regex patterns that match malicious paths
    pub path_patterns: Vec<String>,
    /// Regex patterns that match malicious user agents (case-insensitive)
    pub user_agent_patterns: Vec<String>,
}
```

Both pattern sets are compiled into a `RegexSet` for efficient single-pass matching. User agent patterns are automatically made case-insensitive.

### Configuration Methods

```rust
impl ScreeningConfig {
    pub fn new() -> Self;
    pub fn with_path_pattern(self, pattern: &str) -> Self;
    pub fn with_path_patterns(self, patterns: Vec<String>) -> Self;
    pub fn with_user_agent_pattern(self, pattern: &str) -> Self;
    pub fn with_user_agent_patterns(self, patterns: Vec<String>) -> Self;
}
```

### Metrics Feature

The metrics feature enables the metrics endpoint and the metrics logging methods. These are used for load testing with prometheus logging outside
of production environments. They probably could be used in production environments but you would want to secure the endpoint or change the implementation to use a flat file for metrics rather than an api endpoint. The Cargo.toml looks like this for my setup.
```toml
[features]
default = []
loadtest = ["basic-axum-rate-limit/metrics"]

[dependencies]
basic-axum-rate-limit = "0.2.1"
```

### Example Configuration

```rust
let config = ScreeningConfig::new()
    .with_path_patterns(vec![
        r"\.php\d?$".to_string(),   // PHP files
        r"/\.git/".to_string(),      // Git exposure
        r"/\.env".to_string(),       // Environment files
        r"/wp-admin".to_string(),    // WordPress admin
    ])
    .with_user_agent_patterns(vec![
        "zgrab".to_string(),
        "nuclei".to_string(),
        "sqlmap".to_string(),
    ]);
```

### Behavior

- **Path patterns**: Regex patterns matched against the request path via `RegexSet`
- **User agent patterns**: Regex patterns matched case-insensitively via `RegexSet`
- **Screened requests**: Consume exactly 1 token (error penalties do not apply)
- **No default patterns**: You must explicitly configure patterns for your application

## License

GNU Lesser General Public License v3.0 or later.
