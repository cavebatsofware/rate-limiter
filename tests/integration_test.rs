use basic_axum_rate_limit::{
    rate_limit_middleware, security_context_middleware, NoOpOnBlocked, RateLimitConfig, RateLimiter,
    RequestScreener, ScreeningConfig,
};

use axum::{routing::get, Router};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::oneshot;

async fn handler() -> &'static str {
    "OK"
}

struct TestServer {
    base_url: String,
    shutdown_tx: oneshot::Sender<()>,
}

impl TestServer {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

async fn spawn_test_server(rate_limiter: RateLimiter<NoOpOnBlocked>) -> TestServer {
    let app = Router::new()
        .route("/", get(handler))
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(security_context_middleware));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });

    TestServer {
        base_url: format!("http://{}", addr),
        shutdown_tx,
    }
}

fn default_limiter() -> RateLimiter<NoOpOnBlocked> {
    let config = RateLimitConfig::new(5, Duration::from_secs(10)).with_grace_period(0);
    RateLimiter::new(config, NoOpOnBlocked)
}

async fn get_with_ip(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
    ip: &str,
) -> reqwest::Response {
    client
        .get(format!("{}{}", base_url, path))
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_basic_request_succeeds() {
    let server = spawn_test_server(default_limiter()).await;
    let client = reqwest::Client::new();

    let resp = get_with_ip(&client, &server.base_url, "/", "10.0.0.1").await;
    assert_eq!(resp.status(), 200);

    server.shutdown().await;
}

#[tokio::test]
async fn test_rate_limiting_returns_429() {
    let server = spawn_test_server(default_limiter()).await;
    let client = reqwest::Client::new();

    for i in 1..=5 {
        let resp = get_with_ip(&client, &server.base_url, "/", "10.0.0.1").await;
        assert_eq!(resp.status(), 200, "Request {} should succeed", i);
    }

    let resp = get_with_ip(&client, &server.base_url, "/", "10.0.0.1").await;
    assert_eq!(resp.status(), 429);

    server.shutdown().await;
}

#[tokio::test]
async fn test_blocked_ip_stays_blocked() {
    let server = spawn_test_server(default_limiter()).await;
    let client = reqwest::Client::new();

    // Exhaust tokens and trigger block
    for _ in 1..=5 {
        get_with_ip(&client, &server.base_url, "/", "10.0.0.2").await;
    }
    let resp = get_with_ip(&client, &server.base_url, "/", "10.0.0.2").await;
    assert_eq!(resp.status(), 429);

    // Subsequent requests should also be blocked
    for _ in 0..3 {
        let resp = get_with_ip(&client, &server.base_url, "/", "10.0.0.2").await;
        assert_eq!(resp.status(), 429, "Blocked IP should stay blocked");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn test_different_ips_independent() {
    let server = spawn_test_server(default_limiter()).await;
    let client = reqwest::Client::new();

    // Exhaust tokens for one IP
    for _ in 1..=5 {
        get_with_ip(&client, &server.base_url, "/", "10.0.0.10").await;
    }
    let resp = get_with_ip(&client, &server.base_url, "/", "10.0.0.10").await;
    assert_eq!(resp.status(), 429, "First IP should be blocked");

    // Different IP should still work
    let resp = get_with_ip(&client, &server.base_url, "/", "10.0.0.11").await;
    assert_eq!(resp.status(), 200, "Second IP should not be affected");

    server.shutdown().await;
}

#[tokio::test]
async fn test_screener_blocks_malicious_path() {
    let config = RateLimitConfig::new(50, Duration::from_secs(5)).with_grace_period(0);
    let screening_config = ScreeningConfig::new()
        .with_path_patterns(vec![r"\.php\d?$".to_string(), r"/\.git/".to_string()]);
    let screener = RequestScreener::new(&screening_config).unwrap();
    let limiter = RateLimiter::new(config, NoOpOnBlocked).with_screener(screener);
    let server = spawn_test_server(limiter).await;
    let client = reqwest::Client::new();

    let resp = get_with_ip(&client, &server.base_url, "/test.php", "10.0.0.3").await;
    assert_eq!(resp.status(), 418);

    let resp = get_with_ip(&client, &server.base_url, "/.git/config", "10.0.0.4").await;
    assert_eq!(resp.status(), 418);

    server.shutdown().await;
}

#[tokio::test]
async fn test_screener_blocks_malicious_user_agent() {
    let config = RateLimitConfig::new(50, Duration::from_secs(5)).with_grace_period(0);
    let screening_config =
        ScreeningConfig::new().with_user_agent_patterns(vec!["zgrab".to_string()]);
    let screener = RequestScreener::new(&screening_config).unwrap();
    let limiter = RateLimiter::new(config, NoOpOnBlocked).with_screener(screener);
    let server = spawn_test_server(limiter).await;

    let client = reqwest::Client::builder()
        .user_agent("zgrab/1.0")
        .build()
        .unwrap();

    let resp = client
        .get(format!("{}/", server.base_url))
        .header("X-Forwarded-For", "10.0.0.5")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 418);

    server.shutdown().await;
}

#[tokio::test]
async fn test_screener_block_also_blocks_ip() {
    let config = RateLimitConfig::new(50, Duration::from_secs(10)).with_grace_period(0);
    let screening_config =
        ScreeningConfig::new().with_path_patterns(vec![r"\.php$".to_string()]);
    let screener = RequestScreener::new(&screening_config).unwrap();
    let limiter = RateLimiter::new(config, NoOpOnBlocked).with_screener(screener);
    let server = spawn_test_server(limiter).await;
    let client = reqwest::Client::new();

    // Trigger screener block
    let resp = get_with_ip(&client, &server.base_url, "/evil.php", "10.0.0.20").await;
    assert_eq!(resp.status(), 418);

    // Same IP, normal path -- should now be blocked because block_immediately was called
    let resp = get_with_ip(&client, &server.base_url, "/", "10.0.0.20").await;
    assert_eq!(resp.status(), 429);

    server.shutdown().await;
}
