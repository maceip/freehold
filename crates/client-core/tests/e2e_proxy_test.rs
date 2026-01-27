//! End-to-end test for the TCP proxy flow.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http::{Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use client_core::tcp_proxy::{ProxyRequest, ProxyResponse, TcpProxyClient, TcpProxyConfig};

/// Mock HTTP/1.1 server for testing the TCP proxy.
struct MockHttpServer {
    addr: SocketAddr,
    request_count: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockHttpServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_count = Arc::new(AtomicUsize::new(0));
        let count_clone = request_count.clone();

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        if let Ok((mut socket, _)) = result {
                            let count = count_clone.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                if let Ok(n) = socket.read(&mut buf).await {
                                    if n > 0 {
                                        count.fetch_add(1, Ordering::SeqCst);

                                        // Parse request (very basic)
                                        let request = String::from_utf8_lossy(&buf[..n]);
                                        let path = request
                                            .lines()
                                            .next()
                                            .and_then(|line| line.split_whitespace().nth(1))
                                            .unwrap_or("/");

                                        // Send response
                                        let body = format!("Hello from mock server! Path: {}", path);
                                        let response = format!(
                                            "HTTP/1.1 200 OK\r\n\
                                             Content-Type: text/plain\r\n\
                                             Content-Length: {}\r\n\
                                             X-Mock-Server: true\r\n\
                                             \r\n\
                                             {}",
                                            body.len(),
                                            body
                                        );

                                        let _ = socket.write_all(response.as_bytes()).await;
                                    }
                                }
                            });
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });

        Self {
            addr,
            request_count,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[tokio::test]
async fn test_tcp_proxy_to_mock_server() {
    let server = MockHttpServer::start().await;
    let target = server.addr();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = TcpProxyClient::for_target(target);

    assert!(client.health_check().await, "Mock server should be reachable");

    let request = ProxyRequest::new(Method::GET, "/test/path".parse().unwrap())
        .with_header("user-agent", "test-client");

    let response = client.forward(request).await.unwrap();

    assert_eq!(response.status, StatusCode::OK);
    assert!(response
        .headers
        .iter()
        .any(|(k, v)| k == "x-mock-server" && v == "true"));

    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("Hello from mock server!"));
    assert!(body.contains("/test/path"));

    assert_eq!(server.request_count(), 1);
}

#[tokio::test]
async fn test_tcp_proxy_post_with_body() {
    let server = MockHttpServer::start().await;
    let target = server.addr();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = TcpProxyClient::for_target(target);

    let request = ProxyRequest::new(Method::POST, "/api/data".parse().unwrap())
        .with_header("content-type", "application/json")
        .with_body(r#"{"key": "value"}"#);

    let response = client.forward(request).await.unwrap();

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(server.request_count(), 1);
}

#[tokio::test]
async fn test_tcp_proxy_multiple_requests() {
    let server = MockHttpServer::start().await;
    let target = server.addr();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = TcpProxyClient::for_target(target);

    for i in 0..5 {
        let request = ProxyRequest::new(Method::GET, format!("/request/{}", i).parse().unwrap());
        let response = client.forward(request).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
    }

    assert_eq!(server.request_count(), 5);
}

#[tokio::test]
async fn test_tcp_proxy_unreachable_target() {
    let client = TcpProxyClient::for_target("127.0.0.1:59998".parse().unwrap());

    assert!(!client.health_check().await);

    let request = ProxyRequest::new(Method::GET, "/".parse().unwrap());
    let result = client.forward(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_tcp_proxy_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let _ = socket.read(&mut buf).await;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let config = TcpProxyConfig {
        target: addr,
        request_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let client = TcpProxyClient::new(config);

    let request = ProxyRequest::new(Method::GET, "/".parse().unwrap());
    let result = client.forward(request).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("timeout") || err.to_string().contains("Timeout"));
}

#[tokio::test]
async fn test_concurrent_proxy_requests() {
    let server = MockHttpServer::start().await;
    let target = server.addr();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Arc::new(TcpProxyClient::for_target(target));

    let mut handles = vec![];
    for i in 0..10 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let request =
                ProxyRequest::new(Method::GET, format!("/concurrent/{}", i).parse().unwrap());
            client.forward(request).await
        }));
    }

    let mut success_count = 0;
    for handle in handles {
        if let Ok(Ok(response)) = handle.await {
            if response.status == StatusCode::OK {
                success_count += 1;
            }
        }
    }

    assert_eq!(success_count, 10);
    assert_eq!(server.request_count(), 10);
}

#[tokio::test]
async fn test_proxy_response_builders() {
    let err_resp = ProxyResponse::error(StatusCode::NOT_FOUND, "Resource not found");
    assert_eq!(err_resp.status, StatusCode::NOT_FOUND);
    assert!(String::from_utf8_lossy(&err_resp.body).contains("Resource not found"));

    let timeout_resp = ProxyResponse::gateway_timeout();
    assert_eq!(timeout_resp.status, StatusCode::GATEWAY_TIMEOUT);

    let bad_gw_resp = ProxyResponse::bad_gateway("upstream error");
    assert_eq!(bad_gw_resp.status, StatusCode::BAD_GATEWAY);
    assert!(String::from_utf8_lossy(&bad_gw_resp.body).contains("upstream error"));

    let unavail_resp = ProxyResponse::service_unavailable();
    assert_eq!(unavail_resp.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_proxy_request_builder_chain() {
    let request = ProxyRequest::new(Method::PUT, "/api/update".parse().unwrap())
        .with_header("content-type", "application/json")
        .with_header("authorization", "Bearer token123")
        .with_header("x-custom", "custom-value")
        .with_body(r#"{"update": true}"#);

    assert_eq!(request.method, Method::PUT);
    assert_eq!(request.uri.path(), "/api/update");
    assert_eq!(request.headers.len(), 3);
    assert!(!request.body.is_empty());
}
