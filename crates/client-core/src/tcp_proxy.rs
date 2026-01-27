//! TCP reverse proxy client for forwarding H3 requests to local services.
//!
//! Translates HTTP/3 requests to HTTP/1.1 or HTTP/2 over TCP.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::{debug, warn};

use crate::ClientError;

/// Configuration for the TCP proxy client.
#[derive(Debug, Clone)]
pub struct TcpProxyConfig {
    /// Target address to proxy to (e.g., 127.0.0.1:8080).
    pub target: SocketAddr,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Whether to use HTTP/2 when available.
    pub enable_http2: bool,
}

impl Default for TcpProxyConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1:8080".parse().unwrap(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            enable_http2: true,
        }
    }
}

/// HTTP request extracted from H3.
#[derive(Debug, Clone)]
pub struct ProxyRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl ProxyRequest {
    pub fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }
}

/// HTTP response to send back via H3.
#[derive(Debug, Clone)]
pub struct ProxyResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl ProxyResponse {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Create an error response.
    pub fn error(status: StatusCode, message: impl Into<String>) -> Self {
        let body = message.into();
        Self {
            status,
            headers: vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("content-length".to_string(), body.len().to_string()),
            ],
            body: Bytes::from(body),
        }
    }

    /// Create a gateway timeout response.
    pub fn gateway_timeout() -> Self {
        Self::error(StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout")
    }

    /// Create a bad gateway response.
    pub fn bad_gateway(reason: impl Into<String>) -> Self {
        Self::error(StatusCode::BAD_GATEWAY, format!("Bad Gateway: {}", reason.into()))
    }

    /// Create a service unavailable response.
    pub fn service_unavailable() -> Self {
        Self::error(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
    }
}

/// TCP proxy client for forwarding requests to local services.
pub struct TcpProxyClient {
    config: TcpProxyConfig,
}

impl TcpProxyClient {
    /// Create a new TCP proxy client.
    pub fn new(config: TcpProxyConfig) -> Self {
        Self { config }
    }

    /// Create with default config targeting the given address.
    pub fn for_target(target: SocketAddr) -> Self {
        Self::new(TcpProxyConfig {
            target,
            ..Default::default()
        })
    }

    /// Forward a request to the target and return the response.
    pub async fn forward(&self, request: ProxyRequest) -> Result<ProxyResponse, ClientError> {
        let target = self.config.target;

        // Build the URI with target host
        let uri_str = format!(
            "http://{}{}",
            target,
            request.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
        );

        let uri: Uri = uri_str.parse().map_err(|e| {
            ClientError::Connection(format!("Invalid URI: {}", e))
        })?;

        debug!("Forwarding {} {} to {}", request.method, request.uri, target);

        // Build hyper request
        let mut builder = Request::builder()
            .method(request.method.clone())
            .uri(&uri);

        // Add headers
        for (name, value) in &request.headers {
            // Skip pseudo-headers and host (we'll set our own)
            if name.starts_with(':') || name.eq_ignore_ascii_case("host") {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }

        // Set host header for target
        builder = builder.header("host", target.to_string());

        let body = if request.body.is_empty() {
            Full::new(Bytes::new()).boxed()
        } else {
            Full::new(request.body.clone()).boxed()
        };

        let hyper_request = builder.body(body).map_err(|e| {
            ClientError::Connection(format!("Failed to build request: {}", e))
        })?;

        // Create client
        let client: Client<_, _> = Client::builder(TokioExecutor::new())
            .build_http();

        // Send request with timeout
        let response = tokio::time::timeout(
            self.config.request_timeout,
            client.request(hyper_request),
        )
        .await
        .map_err(|_| ClientError::Connection("Request timeout".to_string()))?
        .map_err(|e| ClientError::Connection(format!("Request failed: {}", e)))?;

        // Extract response
        let status = response.status();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        // Read body
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| ClientError::Connection(format!("Failed to read body: {}", e)))?
            .to_bytes();

        debug!("Received response: {} ({} bytes)", status, body.len());

        Ok(ProxyResponse {
            status,
            headers,
            body,
        })
    }

    /// Check if the target is reachable.
    pub async fn health_check(&self) -> bool {
        match tokio::net::TcpStream::connect(self.config.target).await {
            Ok(_) => {
                debug!("Health check passed for {}", self.config.target);
                true
            }
            Err(e) => {
                warn!("Health check failed for {}: {}", self.config.target, e);
                false
            }
        }
    }

    /// Get the target address.
    pub fn target(&self) -> SocketAddr {
        self.config.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_proxy_config_default() {
        let config = TcpProxyConfig::default();
        assert_eq!(config.target, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert!(config.enable_http2);
    }

    #[test]
    fn test_proxy_request_builder() {
        let req = ProxyRequest::new(Method::POST, "/api/test".parse().unwrap())
            .with_header("content-type", "application/json")
            .with_header("x-custom", "value")
            .with_body(r#"{"key": "value"}"#);

        assert_eq!(req.method, Method::POST);
        assert_eq!(req.uri.path(), "/api/test");
        assert_eq!(req.headers.len(), 2);
        assert!(!req.body.is_empty());
    }

    #[test]
    fn test_proxy_response_builder() {
        let resp = ProxyResponse::new(StatusCode::OK)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status": "ok"}"#);

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.headers.len(), 1);
        assert!(!resp.body.is_empty());
    }

    #[test]
    fn test_proxy_response_error() {
        let resp = ProxyResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong");
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers.iter().any(|(k, _)| k == "content-type"));
    }

    #[test]
    fn test_proxy_response_gateway_timeout() {
        let resp = ProxyResponse::gateway_timeout();
        assert_eq!(resp.status, StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn test_proxy_response_bad_gateway() {
        let resp = ProxyResponse::bad_gateway("connection refused");
        assert_eq!(resp.status, StatusCode::BAD_GATEWAY);
        assert!(String::from_utf8_lossy(&resp.body).contains("connection refused"));
    }

    #[test]
    fn test_proxy_response_service_unavailable() {
        let resp = ProxyResponse::service_unavailable();
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_tcp_proxy_client_new() {
        let config = TcpProxyConfig {
            target: "127.0.0.1:3000".parse().unwrap(),
            ..Default::default()
        };
        let client = TcpProxyClient::new(config);
        assert_eq!(client.target(), "127.0.0.1:3000".parse().unwrap());
    }

    #[test]
    fn test_tcp_proxy_client_for_target() {
        let client = TcpProxyClient::for_target("127.0.0.1:9000".parse().unwrap());
        assert_eq!(client.target(), "127.0.0.1:9000".parse().unwrap());
    }

    #[tokio::test]
    async fn test_health_check_no_server() {
        // Port 59999 should not have a server running
        let client = TcpProxyClient::for_target("127.0.0.1:59999".parse().unwrap());
        assert!(!client.health_check().await);
    }
}
