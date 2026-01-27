//! Sovereign Proxy - forwards H3 requests to local backends

use std::net::SocketAddr;

use anyhow::Result;
use bytes::{Buf, Bytes};
use h3::quic::BidiStream;
use h3::server::RequestStream;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::{debug, error, info};

/// Sovereign Proxy forwards H3 requests to a local HTTP backend
pub struct SovereignProxy {
    target: SocketAddr,
}

impl SovereignProxy {
    pub fn new(target: SocketAddr) -> Self {
        Self { target }
    }

    pub async fn handle_request<S>(
        &self,
        request: Request<()>,
        mut stream: RequestStream<S, Bytes>,
        remote_addr: SocketAddr,
    ) -> Result<()>
    where
        S: BidiStream<Bytes>,
    {
        let method = request.method().clone();
        let uri = request.uri().clone();
        let headers = request.headers().clone();

        info!("{} {} from {}", method, uri, remote_addr);

        // Read request body
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            body.extend_from_slice(chunk.chunk());
            chunk.advance(chunk.remaining());
        }

        // Build HTTP request for backend
        let backend_uri = format!(
            "http://{}{}",
            self.target,
            uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
        );

        let mut backend_req = Request::builder()
            .method(method.clone())
            .uri(&backend_uri);

        // Forward headers (skip pseudo-headers)
        for (name, value) in headers.iter() {
            let name_str = name.as_str();
            if name_str.starts_with(':') || name_str.eq_ignore_ascii_case("host") {
                continue;
            }
            backend_req = backend_req.header(name, value);
        }

        // Set host header for backend
        backend_req = backend_req.header("host", self.target.to_string());

        // Add proxy headers
        backend_req = backend_req.header("x-forwarded-for", remote_addr.ip().to_string());
        backend_req = backend_req.header("x-forwarded-proto", "https");
        backend_req = backend_req.header("x-forwarded-port", remote_addr.port().to_string());

        let backend_body = if body.is_empty() {
            Full::new(Bytes::new()).boxed()
        } else {
            Full::new(Bytes::from(body)).boxed()
        };

        let backend_req = backend_req.body(backend_body)?;

        // Send to backend
        let client: Client<_, _> = Client::builder(TokioExecutor::new()).build_http();

        let backend_resp = match client.request(backend_req).await {
            Ok(resp) => resp,
            Err(e) => {
                error!("Backend error: {}", e);
                let response = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(())?;
                stream.send_response(response).await?;
                stream.send_data(Bytes::from(format!("Bad Gateway: {}", e))).await?;
                stream.finish().await.ok();
                return Ok(());
            }
        };

        let status = backend_resp.status();
        let resp_headers = backend_resp.headers().clone();

        // Build H3 response
        let mut h3_response = Response::builder().status(status);

        for (name, value) in resp_headers.iter() {
            // Skip hop-by-hop headers
            let name_str = name.as_str();
            if name_str.eq_ignore_ascii_case("connection")
                || name_str.eq_ignore_ascii_case("keep-alive")
                || name_str.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            h3_response = h3_response.header(name, value);
        }

        let h3_response = h3_response.body(())?;

        // Send response headers
        stream.send_response(h3_response).await?;

        // Stream response body
        let resp_body = backend_resp.into_body().collect().await?.to_bytes();

        if !resp_body.is_empty() {
            const CHUNK_SIZE: usize = 16384;
            for chunk in resp_body.chunks(CHUNK_SIZE) {
                stream.send_data(Bytes::copy_from_slice(chunk)).await?;
            }
        }

        // Finish stream
        if let Err(e) = stream.finish().await {
            debug!("Stream finish: {} (client may have closed)", e);
        }

        debug!("{} {} -> {} ({} bytes)", method, uri, status.as_u16(), resp_body.len());

        Ok(())
    }
}
