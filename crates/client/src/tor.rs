//! Tor transport via embedded Arti (whitepaper §12): the connection to the
//! first hop (and status queries) goes through Tor by default.
//! `// TRUST: Tor for privacy only, never for correctness (whitepaper §2)`.

use arti_client::{TorClient, TorClientConfig};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Duration;
use tor_rtcompat::PreferredRuntime;

pub struct TorTransport {
    client: Arc<TorClient<PreferredRuntime>>,
}

impl TorTransport {
    /// Bootstrap a Tor client; fails (so the caller can fall back) if the
    /// network is unreachable within `timeout`.
    pub async fn bootstrap(timeout: Duration) -> anyhow::Result<Self> {
        let config = TorClientConfig::default();
        let client = tokio::time::timeout(timeout, TorClient::create_bootstrapped(config))
            .await
            .map_err(|_| anyhow::anyhow!("Tor bootstrap timed out after {timeout:?}"))??;
        Ok(TorTransport { client })
    }

    /// Minimal HTTP/1.1 request over a Tor stream (plain http to the hop).
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<(u16, Vec<u8>)> {
        let (host, port, path) = parse_http_url(url)?;
        let stream = self.client.connect((host.as_str(), port)).await?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", &host)
            .header("Content-Type", "application/octet-stream")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))?;
        let resp = sender.send_request(req).await?;
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await?.to_bytes().to_vec();
        Ok((status, bytes))
    }
}

/// `http://host:port/path` → (host, port, path).
pub fn parse_http_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only http:// URLs are routed through Tor"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>()?),
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn url_parsing() {
        let (h, p, path) = super::parse_http_url("http://example.onion:8440/v1/mix").unwrap();
        assert_eq!(
            (h.as_str(), p, path.as_str()),
            ("example.onion", 8440, "/v1/mix")
        );
        assert!(super::parse_http_url("https://x/").is_err());
    }
}
