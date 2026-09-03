//! Bitcoin headers from an Esplora-style HTTP API (mempool.space,
//! blockstream.info). `// TRUST: header source for liveness only (SPEC §9)`:
//! every header is checked for linkage and proof of work by `HeaderChain`;
//! a lying source can only withhold headers or feed a chain we would reject.

use cv_core::crypto::spv;
use cv_log::headers::{HeaderChain, SharedHeaderChain};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

pub const DEFAULT_HEADERS_API: &str = "https://mempool.space/api";

pub struct HeaderSync {
    pub chain: Arc<SharedHeaderChain>,
    pub api: String,
    pub client: reqwest::Client,
}

impl HeaderSync {
    pub fn new(
        chain: Arc<SharedHeaderChain>,
        api: impl Into<String>,
        client: reqwest::Client,
    ) -> Self {
        HeaderSync {
            chain,
            api: api.into().trim_end_matches('/').to_string(),
            client,
        }
    }

    async fn tip_height(&self) -> anyhow::Result<u32> {
        Ok(self
            .client
            .get(format!("{}/blocks/tip/height", self.api))
            .send()
            .await?
            .text()
            .await?
            .trim()
            .parse()?)
    }

    async fn header_at(&self, height: u32) -> anyhow::Result<spv::BlockHeader> {
        let hash = self
            .client
            .get(format!("{}/block-height/{height}", self.api))
            .send()
            .await?
            .text()
            .await?;
        let hex_header = self
            .client
            .get(format!("{}/block/{}/header", self.api, hash.trim()))
            .send()
            .await?
            .text()
            .await?;
        let bytes = hex::decode(hex_header.trim())?;
        spv::decode_header(&bytes).ok_or_else(|| anyhow::anyhow!("bad header bytes"))
    }

    /// Fetch and append headers up to the remote tip. On a link failure
    /// (reorg), drop a few headers and retry next round.
    pub async fn sync_once(&self) -> anyhow::Result<usize> {
        let remote_tip = self.tip_height().await?;
        let mut added = 0;
        loop {
            let (local_tip, _) = self.chain.0.read().unwrap().tip();
            if local_tip >= remote_tip {
                break;
            }
            let h = self.header_at(local_tip + 1).await?;
            let r = self.chain.0.write().unwrap().append(h);
            match r {
                Ok(_) => added += 1,
                Err(e) => {
                    tracing::warn!(
                        height = local_tip + 1,
                        "header rejected ({e}); truncating 6 headers for reorg"
                    );
                    let mut c = self.chain.0.write().unwrap();
                    let keep = local_tip.saturating_sub(6).max(c.start_height());
                    c.truncate(keep);
                    break;
                }
            }
        }
        Ok(added)
    }

    pub async fn run(
        self,
        interval: Duration,
        on_change: impl Fn() + Send + 'static,
        mut shutdown: watch::Receiver<bool>,
    ) {
        loop {
            match self.sync_once().await {
                Ok(n) if n > 0 => {
                    tracing::info!(
                        added = n,
                        tip = self.chain.0.read().unwrap().tip().0,
                        "headers synced"
                    );
                    on_change();
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("header sync failed: {e}"),
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tokio::time::sleep(interval) => {}
            }
        }
    }
}

/// Parse a `height:hex-header` checkpoint argument.
pub fn parse_checkpoint(height: u32, header_hex: &str) -> anyhow::Result<HeaderChain> {
    let bytes = hex::decode(header_hex)?;
    let h = spv::decode_header(&bytes)
        .ok_or_else(|| anyhow::anyhow!("checkpoint header must be 80 bytes"))?;
    Ok(HeaderChain::new(
        height,
        h,
        cv_core::constants::MIN_CONFIRMATIONS,
    ))
}
