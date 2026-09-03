//! UniFFI surface for iOS/Android shells (whitepaper §15: the UI never
//! touches cryptography). Blocking wrappers over the async library; generate
//! bindings with `uniffi-bindgen` (see README).

use crate::device::Device;
use crate::light::NodeClient;
use crate::mix::{MixClient, TorSetup};
use crate::participant::ParticipantClient;
use cv_core::crypto::groth16;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{msg}")]
    Failure { msg: String },
}

impl From<anyhow::Error> for FfiError {
    fn from(e: anyhow::Error) -> Self {
        FfiError::Failure { msg: e.to_string() }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CastSummary {
    pub nullifier: String,
    pub receipt: String,
    pub anchored_height: Option<u32>,
    pub privacy: String,
    pub attempts: u32,
}

fn runtime() -> Result<tokio::runtime::Runtime, FfiError> {
    tokio::runtime::Runtime::new().map_err(|e| FfiError::Failure { msg: e.to_string() })
}

fn keys(dev: bool, keys_dir: Option<String>) -> Result<Arc<groth16::MembershipKeys>, FfiError> {
    if dev {
        Ok(Arc::new(groth16::setup(
            &mut <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(
                groth16::DEV_SETUP_SEED,
            ),
        )))
    } else {
        let dir = keys_dir.ok_or(FfiError::Failure {
            msg: "keys_dir required outside dev mode".into(),
        })?;
        let bytes = std::fs::read(Path::new(&dir).join("membership.pk"))
            .map_err(|e| FfiError::Failure { msg: e.to_string() })?;
        let pk = groth16::pk_from_bytes(&bytes).ok_or(FfiError::Failure {
            msg: "bad proving key".into(),
        })?;
        Ok(Arc::new(groth16::MembershipKeys::from_proving_key(pk)))
    }
}

/// Create a device file with a fresh secret; returns the commitment (hex).
#[uniffi::export]
pub fn device_create(path: String) -> Result<String, FfiError> {
    let d = Device::generate(&mut rand::rngs::OsRng);
    d.save(Path::new(&path))?;
    Ok(hex::encode(cv_core::crypto::field::fr_to_bytes(
        &d.commitment(),
    )))
}

/// Enroll with an Issuer; returns the leaf index. `credential` is whatever
/// that Issuer's verification backend expects.
#[uniffi::export]
pub fn device_enroll(
    path: String,
    issuer_url: String,
    credential: String,
    node_url: String,
    dev: bool,
) -> Result<u32, FfiError> {
    let rt = runtime()?;
    rt.block_on(async {
        let mut d = Device::load(Path::new(&path))?;
        let mut pc = ParticipantClient::new(NodeClient::new(node_url), keys(dev, None)?);
        pc.dev = dev;
        let r = pc
            .enroll(&mut d, &issuer_url, &credential)
            .await
            .map_err(|e| FfiError::Failure { msg: e.to_string() })?;
        d.save(Path::new(&path))?;
        Ok(r.index)
    })
}

/// Cast through the mix (Tor if reachable within `tor_timeout_secs`, else
/// direct, reported in `privacy`) and retry until anchored.
#[uniffi::export]
pub fn cast_ballot(
    path: String,
    node_url: String,
    vote_id_hex: String,
    option: u8,
    dev: bool,
    window_secs: u64,
    tor_timeout_secs: u64,
) -> Result<CastSummary, FfiError> {
    let rt = runtime()?;
    rt.block_on(async {
        let mut d = Device::load(Path::new(&path))?;
        let vote_id: [u8; 32] = hex::decode(&vote_id_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(FfiError::Failure {
                msg: "bad vote id".into(),
            })?;
        #[cfg(feature = "tor")]
        let tor = if tor_timeout_secs == 0 {
            TorSetup::Disabled
        } else {
            match crate::tor::TorTransport::bootstrap(Duration::from_secs(tor_timeout_secs)).await {
                Ok(t) => TorSetup::Ready(t),
                Err(e) => TorSetup::Failed(e.to_string()),
            }
        };
        #[cfg(not(feature = "tor"))]
        let tor = {
            let _ = tor_timeout_secs;
            TorSetup::Disabled
        };
        let mc = MixClient {
            dev,
            ..MixClient::new(NodeClient::new(node_url), tor)
        };
        let k = keys(dev, None)?;
        let r = mc
            .cast_with_retry(
                &mut d,
                &k,
                &vote_id,
                option,
                Duration::from_secs(window_secs),
                5,
            )
            .await?;
        d.save(Path::new(&path))?;
        Ok(CastSummary {
            nullifier: hex::encode(cv_core::crypto::field::fr_to_bytes(&r.ballot.nullifier)),
            receipt: ParticipantClient::receipt(&r.ballot),
            anchored_height: r.anchored_height,
            privacy: r.privacy.to_string(),
            attempts: r.attempts,
        })
    })
}

/// A vote's result as JSON (as the node computes it).
#[uniffi::export]
pub fn vote_result_json(node_url: String, vote_id_hex: String) -> Result<String, FfiError> {
    let rt = runtime()?;
    rt.block_on(async {
        let r = reqwest::Client::new()
            .get(format!(
                "{}/v1/votes/{}/result",
                node_url.trim_end_matches('/'),
                vote_id_hex
            ))
            .send()
            .await
            .map_err(|e| FfiError::Failure { msg: e.to_string() })?;
        r.text()
            .await
            .map_err(|e| FfiError::Failure { msg: e.to_string() })
    })
}
