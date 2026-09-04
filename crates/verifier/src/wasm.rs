//! Browser entry point. `verify_snapshot(snapshot, headers, config_json)`
//! returns the report as JSON. `config_json`: `{"issuer_keys": [hex],
//! "dev_mode": bool, "mock_tip": u32?, "vk": hex?, "vk_hash": hex?}`.
//! Outside dev mode the verifying key must match a pin (SPEC §18.7): either
//! `vk_hash` from the caller, or `MEMBERSHIP_VK_BLAKE3` compiled into this
//! `.wasm`. The compiled-in form is the one that means something in a
//! browser — the page supplying the snapshot should not also get to choose
//! the key it is checked against.
//! `issuer_keys` is optional: empty means "every Issuer in the snapshot",
//! and each result names the Issuer it was computed under.

use crate::{ChainHeaders, Config, MockHeaders, Report, dev_verifier, verify};
use cv_core::context::Deployment;
use cv_core::crypto::groth16::MembershipVerifier;
use cv_core::headers::HeaderChain;
use cv_core::snapshot::Headers;
use serde::Deserialize;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
struct JsConfig {
    #[serde(default)]
    issuer_keys: Vec<String>,
    #[serde(default)]
    dev_mode: bool,
    mock_tip: Option<u32>,
    vk: Option<String>,
    vk_hash: Option<String>,
    vote: Option<String>,
}

fn key(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "expected 32 bytes of hex".to_string())
}

fn run(snapshot: &[u8], headers: &[u8], config_json: &str) -> Result<Report, String> {
    let cfg: JsConfig = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
    let deployment = Deployment {
        issuer_keys: cfg
            .issuer_keys
            .iter()
            .map(|k| key(k))
            .collect::<Result<_, _>>()?,
        dev_mode: cfg.dev_mode,
    };
    let verifier = match (&cfg.vk, cfg.dev_mode) {
        (Some(v), _) => {
            let verifier =
                MembershipVerifier::from_bytes(&hex::decode(v).map_err(|e| e.to_string())?)
                    .ok_or("bad verifying key")?;
            if !cfg.dev_mode {
                let pin = cfg.vk_hash.as_deref().map(key).transpose()?;
                cv_core::keys::check_pin(&verifier, pin).map_err(|e| e.to_string())?;
            }
            verifier
        }
        (None, true) => dev_verifier(),
        (None, false) => return Err("vk is required outside dev mode".into()),
    };
    let hs: Arc<dyn Headers> = if headers.is_empty() {
        if !cfg.dev_mode {
            return Err("headers are required outside dev mode".into());
        }
        Arc::new(MockHeaders {
            tip: cfg.mock_tip.unwrap_or(1_000_000),
        })
    } else {
        Arc::new(ChainHeaders(
            HeaderChain::from_file(headers, 0).map_err(|e| e.to_string())?,
        ))
    };
    let only = cfg.vote.as_deref().map(key).transpose()?;
    verify(
        snapshot,
        hs,
        Config {
            deployment,
            verifier: Arc::new(verifier),
        },
        only,
    )
}

#[wasm_bindgen]
pub fn verify_snapshot(snapshot: &[u8], headers: &[u8], config_json: &str) -> String {
    match run(snapshot, headers, config_json) {
        Ok(r) => serde_json::to_string(&r).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}
