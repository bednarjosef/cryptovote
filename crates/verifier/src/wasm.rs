//! Browser entry point. `verify_snapshot(snapshot, headers, config_json)`
//! returns the report as JSON. `config_json`: `{"issuer_key": hex,
//! "authority_keys": [hex], "dev_mode": bool, "mock_tip": u32?, "vk": hex?}`.

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
    issuer_key: String,
    #[serde(default)]
    authority_keys: Vec<String>,
    #[serde(default)]
    dev_mode: bool,
    mock_tip: Option<u32>,
    vk: Option<String>,
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
        authority_keys: cfg
            .authority_keys
            .iter()
            .map(|k| key(k))
            .collect::<Result<_, _>>()?,
        issuer_key: key(&cfg.issuer_key)?,
        dev_mode: cfg.dev_mode,
    };
    let verifier = match (&cfg.vk, cfg.dev_mode) {
        (Some(v), _) => MembershipVerifier::from_bytes(&hex::decode(v).map_err(|e| e.to_string())?)
            .ok_or("bad verifying key")?,
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
