//! Participant actions over the node API: enroll, cast, confirm, support,
//! author initiatives. Retry-until-anchored and the mix path are Phase 7;
//! this is the direct path.

use crate::device::Device;
use crate::light::{ClientError, NodeClient};
use cv_core::build::*;
use cv_core::constants::initiative_threshold;
use cv_core::crypto::field::Fr;
use cv_core::crypto::groth16::MembershipKeys;
use cv_core::items::*;
use cv_core::wire::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum ParticipantError {
    #[error("{0}")]
    Client(#[from] ClientError),
    #[error("device is not enrolled in registry root {0}")]
    NotEnrolled(String),
    #[error("unknown vote")]
    UnknownVote,
    #[error("unknown initiative")]
    UnknownInitiative,
    #[error("registry not available on the node")]
    NoRegistry,
    #[error("cannot prove membership: {0}")]
    Prove(#[from] cv_core::crypto::groth16::Unsatisfiable),
    #[error("node rejected the item: {0}")]
    Rejected(String),
    #[error("issuer error: {0}")]
    Issuer(String),
}

pub struct ParticipantClient {
    pub node: NodeClient,
    pub keys: Arc<MembershipKeys>,
}

impl ParticipantClient {
    pub fn new(node: NodeClient, keys: Arc<MembershipKeys>) -> Self {
        ParticipantClient { node, keys }
    }

    /// Enroll with an issuer over HTTP (mock eID in dev).
    pub async fn enroll(
        &self,
        device: &mut Device,
        issuer_url: &str,
        eid: &str,
    ) -> Result<EnrollResponse, ParticipantError> {
        let req = EnrollRequest {
            eid: eid.to_string(),
            commitment: hex::encode(cv_core::crypto::field::fr_to_bytes(&device.commitment())),
        };
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/enroll", issuer_url.trim_end_matches('/')))
            .json(&req)
            .send()
            .await
            .map_err(|e| ParticipantError::Issuer(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ParticipantError::Issuer(format!(
                "status {}",
                resp.status()
            )));
        }
        let r: EnrollResponse = resp
            .json()
            .await
            .map_err(|e| ParticipantError::Issuer(e.to_string()))?;
        device.enrollment = Some(crate::device::Enrollment {
            issuer_url: issuer_url.to_string(),
            index: r.index,
        });
        Ok(r)
    }

    /// Proving material for `root`, fetched from the node.
    pub async fn participant(
        &self,
        device: &Device,
        root: &Fr,
    ) -> Result<Participant, ParticipantError> {
        let (_, leaves) = self
            .node
            .registry(root)
            .await?
            .ok_or(ParticipantError::NoRegistry)?;
        device.participant(&leaves).ok_or_else(|| {
            ParticipantError::NotEnrolled(hex::encode(cv_core::crypto::field::fr_to_bytes(root)))
        })
    }

    fn check(resp: SubmitResponse) -> Result<SubmitResponse, ParticipantError> {
        match resp {
            SubmitResponse::Rejected { reason } => Err(ParticipantError::Rejected(reason)),
            ok => Ok(ok),
        }
    }

    /// Build and submit a plaintext ballot (secrecy = none).
    pub async fn cast(
        &self,
        device: &Device,
        vote_id: &Id,
        option: u8,
    ) -> Result<(Ballot, SubmitResponse), ParticipantError> {
        let vd = self
            .node
            .vote(vote_id)
            .await?
            .ok_or(ParticipantError::UnknownVote)?;
        let p = self.participant(device, &vd.registry_root).await?;
        let ballot = plaintext_ballot(&self.keys, &p, &vd, option)?;
        let resp = Self::check(self.node.submit_item(&Item::Ballot(ballot.clone())).await?)?;
        Ok((ballot, resp))
    }

    /// Poll until the nullifier appears under an anchor (whitepaper §12
    /// "client responsibility"). Returns the anchor height.
    pub async fn confirm(
        &self,
        vote_id: &Id,
        nullifier: &Fr,
        timeout: Duration,
    ) -> Result<Option<u32>, ParticipantError> {
        let deadline = Instant::now() + timeout;
        loop {
            let st = self.node.ballot_status(vote_id, nullifier).await?;
            if let Some(h) = st.iter().filter_map(|s| s.anchored_height).min() {
                return Ok(Some(h));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn support(
        &self,
        device: &Device,
        initiative_id: &Id,
    ) -> Result<(Support, SubmitResponse), ParticipantError> {
        let Some(Item::Initiative(init)) = self.node.item(initiative_id).await? else {
            return Err(ParticipantError::UnknownInitiative);
        };
        let p = self.participant(device, &init.registry_root).await?;
        let s = build_support(&self.keys, &p, initiative_id)?;
        let resp = Self::check(self.node.submit_item(&Item::Support(s.clone())).await?)?;
        Ok((s, resp))
    }

    pub async fn create_initiative(
        &self,
        device: &Device,
        root: &Fr,
        text: String,
        support_deadline_block: u32,
        secrecy: Secrecy,
    ) -> Result<(Initiative, SubmitResponse), ParticipantError> {
        let (snapshot, _) = self
            .node
            .registry(root)
            .await?
            .ok_or(ParticipantError::NoRegistry)?;
        let p = self.participant(device, root).await?;
        let n = initiative_threshold(snapshot.leaf_count);
        let i = build_initiative(&self.keys, &p, text, n, support_deadline_block, secrecy)?;
        let resp = Self::check(self.node.submit_item(&Item::Initiative(i.clone())).await?)?;
        Ok((i, resp))
    }

    pub async fn result(&self, vote_id: &Id) -> Result<Option<ResultJson>, ParticipantError> {
        let r = reqwest::Client::new()
            .get(format!(
                "{}/v1/votes/{}/result",
                self.node.base_url(),
                hex::encode(vote_id)
            ))
            .send()
            .await
            .map_err(ClientError::Http)?;
        match r.status().as_u16() {
            200 => Ok(Some(r.json().await.map_err(ClientError::Http)?)),
            404 => Ok(None),
            s => Err(ClientError::Status(s).into()),
        }
    }

    pub async fn initiatives(&self) -> Result<Vec<InitiativeSummary>, ParticipantError> {
        let r = reqwest::Client::new()
            .get(format!("{}/v1/initiatives", self.node.base_url()))
            .send()
            .await
            .map_err(ClientError::Http)?;
        Ok(r.json().await.map_err(ClientError::Http)?)
    }

    /// Receipt code (SPEC §16): 8 Crockford base32 characters of `H_B("receipt"; n || payload)`.
    pub fn receipt(ballot: &Ballot) -> String {
        let mut data = cv_core::crypto::field::fr_to_bytes(&ballot.nullifier).to_vec();
        data.extend_from_slice(&ballot.payload);
        let h = cv_core::crypto::hash::tagged("receipt", &data);
        crockford(&h[..5])
    }
}

fn crockford(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut out = String::new();
    for b in bytes {
        bits = (bits << 8) | *b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((bits >> nbits) & 31) as usize] as char);
        }
    }
    out
}
