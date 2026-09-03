//! Light client: talks to nodes over HTTP. Never trusts a single node for
//! anything that matters (whitepaper §12): anchors are verified by SPV and
//! items by their proofs on the client side.

use cv_core::crypto::field::{Fr, fr_to_bytes};
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, decode_leaves, encode_leaves};
use cv_core::wire::*;

#[derive(Clone)]
pub struct NodeClient {
    base: String,
    http: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("node returned {0}")]
    Status(u16),
    #[error("malformed response: {0}")]
    Malformed(String),
    #[error("node answered with something other than {0}")]
    WrongItem(String),
    #[error("registry from the node is not the one that was asked for: {0}")]
    BadRegistry(&'static str),
}

impl NodeClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        NodeClient {
            base: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    pub async fn status(&self) -> Result<Status, ClientError> {
        Ok(self
            .http
            .get(format!("{}/v1/status", self.base))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn submit(&self, bytes: Vec<u8>) -> Result<SubmitResponse, ClientError> {
        Ok(self
            .http
            .post(format!("{}/v1/items", self.base))
            .body(bytes)
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn submit_item(&self, item: &Item) -> Result<SubmitResponse, ClientError> {
        self.submit(item.encode()).await
    }

    async fn get_bytes(&self, path: String) -> Result<Option<Vec<u8>>, ClientError> {
        let r = self
            .http
            .get(format!("{}{}", self.base, path))
            .send()
            .await?;
        match r.status().as_u16() {
            200 => Ok(Some(r.bytes().await?.to_vec())),
            404 => Ok(None),
            s => Err(ClientError::Status(s)),
        }
    }

    /// Fetch an item by content id. The answer is checked against the id that
    /// was asked for: a node that serves a *different* item — a decoy vote
    /// with the options swapped, say — is caught here rather than believed
    /// (whitepaper §12: never trust a single node).
    pub async fn item(&self, content_id: &Id) -> Result<Option<Item>, ClientError> {
        match self
            .get_bytes(format!("/v1/items/{}", hex::encode(content_id)))
            .await?
        {
            Some(b) => {
                let item = Item::decode(&b).map_err(|e| ClientError::Malformed(e.to_string()))?;
                if item.content_id() != *content_id {
                    return Err(ClientError::WrongItem(hex::encode(content_id)));
                }
                Ok(Some(item))
            }
            None => Ok(None),
        }
    }

    /// Fetch item bytes by item hash, checking the bytes hash to what was asked.
    pub async fn item_by_hash(&self, item_hash: &Id) -> Result<Option<Vec<u8>>, ClientError> {
        let bytes = self
            .get_bytes(format!("/v1/items/by-hash/{}", hex::encode(item_hash)))
            .await?;
        if let Some(b) = &bytes {
            if cv_core::crypto::hash::blake3_hash(b) != *item_hash {
                return Err(ClientError::WrongItem(hex::encode(item_hash)));
            }
        }
        Ok(bytes)
    }

    pub async fn inventory(&self, since: u64, limit: usize) -> Result<Inventory, ClientError> {
        Ok(self
            .http
            .get(format!(
                "{}/v1/inventory?since={since}&limit={limit}",
                self.base
            ))
            .send()
            .await?
            .json()
            .await?)
    }

    /// All item hashes held by the node (pages through the inventory).
    pub async fn all_hashes(&self) -> Result<Vec<Id>, ClientError> {
        let mut out = Vec::new();
        let mut since = 0;
        loop {
            let inv = self.inventory(since, 1000).await?;
            if inv.items.is_empty() {
                break;
            }
            for (seq, h) in inv.items {
                since = seq;
                if let Ok(h) = hex::decode(h) {
                    if let Ok(h) = h.try_into() {
                        out.push(h);
                    }
                }
            }
        }
        Ok(out)
    }

    pub async fn votes(&self) -> Result<Vec<VoteSummary>, ClientError> {
        Ok(self
            .http
            .get(format!("{}/v1/votes", self.base))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn vote(&self, vote_id: &Id) -> Result<Option<VoteDefinition>, ClientError> {
        match self.item(vote_id).await? {
            Some(Item::VoteDefinition(v)) => Ok(Some(v)),
            Some(_) => Err(ClientError::Malformed("not a vote definition".into())),
            None => Ok(None),
        }
    }

    pub async fn vote_ballots(&self, vote_id: &Id) -> Result<Vec<BallotStatusJson>, ClientError> {
        Ok(self
            .http
            .get(format!(
                "{}/v1/votes/{}/ballots",
                self.base,
                hex::encode(vote_id)
            ))
            .send()
            .await?
            .json()
            .await?)
    }

    /// Light-client query by nullifier (whitepaper §12).
    pub async fn ballot_status(
        &self,
        vote_id: &Id,
        nullifier: &Fr,
    ) -> Result<Vec<BallotStatusJson>, ClientError> {
        Ok(self
            .http
            .get(format!(
                "{}/v1/votes/{}/nullifier/{}",
                self.base,
                hex::encode(vote_id),
                hex::encode(fr_to_bytes(nullifier))
            ))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn keyparties(&self, vote_id: &Id) -> Result<Vec<KeyPartySummary>, ClientError> {
        Ok(self
            .http
            .get(format!(
                "{}/v1/votes/{}/keyparties",
                self.base,
                hex::encode(vote_id)
            ))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn nodes(&self) -> Result<Vec<NodeSummary>, ClientError> {
        Ok(self
            .http
            .get(format!("{}/v1/nodes", self.base))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn anchors(&self) -> Result<Vec<AnchorSummary>, ClientError> {
        Ok(self
            .http
            .get(format!("{}/v1/anchors", self.base))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn anchor_proof(
        &self,
        anchor_id: &Id,
        content_id: &Id,
    ) -> Result<Option<InclusionProofJson>, ClientError> {
        let r = self
            .http
            .get(format!(
                "{}/v1/anchors/{}/proof/{}",
                self.base,
                hex::encode(anchor_id),
                hex::encode(content_id)
            ))
            .send()
            .await?;
        match r.status().as_u16() {
            200 => Ok(Some(r.json().await?)),
            404 => Ok(None),
            s => Err(ClientError::Status(s)),
        }
    }

    pub async fn registries(&self) -> Result<Vec<RegistrySummary>, ClientError> {
        Ok(self
            .http
            .get(format!("{}/v1/registry", self.base))
            .send()
            .await?
            .json()
            .await?)
    }

    /// One Issuer's registry: a root alone does not identify an electorate.
    pub async fn registry(
        &self,
        issuer_key: &[u8; 32],
        root: &Fr,
    ) -> Result<Option<(RegistrySnapshot, Vec<Fr>)>, ClientError> {
        let issuer_hex = hex::encode(issuer_key);
        let root_hex = hex::encode(fr_to_bytes(root));
        let Some(snap) = self
            .get_bytes(format!("/v1/registry/{issuer_hex}/{root_hex}/snapshot"))
            .await?
        else {
            return Ok(None);
        };
        let Some(leaves) = self
            .get_bytes(format!("/v1/registry/{issuer_hex}/{root_hex}/leaves"))
            .await?
        else {
            return Ok(None);
        };
        let snapshot =
            RegistrySnapshot::decode(&snap).map_err(|e| ClientError::Malformed(e.to_string()))?;
        let leaves = decode_leaves(&leaves).map_err(|e| ClientError::Malformed(e.to_string()))?;
        // The node is not trusted for the electorate: the snapshot must be the
        // one that was asked for and must carry that Issuer's own signature.
        if snapshot.issuer_key != *issuer_key {
            return Err(ClientError::BadRegistry("another issuer"));
        }
        if snapshot.root != *root {
            return Err(ClientError::BadRegistry("another root"));
        }
        if !snapshot.verify() {
            return Err(ClientError::BadRegistry("issuer signature"));
        }
        if snapshot.leaf_count != leaves.len() as u64 {
            return Err(ClientError::BadRegistry("leaf count"));
        }
        Ok(Some((snapshot, leaves)))
    }

    pub async fn post_registry(
        &self,
        snapshot: &RegistrySnapshot,
        leaves: &[Fr],
    ) -> Result<(), ClientError> {
        let mut body = snapshot.encode();
        body.extend_from_slice(&encode_leaves(leaves));
        let r = self
            .http
            .post(format!("{}/v1/registry", self.base))
            .body(body)
            .send()
            .await?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(ClientError::Status(r.status().as_u16()))
        }
    }

    pub async fn tip(&self) -> Result<Option<u32>, ClientError> {
        let t: Tip = self
            .http
            .get(format!("{}/v1/headers/tip", self.base))
            .send()
            .await?
            .json()
            .await?;
        Ok(t.height)
    }

    pub async fn snapshot(&self) -> Result<Vec<u8>, ClientError> {
        Ok(self
            .http
            .get(format!("{}/v1/snapshot", self.base))
            .send()
            .await?
            .bytes()
            .await?
            .to_vec())
    }
}
