//! JSON types of the node HTTP API (shared by node and light client).
//! Binary items travel as raw bytes; these types carry indexes and status.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum SubmitResponse {
    New {
        content_id: String,
        item_type: String,
        seq: u64,
    },
    AlreadyHave,
    Equivalent {
        content_id: String,
    },
    Orphaned {
        reference: String,
    },
    Rejected {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inventory {
    pub latest_seq: u64,
    /// `(seq, item_hash hex)` pairs in sequence order.
    pub items: Vec<(u64, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteSummary {
    pub vote_id: String,
    pub question: String,
    pub options: Vec<String>,
    pub open_block: u32,
    pub close_block: u32,
    pub min_ballots: u32,
    pub secrecy: String,
    pub ballots: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BallotStatusJson {
    pub content_id: String,
    pub anchored_height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorSummary {
    pub content_id: String,
    pub height: u32,
    pub leaf_count: usize,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionProofJson {
    pub root: String,
    pub leaf_count: u32,
    pub index: u32,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrySummary {
    pub root: String,
    pub epoch: u64,
    pub leaf_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub name: String,
    pub dev_mode: bool,
    pub items: usize,
    pub orphans: usize,
    pub latest_seq: u64,
    pub tip_height: Option<u32>,
    pub peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tip {
    pub height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResultJson {
    pub vote_id: String,
    pub question: String,
    pub options: Vec<String>,
    pub secrecy: String,
    /// "result" | "below_minimum" | "not_closed" | "pending" | "unknown"
    pub outcome: String,
    pub guarantee: Option<String>,
    pub counts: Option<Vec<u64>>,
    pub counted: Option<u64>,
    pub missing_shares: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitiativeSummary {
    pub initiative_id: String,
    pub text: String,
    pub threshold_n: u32,
    pub support_deadline_block: u32,
    pub secrecy: String,
    pub supports: usize,
    pub derived_vote_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollRequest {
    pub eid: String,
    pub commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollResponse {
    pub index: u32,
    pub epoch: u64,
    pub root: String,
    pub replaced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeSummary {
    pub node_key: String,
    pub mix_key: String,
    pub endpoint: String,
    pub operator: String,
    pub country: String,
    pub asn: u32,
}
