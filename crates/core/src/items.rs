//! Log items: types, canonical encoding, content ids (SPEC §6).
//!
//! `content_id` is the BLAKE3 hash of the item bytes **without** the trailing
//! proof or signature (ASSUMPTIONS A3); `item_hash` covers the exact bytes.

use crate::constants::*;
use crate::encoding::{MAX_BYTES_FIELD, Reader, Writer};
use crate::error::DecodeError;
use cv_crypto::field::Fr;
use cv_crypto::hash::blake3_hash;

pub type Id = [u8; 32];

/// A Groth16 proof in canonical compressed form (SPEC §1.4).
#[derive(Clone, PartialEq, Eq)]
pub struct Proof(pub [u8; 128]);

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Proof({}…)", hex_prefix(&self.0))
    }
}

fn hex_prefix(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{x:02x}")).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ItemType {
    VoteDefinition = 0x01,
    Initiative = 0x02,
    Support = 0x03,
    Ballot = 0x04,
    Anchor = 0x05,
    KeyParty = 0x06,
    NodeRegistration = 0x07,
    Witness = 0x08,
    Share = 0x09,
}

impl ItemType {
    pub fn from_u8(b: u8) -> Result<Self, DecodeError> {
        Ok(match b {
            0x01 => ItemType::VoteDefinition,
            0x02 => ItemType::Initiative,
            0x03 => ItemType::Support,
            0x04 => ItemType::Ballot,
            0x05 => ItemType::Anchor,
            0x06 => ItemType::KeyParty,
            0x07 => ItemType::NodeRegistration,
            0x08 => ItemType::Witness,
            0x09 => ItemType::Share,
            other => return Err(DecodeError::ItemType(other)),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Secrecy {
    None = 0x00,
    KeyParties = 0x01,
}

impl Secrecy {
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u8()? {
            0x00 => Ok(Secrecy::None),
            0x01 => Ok(Secrecy::KeyParties),
            d => Err(DecodeError::Discriminant(d)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Authority {
        authority_key: [u8; 32],
        signature: [u8; 64],
    },
    Initiative {
        initiative_id: Id,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteDefinition {
    pub question: String,
    pub options: Vec<String>,
    pub registry_root: Fr,
    pub open_block: u32,
    pub close_block: u32,
    pub min_ballots: u32,
    pub secrecy: Secrecy,
    pub origin: Origin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Initiative {
    pub text: String,
    pub registry_root: Fr,
    pub threshold_n: u32,
    pub support_deadline_block: u32,
    pub secrecy: Secrecy,
    pub author: Fr,
    pub proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Support {
    pub initiative_id: Id,
    pub nullifier: Fr,
    pub proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ballot {
    pub vote_id: Id,
    pub nullifier: Fr,
    /// `secrecy = none`: one byte, the option index.
    /// `secrecy = keyparties`: `enc(party_ids) || c1 || c2` (SPEC §6.4).
    pub payload: Vec<u8>,
    pub proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorProof {
    Ots {
        height: u32,
        ots: Vec<u8>,
    },
    Direct {
        height: u32,
        raw_tx: Vec<u8>,
        partial_merkle_tree: Vec<u8>,
    },
    /// Dev mode only; rejected by release validation.
    Dev {
        height: u32,
    },
}

impl AnchorProof {
    pub fn height(&self) -> u32 {
        match self {
            AnchorProof::Ots { height, .. }
            | AnchorProof::Direct { height, .. }
            | AnchorProof::Dev { height } => *height,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// Content ids, strictly ascending, unique.
    pub leaves: Vec<Id>,
    pub proof: AnchorProof,
}

pub type BigInt256 = Box<[u8; 256]>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Puzzle {
    pub u: BigInt256,
    pub ct: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub share: [u8; 32],
    pub r: BigInt256,
}

/// Key-party registration with a verifiable timed commitment (SPEC §6.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyParty {
    pub vote_id: Id,
    pub pk: [u8; 32],
    pub modulus: BigInt256,
    pub g: BigInt256,
    pub h: BigInt256,
    pub poe: BigInt256,
    pub delay_t: u64,
    pub share_commitments: Vec<[u8; 32]>,
    pub puzzles: Vec<Puzzle>,
    pub openings: Vec<Opening>,
    pub registry_root: Fr,
    pub nullifier: Fr,
    pub proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRegistration {
    pub node_key: [u8; 32],
    pub mix_key: [u8; 32],
    pub endpoint: String,
    pub operator: String,
    pub country: [u8; 2],
    pub asn: u32,
    pub registry_root: Fr,
    pub nullifier: Fr,
    pub proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub content_id: Id,
    pub vote_id: Id,
    pub node_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub vote_id: Id,
    pub keyparty_id: Id,
    pub sk: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    VoteDefinition(VoteDefinition),
    Initiative(Initiative),
    Support(Support),
    Ballot(Ballot),
    Anchor(Anchor),
    KeyParty(KeyParty),
    NodeRegistration(NodeRegistration),
    Witness(Witness),
    Share(Share),
}

// ---------------------------------------------------------------------------
// Encoding. Each `encode_*` writes the body and returns the position at which
// the trailing proof/signature starts (= content length), or the total length
// when there is none.

fn encode_vote(v: &VoteDefinition, w: &mut Writer) -> usize {
    w.string(&v.question);
    w.list_len(v.options.len());
    for o in &v.options {
        w.string(o);
    }
    w.fr(&v.registry_root);
    w.u32(v.open_block);
    w.u32(v.close_block);
    w.u32(v.min_ballots);
    w.u8(v.secrecy as u8);
    match &v.origin {
        Origin::Authority {
            authority_key,
            signature,
        } => {
            w.u8(0x00);
            w.fixed(authority_key);
            let content_len = w.len();
            w.fixed(signature);
            content_len
        }
        Origin::Initiative { initiative_id } => {
            w.u8(0x01);
            w.fixed(initiative_id);
            w.len()
        }
    }
}

fn decode_vote(r: &mut Reader) -> Result<VoteDefinition, DecodeError> {
    let question = r.string(MAX_STRING_BYTES)?;
    let n = r.list_len(MAX_OPTIONS)?;
    let mut options = Vec::with_capacity(n);
    for _ in 0..n {
        options.push(r.string(MAX_STRING_BYTES)?);
    }
    let registry_root = r.fr()?;
    let open_block = r.u32()?;
    let close_block = r.u32()?;
    let min_ballots = r.u32()?;
    let secrecy = Secrecy::decode(r)?;
    let origin = match r.u8()? {
        0x00 => Origin::Authority {
            authority_key: r.fixed()?,
            signature: r.fixed()?,
        },
        0x01 => Origin::Initiative {
            initiative_id: r.fixed()?,
        },
        d => return Err(DecodeError::Discriminant(d)),
    };
    Ok(VoteDefinition {
        question,
        options,
        registry_root,
        open_block,
        close_block,
        min_ballots,
        secrecy,
        origin,
    })
}

fn encode_initiative(v: &Initiative, w: &mut Writer) -> usize {
    w.string(&v.text);
    w.fr(&v.registry_root);
    w.u32(v.threshold_n);
    w.u32(v.support_deadline_block);
    w.u8(v.secrecy as u8);
    w.fr(&v.author);
    let c = w.len();
    w.fixed(&v.proof.0);
    c
}

fn decode_initiative(r: &mut Reader) -> Result<Initiative, DecodeError> {
    Ok(Initiative {
        text: r.string(MAX_STRING_BYTES)?,
        registry_root: r.fr()?,
        threshold_n: r.u32()?,
        support_deadline_block: r.u32()?,
        secrecy: Secrecy::decode(r)?,
        author: r.fr()?,
        proof: Proof(r.fixed()?),
    })
}

fn encode_support(v: &Support, w: &mut Writer) -> usize {
    w.fixed(&v.initiative_id);
    w.fr(&v.nullifier);
    let c = w.len();
    w.fixed(&v.proof.0);
    c
}

fn decode_support(r: &mut Reader) -> Result<Support, DecodeError> {
    Ok(Support {
        initiative_id: r.fixed()?,
        nullifier: r.fr()?,
        proof: Proof(r.fixed()?),
    })
}

fn encode_ballot(v: &Ballot, w: &mut Writer) -> usize {
    w.fixed(&v.vote_id);
    w.fr(&v.nullifier);
    w.bytes(&v.payload);
    let c = w.len();
    w.fixed(&v.proof.0);
    c
}

/// Largest possible keyparties payload: 4 + 32·MAX_KEY_PARTIES + 64.
pub const MAX_BALLOT_PAYLOAD: usize = 4 + 32 * MAX_KEY_PARTIES + 64;

fn decode_ballot(r: &mut Reader) -> Result<Ballot, DecodeError> {
    Ok(Ballot {
        vote_id: r.fixed()?,
        nullifier: r.fr()?,
        payload: r.bytes(MAX_BALLOT_PAYLOAD)?,
        proof: Proof(r.fixed()?),
    })
}

fn encode_anchor(v: &Anchor, w: &mut Writer) -> usize {
    w.list_len(v.leaves.len());
    for l in &v.leaves {
        w.fixed(l);
    }
    match &v.proof {
        AnchorProof::Ots { height, ots } => {
            w.u8(0x00);
            w.u32(*height);
            w.bytes(ots);
        }
        AnchorProof::Direct {
            height,
            raw_tx,
            partial_merkle_tree,
        } => {
            w.u8(0x01);
            w.u32(*height);
            w.bytes(raw_tx);
            w.bytes(partial_merkle_tree);
        }
        AnchorProof::Dev { height } => {
            w.u8(0xFF);
            w.u32(*height);
        }
    }
    w.len()
}

fn decode_anchor(r: &mut Reader) -> Result<Anchor, DecodeError> {
    let n = r.list_len(MAX_ANCHOR_LEAVES)?;
    let mut leaves: Vec<Id> = Vec::with_capacity(n);
    for i in 0..n {
        let id: Id = r.fixed()?;
        if i > 0 && leaves[i - 1] >= id {
            return Err(DecodeError::Unsorted);
        }
        leaves.push(id);
    }
    let proof = match r.u8()? {
        0x00 => AnchorProof::Ots {
            height: r.u32()?,
            ots: r.bytes(MAX_BYTES_FIELD)?,
        },
        0x01 => AnchorProof::Direct {
            height: r.u32()?,
            raw_tx: r.bytes(MAX_BYTES_FIELD)?,
            partial_merkle_tree: r.bytes(MAX_BYTES_FIELD)?,
        },
        0xFF => AnchorProof::Dev { height: r.u32()? },
        d => return Err(DecodeError::Discriminant(d)),
    };
    Ok(Anchor { leaves, proof })
}

fn encode_keyparty(v: &KeyParty, w: &mut Writer) -> usize {
    w.fixed(&v.vote_id);
    w.fixed(&v.pk);
    w.fixed(&v.modulus[..]);
    w.fixed(&v.g[..]);
    w.fixed(&v.h[..]);
    w.fixed(&v.poe[..]);
    w.u64(v.delay_t);
    w.list_len(v.share_commitments.len());
    for c in &v.share_commitments {
        w.fixed(c);
    }
    w.list_len(v.puzzles.len());
    for p in &v.puzzles {
        w.fixed(&p.u[..]);
        w.fixed(&p.ct);
    }
    w.list_len(v.openings.len());
    for o in &v.openings {
        w.fixed(&o.share);
        w.fixed(&o.r[..]);
    }
    w.fr(&v.registry_root);
    w.fr(&v.nullifier);
    let c = w.len();
    w.fixed(&v.proof.0);
    c
}

fn exact_count(got: usize, expected: usize) -> Result<(), DecodeError> {
    if got == expected {
        Ok(())
    } else {
        Err(DecodeError::Count { expected, got })
    }
}

fn decode_keyparty(r: &mut Reader) -> Result<KeyParty, DecodeError> {
    let vote_id = r.fixed()?;
    let pk = r.fixed()?;
    let modulus = r.fixed_boxed()?;
    let g = r.fixed_boxed()?;
    let h = r.fixed_boxed()?;
    let poe = r.fixed_boxed()?;
    let delay_t = r.u64()?;
    let n = r.list_len(VTC_N)?;
    exact_count(n, VTC_N)?;
    let mut share_commitments = Vec::with_capacity(n);
    for _ in 0..n {
        share_commitments.push(r.fixed()?);
    }
    let n = r.list_len(VTC_N)?;
    exact_count(n, VTC_N)?;
    let mut puzzles = Vec::with_capacity(n);
    for _ in 0..n {
        puzzles.push(Puzzle {
            u: r.fixed_boxed()?,
            ct: r.fixed()?,
        });
    }
    let n = r.list_len(VTC_OPEN)?;
    exact_count(n, VTC_OPEN)?;
    let mut openings = Vec::with_capacity(n);
    for _ in 0..n {
        openings.push(Opening {
            share: r.fixed()?,
            r: r.fixed_boxed()?,
        });
    }
    Ok(KeyParty {
        vote_id,
        pk,
        modulus,
        g,
        h,
        poe,
        delay_t,
        share_commitments,
        puzzles,
        openings,
        registry_root: r.fr()?,
        nullifier: r.fr()?,
        proof: Proof(r.fixed()?),
    })
}

fn encode_node(v: &NodeRegistration, w: &mut Writer) -> usize {
    w.fixed(&v.node_key);
    w.fixed(&v.mix_key);
    w.string(&v.endpoint);
    w.string(&v.operator);
    w.fixed(&v.country);
    w.u32(v.asn);
    w.fr(&v.registry_root);
    w.fr(&v.nullifier);
    let c = w.len();
    w.fixed(&v.proof.0);
    c
}

fn decode_node(r: &mut Reader) -> Result<NodeRegistration, DecodeError> {
    Ok(NodeRegistration {
        node_key: r.fixed()?,
        mix_key: r.fixed()?,
        endpoint: r.string(MAX_ENDPOINT_BYTES)?,
        operator: r.string(MAX_STRING_BYTES)?,
        country: r.fixed()?,
        asn: r.u32()?,
        registry_root: r.fr()?,
        nullifier: r.fr()?,
        proof: Proof(r.fixed()?),
    })
}

fn encode_witness(v: &Witness, w: &mut Writer) -> usize {
    w.fixed(&v.content_id);
    w.fixed(&v.vote_id);
    w.fixed(&v.node_key);
    let c = w.len();
    w.fixed(&v.signature);
    c
}

fn decode_witness(r: &mut Reader) -> Result<Witness, DecodeError> {
    Ok(Witness {
        content_id: r.fixed()?,
        vote_id: r.fixed()?,
        node_key: r.fixed()?,
        signature: r.fixed()?,
    })
}

fn encode_share(v: &Share, w: &mut Writer) -> usize {
    w.fixed(&v.vote_id);
    w.fixed(&v.keyparty_id);
    w.fixed(&v.sk);
    w.len()
}

fn decode_share(r: &mut Reader) -> Result<Share, DecodeError> {
    Ok(Share {
        vote_id: r.fixed()?,
        keyparty_id: r.fixed()?,
        sk: r.fixed()?,
    })
}

impl Item {
    pub fn item_type(&self) -> ItemType {
        match self {
            Item::VoteDefinition(_) => ItemType::VoteDefinition,
            Item::Initiative(_) => ItemType::Initiative,
            Item::Support(_) => ItemType::Support,
            Item::Ballot(_) => ItemType::Ballot,
            Item::Anchor(_) => ItemType::Anchor,
            Item::KeyParty(_) => ItemType::KeyParty,
            Item::NodeRegistration(_) => ItemType::NodeRegistration,
            Item::Witness(_) => ItemType::Witness,
            Item::Share(_) => ItemType::Share,
        }
    }

    /// Canonical bytes plus the length of the content prefix (SPEC §2).
    pub fn encode_with_content_len(&self) -> (Vec<u8>, usize) {
        let mut w = Writer::new();
        w.u8(PROTOCOL_VERSION);
        w.u8(self.item_type() as u8);
        let content_len = match self {
            Item::VoteDefinition(v) => encode_vote(v, &mut w),
            Item::Initiative(v) => encode_initiative(v, &mut w),
            Item::Support(v) => encode_support(v, &mut w),
            Item::Ballot(v) => encode_ballot(v, &mut w),
            Item::Anchor(v) => encode_anchor(v, &mut w),
            Item::KeyParty(v) => encode_keyparty(v, &mut w),
            Item::NodeRegistration(v) => encode_node(v, &mut w),
            Item::Witness(v) => encode_witness(v, &mut w),
            Item::Share(v) => encode_share(v, &mut w),
        };
        (w.into_inner(), content_len)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_with_content_len().0
    }

    /// `content_id`: hash of the bytes without the trailing proof/signature.
    pub fn content_id(&self) -> Id {
        let (bytes, n) = self.encode_with_content_len();
        blake3_hash(&bytes[..n])
    }

    /// `item_hash`: hash of the exact bytes.
    pub fn item_hash(&self) -> Id {
        blake3_hash(&self.encode())
    }

    pub fn decode(bytes: &[u8]) -> Result<Item, DecodeError> {
        if bytes.len() > MAX_ITEM_BYTES {
            return Err(DecodeError::TooLong(bytes.len(), MAX_ITEM_BYTES));
        }
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != PROTOCOL_VERSION {
            return Err(DecodeError::Version(version));
        }
        let item = match ItemType::from_u8(r.u8()?)? {
            ItemType::VoteDefinition => Item::VoteDefinition(decode_vote(&mut r)?),
            ItemType::Initiative => Item::Initiative(decode_initiative(&mut r)?),
            ItemType::Support => Item::Support(decode_support(&mut r)?),
            ItemType::Ballot => Item::Ballot(decode_ballot(&mut r)?),
            ItemType::Anchor => Item::Anchor(decode_anchor(&mut r)?),
            ItemType::KeyParty => Item::KeyParty(decode_keyparty(&mut r)?),
            ItemType::NodeRegistration => Item::NodeRegistration(decode_node(&mut r)?),
            ItemType::Witness => Item::Witness(decode_witness(&mut r)?),
            ItemType::Share => Item::Share(decode_share(&mut r)?),
        };
        r.finish()?;
        Ok(item)
    }
}

impl VoteDefinition {
    /// `vote_id` = content id (excludes the authority signature).
    pub fn vote_id(&self) -> Id {
        Item::VoteDefinition(self.clone()).content_id()
    }
}

macro_rules! content_id_for {
    ($t:ty, $variant:ident) => {
        impl $t {
            pub fn content_id(&self) -> Id {
                Item::$variant(self.clone()).content_id()
            }
        }
    };
}
content_id_for!(Initiative, Initiative);
content_id_for!(Support, Support);
content_id_for!(Ballot, Ballot);
content_id_for!(Anchor, Anchor);
content_id_for!(KeyParty, KeyParty);
content_id_for!(NodeRegistration, NodeRegistration);
content_id_for!(Witness, Witness);
content_id_for!(Share, Share);

/// Parsed `keyparties` ballot payload (SPEC §6.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPartiesPayload {
    pub party_ids: Vec<Id>,
    pub c1: [u8; 32],
    pub c2: [u8; 32],
}

impl KeyPartiesPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.list_len(self.party_ids.len());
        for p in &self.party_ids {
            w.fixed(p);
        }
        w.fixed(&self.c1);
        w.fixed(&self.c2);
        w.into_inner()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(payload);
        let n = r.list_len(MAX_KEY_PARTIES)?;
        let mut party_ids: Vec<Id> = Vec::with_capacity(n);
        for i in 0..n {
            let id: Id = r.fixed()?;
            if i > 0 && party_ids[i - 1] >= id {
                return Err(DecodeError::Unsorted);
            }
            party_ids.push(id);
        }
        let c1 = r.fixed()?;
        let c2 = r.fixed()?;
        r.finish()?;
        Ok(Self { party_ids, c1, c2 })
    }
}
