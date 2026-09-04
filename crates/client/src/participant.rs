//! Participant actions over the node API: enroll, cast, confirm, support,
//! author initiatives. Retry-until-anchored and the mix path are Phase 7;
//! this is the direct path.

use crate::device::Device;
use crate::evidence::{AnchorEvidence, anchor_evidence};
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
    #[error("device is not enrolled in issuer {0}'s registry root {1}")]
    NotEnrolled(String, String),
    #[error("unknown vote")]
    UnknownVote,
    #[error("unknown initiative")]
    UnknownInitiative,
    #[error("registry not available on the node")]
    NoRegistry,
    #[error("the leaves the node served do not build the signed root")]
    ForgedLeaves,
    #[error("the node listed a key party it cannot back with a matching item")]
    ForgedKeyParty,
    #[error(
        "this vote requires {required} key parties and only {available} are selectable; \
         a ballot below the floor would be invalid, so it cannot be cast yet"
    )]
    TooFewKeyParties { required: u32, available: usize },
    #[error("cannot prove membership: {0}")]
    Prove(#[from] cv_core::crypto::groth16::Unsatisfiable),
    #[error("node rejected the item: {0}")]
    Rejected(String),
    #[error("issuer error: {0}")]
    Issuer(String),
    #[error("could not send through the mix: {0}")]
    Mix(String),
}

/// Build a [`Participant`] from this device's Merkle path under a signed root.
///
/// The node serves one path, not the electorate: at national scale the leaves
/// file is hundreds of megabytes and every cast would pay for it (A58). The
/// path is checked against the root the caller already trusts, so a node that
/// lies about the index or any sibling is caught exactly as a forged leaves
/// file was — the recomputed root does not match.
pub async fn participant_via_path(
    node: &NodeClient,
    device: &Device,
    issuer_key: &[u8; 32],
    root: &Fr,
) -> Result<Participant, ParticipantError> {
    let commitment = device.commitment();
    let (index, siblings) = node
        .registry_path(issuer_key, root, &commitment)
        .await?
        .ok_or_else(|| {
            ParticipantError::NotEnrolled(
                hex::encode(issuer_key),
                hex::encode(cv_core::crypto::field::fr_to_bytes(root)),
            )
        })?;
    if cv_core::registry::root_from_path(commitment, index, &siblings) != *root {
        return Err(ParticipantError::ForgedLeaves);
    }
    Ok(Participant {
        secret: device.secret,
        issuer_key: *issuer_key,
        registry_root: *root,
        index,
        siblings,
    })
}

pub struct ParticipantClient {
    pub node: NodeClient,
    pub keys: Arc<MembershipKeys>,
    /// Dev mode relaxes the key-party delay requirement (SPEC §10.4) and
    /// accepts dev anchors as confirmation. Never set it outside dev.
    pub dev: bool,
    /// Block headers for checking that an anchor is really in Bitcoin. With
    /// none, a confirmation only proves the ballot is in the anchor's root.
    pub headers: Option<Arc<dyn cv_core::snapshot::Headers>>,
}

impl ParticipantClient {
    pub fn new(node: NodeClient, keys: Arc<MembershipKeys>) -> Self {
        ParticipantClient {
            node,
            keys,
            dev: false,
            headers: None,
        }
    }

    /// Enroll with an Issuer over HTTP. `credential` is whatever that
    /// Issuer's verification backend expects (any non-empty string under the
    /// mock backend in dev).
    pub async fn enroll(
        &self,
        device: &mut Device,
        issuer_url: &str,
        credential: &str,
    ) -> Result<EnrollResponse, ParticipantError> {
        let req = EnrollRequest {
            commitment: hex::encode(cv_core::crypto::field::fr_to_bytes(&device.commitment())),
            credential: credential.to_string(),
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
        device.record_enrollment(issuer_url, &r.issuer_key, r.index);
        Ok(r)
    }

    /// Proving material for one Issuer's `root`, fetched from the node.
    pub async fn participant(
        &self,
        device: &Device,
        issuer_key: &[u8; 32],
        root: &Fr,
    ) -> Result<Participant, ParticipantError> {
        participant_via_path(&self.node, device, issuer_key, root).await
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
        let p = self
            .participant(device, &vd.issuer_key, &vd.registry_root)
            .await?;
        let ballot = prepare_ballot(&self.node, &self.keys, &p, &vd, option, self.dev).await?;
        let resp = Self::check(self.node.submit_item(&Item::Ballot(ballot.clone())).await?)?;
        Ok((ballot, resp))
    }

    /// Poll until the ballot is anchored (whitepaper §12 "client
    /// responsibility"), and **check the anchor** rather than believe the
    /// node's answer: a node that dropped the ballot would otherwise just say
    /// "anchored" and the voter would stop resending. Returns the evidence.
    pub async fn confirm_evidence(
        &self,
        ballot: &Ballot,
        timeout: Duration,
    ) -> Result<Option<AnchorEvidence>, ParticipantError> {
        let content_id = ballot.content_id();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(e) =
                anchor_evidence(&self.node, &content_id, self.headers.as_deref(), self.dev).await?
            {
                return Ok(Some(e));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// The height of a checked anchor covering the voter's own ballot, or
    /// `None` if nothing checkable turned up in time.
    pub async fn confirm(
        &self,
        vote_id: &Id,
        nullifier: &Fr,
        timeout: Duration,
    ) -> Result<Option<u32>, ParticipantError> {
        // The voter's own ballot is identified by content id; ask the node
        // which ones carry this nullifier, then check each candidate. A node
        // can invent candidates, but not evidence for them.
        let deadline = Instant::now() + timeout;
        loop {
            for s in self.node.ballot_status(vote_id, nullifier).await? {
                let Ok(cid) = hex::decode(&s.content_id) else {
                    continue;
                };
                let Ok(cid): Result<Id, _> = cid.try_into() else {
                    continue;
                };
                if let Some(e) =
                    anchor_evidence(&self.node, &cid, self.headers.as_deref(), self.dev).await?
                {
                    return Ok(Some(e.height));
                }
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
        let p = self
            .participant(device, &init.issuer_key, &init.registry_root)
            .await?;
        let s = build_support(&self.keys, &p, initiative_id)?;
        let resp = Self::check(self.node.submit_item(&Item::Support(s.clone())).await?)?;
        Ok((s, resp))
    }

    /// Publish a NodeRegistration for a node this person operates (SPEC §6.7).
    /// It proves membership of `issuer_key`'s registry in zero knowledge — the
    /// Issuer is not asked and never learns of it — and it is what lets other
    /// people's clients pick this node as a mix hop.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_node(
        &self,
        device: &Device,
        issuer_key: &[u8; 32],
        root: &Fr,
        node_key: [u8; 32],
        mix_key: [u8; 32],
        endpoint: String,
        operator: String,
        country: [u8; 2],
        asn: u32,
    ) -> Result<(NodeRegistration, SubmitResponse), ParticipantError> {
        let p = self.participant(device, issuer_key, root).await?;
        let reg = build_node_registration(
            &self.keys, &p, node_key, mix_key, endpoint, operator, country, asn,
        )?;
        let resp = Self::check(
            self.node
                .submit_item(&Item::NodeRegistration(reg.clone()))
                .await?,
        )?;
        Ok((reg, resp))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_initiative(
        &self,
        device: &Device,
        issuer_key: &[u8; 32],
        root: &Fr,
        text: String,
        support_deadline_block: u32,
        secrecy: Secrecy,
        min_parties: u32,
    ) -> Result<(Initiative, SubmitResponse), ParticipantError> {
        // `leaf_count` is in the snapshot; the leaves file is not needed to
        // compute a threshold over it (A58).
        let snapshot = self
            .node
            .registry_snapshot(issuer_key, root)
            .await?
            .ok_or(ParticipantError::NoRegistry)?;
        let p = self.participant(device, issuer_key, root).await?;
        let n = initiative_threshold(snapshot.leaf_count);
        let i = build_initiative(
            &self.keys,
            &p,
            text,
            n,
            support_deadline_block,
            secrecy,
            min_parties,
        )?;
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

/// Key parties a client encrypts to (SPEC §11.1): listed by the node after
/// the duplicate rule, anchored before `open_block`, with a sufficient delay
/// (relaxed in dev mode), at most `MAX_KEY_PARTIES`.
///
/// The listing is only a hint: every `pk` a ballot is encrypted to is taken
/// from the KeyParty item itself (fetched by content id, so the node cannot
/// substitute one), never from the summary. A node that swaps in a key of its
/// own would otherwise make the ballot undecryptable and uncounted.
pub async fn select_parties(
    node: &NodeClient,
    vd: &VoteDefinition,
    dev: bool,
) -> Result<Vec<(Id, [u8; 32])>, ParticipantError> {
    let vote_id = vd.vote_id();
    let mut out: Vec<(Id, [u8; 32])> = Vec::new();
    for k in node.keyparties(&vote_id).await? {
        let Some(h) = k.anchored_height else { continue };
        if h >= vd.open_block {
            continue;
        }
        if !dev && k.delay_t < cv_core::constants::required_delay(vd.close_block.saturating_sub(h))
        {
            continue;
        }
        let Ok(id) = hex::decode(&k.keyparty_id) else {
            continue;
        };
        let Ok(id): Result<Id, _> = id.try_into() else {
            continue;
        };
        let Some(Item::KeyParty(kp)) = node.item(&id).await? else {
            return Err(ParticipantError::ForgedKeyParty);
        };
        if kp.vote_id != vote_id {
            return Err(ParticipantError::ForgedKeyParty);
        }
        out.push((id, kp.pk));
    }
    out.sort();
    out.truncate(cv_core::constants::MAX_KEY_PARTIES);
    Ok(out)
}

/// Build the ballot for either secrecy mode.
pub async fn prepare_ballot(
    node: &NodeClient,
    keys: &MembershipKeys,
    p: &Participant,
    vd: &VoteDefinition,
    option: u8,
    dev: bool,
) -> Result<Ballot, ParticipantError> {
    Ok(match vd.secrecy {
        Secrecy::None => plaintext_ballot(keys, p, vd, option)?,
        Secrecy::KeyParties => {
            let parties = select_parties(node, vd, dev).await?;
            // The Issuer's floor is a validity rule (SPEC §6.4), so casting
            // below it produces an item the network will reject. Falling back
            // to a smaller set would be worse than failing: at zero parties
            // the ciphertext is the option index in the clear (A52).
            if (parties.len() as u32) < vd.min_parties {
                return Err(ParticipantError::TooFewKeyParties {
                    required: vd.min_parties,
                    available: parties.len(),
                });
            }
            keyparties_ballot(keys, p, vd, &parties, option)?
        }
    })
}

impl ParticipantClient {
    /// Register as a key party for a vote (SPEC §6.6); the secret share is
    /// kept on the device until `publish_share`.
    /// Sent through `mix`, which routes by size: a registration is ~32 KB and
    /// does not fit a Sphinx payload (`MAX_MESSAGE_LEN`), so it goes direct —
    /// over Tor when the transport has it. The returned `PrivacyLevel` says
    /// which protection was actually achieved; it reports `NO Tor` rather than
    /// failing, so a caller who needs anonymity must check it.
    ///
    /// The item itself is already anonymous — a ZK membership proof and a
    /// nullifier scoped by tag and `vote_id`, unlinkable to the same person's
    /// ballot and across votes (A50). What leaks without this is the network
    /// layer: the address that submitted it (A56).
    pub async fn register_keyparty(
        &self,
        mix: &crate::mix::MixClient,
        device: &mut Device,
        vote_id: &Id,
        delay_t: u64,
    ) -> Result<(KeyParty, crate::mix::PrivacyLevel), ParticipantError> {
        let vd = self
            .node
            .vote(vote_id)
            .await?
            .ok_or(ParticipantError::UnknownVote)?;
        let p = self
            .participant(device, &vd.issuer_key, &vd.registry_root)
            .await?;
        let (kp, sk) = build_keyparty(&self.keys, &p, vote_id, delay_t, &mut rand::rngs::OsRng)?;
        // Keep the secret before announcing: a registration on the Log whose
        // share this device cannot produce would stall the vote until a solver
        // forces it open (A54).
        device
            .keyparty_secrets
            .insert(hex::encode(vote_id), hex::encode(sk));
        let (privacy, _) = mix
            .send_item(device, Item::KeyParty(kp.clone()).encode(), &[])
            .await
            .map_err(|e| ParticipantError::Mix(e.to_string()))?;
        Ok((kp, privacy))
    }

    /// Publish this device's share for a vote (after close, SPEC §10.5).
    /// A `Share` is 97 bytes, so unlike the registration it fits a Sphinx
    /// payload and goes through the mix, hidden among ballot traffic. It is
    /// the second observable act by one key party, so sending it the same way
    /// as the first would give an observer two chances at the same address
    /// (A56).
    pub async fn publish_share(
        &self,
        mix: &crate::mix::MixClient,
        device: &mut Device,
        vote_id: &Id,
        keyparty_id: &Id,
    ) -> Result<crate::mix::PrivacyLevel, ParticipantError> {
        let sk_hex = device.keyparty_secrets.get(&hex::encode(vote_id)).ok_or(
            ParticipantError::Rejected("no key-party secret for this vote".into()),
        )?;
        let sk: [u8; 32] = hex::decode(sk_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(ParticipantError::Rejected("bad stored secret".into()))?;
        let bytes = Item::Share(Share {
            vote_id: *vote_id,
            keyparty_id: *keyparty_id,
            sk,
        })
        .encode();
        let (privacy, _) = mix
            .send_item(device, bytes, &[])
            .await
            .map_err(|e| ParticipantError::Mix(e.to_string()))?;
        Ok(privacy)
    }
}
