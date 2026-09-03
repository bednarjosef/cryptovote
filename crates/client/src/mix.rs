//! Mix client (whitepaper §12): hop selection with diversity rules and a
//! persistent guard, path shortening down to one hop or direct, dual-path
//! send, retry until the nullifier is anchored, decoys, and the privacy
//! indicator. Transport is direct HTTP or Tor (Arti) with automatic fallback.

use crate::device::Device;
use crate::light::NodeClient;
use cv_core::build::{Participant, plaintext_ballot};
use cv_core::crypto::field::{Fr, fr_to_bytes};
use cv_core::crypto::groth16::MembershipKeys;
use cv_core::crypto::mix::{Hop, MAX_MESSAGE_LEN, build_packet, decoy_payload};
use cv_core::items::*;
use cv_core::wire::{BallotStatusJson, NodeSummary};
use rand::Rng;
use rand::seq::SliceRandom;
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const GUARD_ROTATION_SECS: u64 = cv_core::constants::GUARD_ROTATION_DAYS * 86_400;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopInfo {
    pub node_key: [u8; 32],
    pub mix_key: [u8; 32],
    pub endpoint: String,
    pub operator: String,
    pub country: String,
    pub asn: u32,
}

impl HopInfo {
    pub fn from_summary(s: &NodeSummary) -> Option<Self> {
        let node_key: [u8; 32] = hex::decode(&s.node_key).ok()?.try_into().ok()?;
        let mix_key: [u8; 32] = hex::decode(&s.mix_key).ok()?.try_into().ok()?;
        Some(HopInfo {
            node_key,
            mix_key,
            endpoint: s.endpoint.clone(),
            operator: s.operator.clone(),
            country: s.country.clone(),
            asn: s.asn,
        })
    }

    fn hop(&self) -> Hop {
        Hop {
            address: self.node_key,
            mix_key: self.mix_key,
        }
    }

    /// Whitepaper §12 diversity rules: distinct operators, ASNs, countries.
    // TRUST: node operators for their self-declared diversity attributes (privacy only, SPEC §6.7).
    fn diverse_from(&self, others: &[HopInfo]) -> bool {
        others
            .iter()
            .all(|o| o.operator != self.operator && o.asn != self.asn && o.country != self.country)
    }
}

/// What the client actually achieved for a send (whitepaper §12 privacy indicator).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyLevel {
    /// Hops of the shortest path used (0 = direct submission).
    pub hops: usize,
    pub tor: bool,
    pub paths: usize,
}

impl std::fmt::Display for PrivacyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tor = if self.tor { "Tor" } else { "NO Tor" };
        match self.hops {
            0 => write!(f, "DIRECT: no mix hops, {tor}"),
            3 if self.tor => write!(f, "full: 3 mix hops + Tor, {} paths", self.paths),
            n => write!(f, "partial: {n} mix hop(s), {tor}, {} path(s)", self.paths),
        }
    }
}

/// Outcome of trying to reach Tor.
pub enum TorSetup {
    Disabled,
    Failed(String),
    #[cfg(feature = "tor")]
    Ready(crate::tor::TorTransport),
}

pub enum Transport {
    Direct(reqwest::Client),
    #[cfg(feature = "tor")]
    Tor(crate::tor::TorTransport),
}

impl Transport {
    pub fn is_tor(&self) -> bool {
        !matches!(self, Transport::Direct(_))
    }

    pub async fn post(&self, url: &str, body: Vec<u8>) -> anyhow::Result<(u16, Vec<u8>)> {
        match self {
            Transport::Direct(c) => {
                let r = c.post(url).body(body).send().await?;
                Ok((r.status().as_u16(), r.bytes().await?.to_vec()))
            }
            #[cfg(feature = "tor")]
            Transport::Tor(t) => t.request("POST", url, body).await,
        }
    }

    pub async fn get(&self, url: &str) -> anyhow::Result<(u16, Vec<u8>)> {
        match self {
            Transport::Direct(c) => {
                let r = c.get(url).send().await?;
                Ok((r.status().as_u16(), r.bytes().await?.to_vec()))
            }
            #[cfg(feature = "tor")]
            Transport::Tor(t) => t.request("GET", url, Vec::new()).await,
        }
    }
}

/// Choose up to `want` hops: the guard first (if given and eligible), then
/// random hops satisfying the diversity rules; shorter if not enough exist.
pub fn select_path<R: Rng>(
    rng: &mut R,
    hops: &[HopInfo],
    guard: Option<[u8; 32]>,
    exclude: &[[u8; 32]],
    want: usize,
) -> Vec<HopInfo> {
    let mut path: Vec<HopInfo> = Vec::new();
    if let Some(g) = guard {
        if let Some(h) = hops.iter().find(|h| h.node_key == g) {
            path.push(h.clone());
        }
    }
    let mut candidates: Vec<&HopInfo> = hops
        .iter()
        .filter(|h| !exclude.contains(&h.node_key))
        .collect();
    candidates.shuffle(rng);
    for c in candidates {
        if path.len() >= want {
            break;
        }
        if path.iter().any(|p| p.node_key == c.node_key) {
            continue;
        }
        if c.diverse_from(&path) {
            path.push(c.clone());
        }
    }
    path
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct CastReport {
    pub ballot: Ballot,
    pub anchored_height: Option<u32>,
    pub privacy: PrivacyLevel,
    pub attempts: u32,
}

pub struct MixClient {
    /// Direct light client for public data (registry, vote definitions).
    pub node: NodeClient,
    pub transport: Transport,
    pub tor_error: Option<String>,
    pub hops_per_path: usize,
    pub paths: usize,
}

impl MixClient {
    /// `tor`: the result of bootstrapping Tor. Failure falls back to direct
    /// HTTP and is reported in every `PrivacyLevel` (never silently).
    pub fn new(node: NodeClient, tor: TorSetup) -> Self {
        let (transport, tor_error) = match tor {
            TorSetup::Disabled => (
                Transport::Direct(reqwest::Client::new()),
                Some("Tor disabled".into()),
            ),
            TorSetup::Failed(e) => (
                Transport::Direct(reqwest::Client::new()),
                Some(format!("Tor unreachable: {e}")),
            ),
            #[cfg(feature = "tor")]
            TorSetup::Ready(t) => (Transport::Tor(t), None),
        };
        MixClient {
            node,
            transport,
            tor_error,
            hops_per_path: cv_core::constants::MIX_HOPS,
            paths: cv_core::constants::PATHS_PER_BALLOT,
        }
    }

    pub async fn registered_hops(&self) -> anyhow::Result<Vec<HopInfo>> {
        Ok(self
            .node
            .nodes()
            .await?
            .iter()
            .filter_map(HopInfo::from_summary)
            .collect())
    }

    /// Keep the guard for months; rotate when expired or no longer registered.
    fn guard<R: Rng>(
        &self,
        device: &mut Device,
        hops: &[HopInfo],
        rng: &mut R,
    ) -> Option<[u8; 32]> {
        let current = device
            .guard
            .as_ref()
            .and_then(|g| hex::decode(g).ok())
            .and_then(|v| v.try_into().ok());
        let fresh = device
            .guard_since_unix
            .is_some_and(|t| now_unix().saturating_sub(t) < GUARD_ROTATION_SECS);
        if let Some(g) = current {
            if fresh && hops.iter().any(|h| h.node_key == g) {
                return Some(g);
            }
        }
        let g = hops.choose(rng)?.node_key;
        device.guard = Some(hex::encode(g));
        device.guard_since_unix = Some(now_unix());
        Some(g)
    }

    /// Send item bytes through up to `paths` mix paths (or directly if no
    /// hops exist / the item is too large). Returns the achieved privacy
    /// level and the hops used (to exclude on retry).
    pub async fn send_item(
        &self,
        device: &mut Device,
        bytes: Vec<u8>,
        exclude: &[[u8; 32]],
    ) -> anyhow::Result<(PrivacyLevel, Vec<[u8; 32]>)> {
        let mut rng = rand::rngs::OsRng;
        let hops = self.registered_hops().await?;
        if hops.is_empty() || bytes.len() > MAX_MESSAGE_LEN {
            let (status, _) = self
                .transport
                .post(&format!("{}/v1/items", self.node.base_url()), bytes)
                .await?;
            if !(200..300).contains(&status) {
                anyhow::bail!("direct submission returned {status}");
            }
            return Ok((
                PrivacyLevel {
                    hops: 0,
                    tor: self.transport.is_tor(),
                    paths: 1,
                },
                vec![],
            ));
        }
        let guard = self.guard(device, &hops, &mut rng);
        let mut used: Vec<[u8; 32]> = Vec::new();
        let mut min_hops = usize::MAX;
        let mut sent = 0;
        let mut excl: Vec<[u8; 32]> = exclude.to_vec();
        for _ in 0..self.paths {
            let path = select_path(&mut rng, &hops, guard, &excl, self.hops_per_path);
            if path.is_empty() {
                break;
            }
            let route: Vec<Hop> = path.iter().map(HopInfo::hop).collect();
            let packet = build_packet(&bytes, &route)?;
            let entry = &path[0];
            let (status, _) = self
                .transport
                .post(&format!("http://{}/v1/mix", entry.endpoint), packet)
                .await?;
            if !(200..300).contains(&status) {
                anyhow::bail!("entry hop returned {status}");
            }
            min_hops = min_hops.min(path.len());
            sent += 1;
            // Later paths avoid this path's non-guard hops (independent paths).
            for h in path.iter().skip(1) {
                excl.push(h.node_key);
            }
            used.extend(path.iter().map(|h| h.node_key));
        }
        if sent == 0 {
            anyhow::bail!("no path could be built");
        }
        Ok((
            PrivacyLevel {
                hops: min_hops,
                tor: self.transport.is_tor(),
                paths: sent,
            },
            used,
        ))
    }

    /// Nullifier status through the (possibly Tor) transport, so the query
    /// does not link the voter's IP to the nullifier.
    pub async fn anchored_height(
        &self,
        vote_id: &Id,
        nullifier: &Fr,
    ) -> anyhow::Result<Option<u32>> {
        let url = format!(
            "{}/v1/votes/{}/nullifier/{}",
            self.node.base_url(),
            hex::encode(vote_id),
            hex::encode(fr_to_bytes(nullifier))
        );
        let (status, body) = self.transport.get(&url).await?;
        if status != 200 {
            anyhow::bail!("status query returned {status}");
        }
        let st: Vec<BallotStatusJson> = serde_json::from_slice(&body)?;
        Ok(st.iter().filter_map(|s| s.anchored_height).min())
    }

    /// Cast and keep re-sending through fresh paths until the nullifier is
    /// seen under an anchor (whitepaper §12 client responsibility).
    pub async fn cast_with_retry(
        &self,
        device: &mut Device,
        keys: &MembershipKeys,
        vote_id: &Id,
        option: u8,
        window: Duration,
        max_attempts: u32,
    ) -> anyhow::Result<CastReport> {
        let vd = self
            .node
            .vote(vote_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("unknown vote"))?;
        let (_, leaves) = self
            .node
            .registry(&vd.registry_root)
            .await?
            .ok_or_else(|| anyhow::anyhow!("registry not available"))?;
        let p: Participant = device
            .participant(&leaves)
            .ok_or_else(|| anyhow::anyhow!("device not enrolled in this registry"))?;
        let ballot = plaintext_ballot(keys, &p, &vd, option)?;
        let bytes = Item::Ballot(ballot.clone()).encode();
        let mut exclude: Vec<[u8; 32]> = Vec::new();
        let mut last_privacy = PrivacyLevel {
            hops: 0,
            tor: self.transport.is_tor(),
            paths: 0,
        };
        for attempt in 1..=max_attempts {
            let (privacy, used) = self.send_item(device, bytes.clone(), &exclude).await?;
            last_privacy = privacy;
            let deadline = Instant::now() + window;
            loop {
                if let Some(h) = self.anchored_height(vote_id, &ballot.nullifier).await? {
                    return Ok(CastReport {
                        ballot,
                        anchored_height: Some(h),
                        privacy,
                        attempts: attempt,
                    });
                }
                if Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            exclude.extend(used);
        }
        Ok(CastReport {
            ballot,
            anchored_height: None,
            privacy: last_privacy,
            attempts: max_attempts,
        })
    }

    /// An indistinguishable decoy through one path (whitepaper §12).
    pub async fn send_decoy(&self, device: &mut Device) -> anyhow::Result<bool> {
        let mut rng = rand::rngs::OsRng;
        let hops = self.registered_hops().await?;
        if hops.is_empty() {
            return Ok(false);
        }
        let guard = self.guard(device, &hops, &mut rng);
        let path = select_path(&mut rng, &hops, guard, &[], self.hops_per_path);
        let route: Vec<Hop> = path.iter().map(HopInfo::hop).collect();
        let packet = build_packet(&decoy_payload(&mut rng, 300), &route)?;
        let (status, _) = self
            .transport
            .post(&format!("http://{}/v1/mix", path[0].endpoint), packet)
            .await?;
        Ok((200..300).contains(&status))
    }
}

/// Hops actually used by a path, for tests and diagnostics.
pub fn path_keys(path: &[HopInfo]) -> HashSet<[u8; 32]> {
    path.iter().map(|h| h.node_key).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn hop(i: u8, op: &str, cc: &str, asn: u32) -> HopInfo {
        HopInfo {
            node_key: [i; 32],
            mix_key: [i; 32],
            endpoint: format!("h{i}:1"),
            operator: op.into(),
            country: cc.into(),
            asn,
        }
    }

    #[test]
    fn diversity_guard_and_shortening() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([1u8; 32]);
        let hops = vec![
            hop(1, "a", "CZ", 1),
            hop(2, "b", "DE", 2),
            hop(3, "c", "AT", 3),
            hop(4, "a", "PL", 4),
            hop(5, "d", "CZ", 5),
        ];
        let p = select_path(&mut rng, &hops, Some([1; 32]), &[], 3);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].node_key, [1; 32], "guard is the entry");
        let ops: HashSet<&str> = p.iter().map(|h| h.operator.as_str()).collect();
        let ccs: HashSet<&str> = p.iter().map(|h| h.country.as_str()).collect();
        assert_eq!(ops.len(), 3);
        assert_eq!(ccs.len(), 3);
        // Only two mutually diverse hops exist → shortened to 2; one hop → 1.
        let two = vec![
            hop(1, "a", "CZ", 1),
            hop(2, "a", "DE", 2),
            hop(3, "b", "DE", 3),
        ];
        let p = select_path(&mut rng, &two, None, &[], 3);
        assert!(p.len() <= 2 && !p.is_empty());
        let one = vec![hop(9, "z", "ZZ", 9)];
        assert_eq!(select_path(&mut rng, &one, None, &[], 3).len(), 1);
        assert!(select_path(&mut rng, &one, None, &[[9; 32]], 3).is_empty());
        let full = PrivacyLevel {
            hops: 3,
            tor: true,
            paths: 2,
        };
        assert!(full.to_string().starts_with("full"));
        assert!(
            PrivacyLevel {
                hops: 0,
                tor: false,
                paths: 1
            }
            .to_string()
            .starts_with("DIRECT")
        );
    }
}
