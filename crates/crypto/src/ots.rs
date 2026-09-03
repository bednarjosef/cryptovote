//! OpenTimestamps proofs (SPEC §9): parsing, attestation extraction,
//! upgrading a pending proof with a calendar's completed timestamp. All
//! op execution is done by the `opentimestamps` crate; the Bitcoin check
//! itself is done by the caller against a header (`spv`).

use opentimestamps::attestation::Attestation;
use opentimestamps::op::Op;
use opentimestamps::ser::{Deserializer, Serializer};
use opentimestamps::timestamp::{Step, StepData, Timestamp};
use std::io::Cursor;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attestations {
    /// `(height, digest at the attestation)`: the digest must equal the
    /// block's merkle root (internal byte order) for the proof to be valid.
    pub bitcoin: Vec<(u32, Vec<u8>)>,
    /// Calendar URIs of attestations that are not yet in Bitcoin.
    pub pending: Vec<String>,
}

/// Parse a serialized timestamp (steps only, no detached-file header) that
/// starts from `start_digest`.
pub fn parse(start_digest: &[u8], bytes: &[u8]) -> Result<Timestamp, String> {
    let mut d = Deserializer::new(Cursor::new(bytes));
    let ts = Timestamp::deserialize(&mut d, start_digest.to_vec()).map_err(|e| e.to_string())?;
    d.check_eof().map_err(|e| e.to_string())?;
    Ok(ts)
}

pub fn serialize(ts: &Timestamp) -> Vec<u8> {
    let mut s = Serializer::new(Vec::new());
    ts.serialize(&mut s).expect("serialize timestamp");
    s.into_inner()
}

fn walk(step: &Step, out: &mut Attestations) {
    match &step.data {
        StepData::Attestation(Attestation::Bitcoin { height }) => {
            out.bitcoin.push((*height as u32, step.output.clone()))
        }
        StepData::Attestation(Attestation::Pending { uri }) => out.pending.push(uri.clone()),
        StepData::Attestation(_) => {}
        StepData::Fork | StepData::Op(_) => {}
    }
    for n in &step.next {
        walk(n, out);
    }
}

/// All attestations reachable in the proof.
pub fn attestations(ts: &Timestamp) -> Attestations {
    let mut out = Attestations::default();
    walk(&ts.first_step, &mut out);
    out
}

/// Replace the pending attestation whose input digest equals
/// `completed.start_digest` by the completed timestamp's steps (the OTS
/// "upgrade" operation). Returns `false` if no such pending step exists.
pub fn upgrade(ts: &mut Timestamp, completed: &Timestamp) -> bool {
    fn rec(step: &mut Step, completed: &Timestamp) -> bool {
        if matches!(
            step.data,
            StepData::Attestation(Attestation::Pending { .. })
        ) && step.output == completed.start_digest
        {
            *step = completed.first_step.clone();
            return true;
        }
        step.next.iter_mut().any(|n| rec(n, completed))
    }
    rec(&mut ts.first_step, completed)
}

/// Build a linear timestamp `digest -> ops... -> attestation` (tests and the
/// dev anchorer).
pub fn linear(start_digest: &[u8], ops: &[Op], attestation: Attestation) -> Timestamp {
    let mut digest = start_digest.to_vec();
    let mut steps: Vec<(Op, Vec<u8>)> = Vec::new();
    for op in ops {
        digest = op.execute(&digest);
        steps.push((op.clone(), digest.clone()));
    }
    let mut step = Step {
        data: StepData::Attestation(attestation),
        output: digest,
        next: vec![],
    };
    for (op, output) in steps.into_iter().rev() {
        step = Step {
            data: StepData::Op(op),
            output,
            next: vec![step],
        };
    }
    Timestamp {
        start_digest: start_digest.to_vec(),
        first_step: step,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_attestations() {
        let digest = [7u8; 32];
        let ts = linear(
            &digest,
            &[Op::Append(vec![1, 2]), Op::Sha256],
            Attestation::Bitcoin { height: 800_000 },
        );
        let bytes = serialize(&ts);
        let back = parse(&digest, &bytes).unwrap();
        assert_eq!(back, ts);
        let a = attestations(&back);
        assert_eq!(a.bitcoin.len(), 1);
        assert_eq!(a.bitcoin[0].0, 800_000);
        assert!(a.pending.is_empty());
        assert!(parse(&digest, &bytes[..bytes.len() - 1]).is_err());
        assert!(parse(&digest, &[bytes.clone(), vec![0]].concat()).is_err());
    }

    #[test]
    fn pending_then_upgrade() {
        let digest = [9u8; 32];
        let mut ts = linear(
            &digest,
            &[Op::Sha256],
            Attestation::Pending {
                uri: "https://a.example".into(),
            },
        );
        let a = attestations(&ts);
        assert!(a.bitcoin.is_empty());
        assert_eq!(a.pending, vec!["https://a.example".to_string()]);
        let mid = Op::Sha256.execute(&digest);
        let completed = linear(
            &mid,
            &[Op::Prepend(vec![3]), Op::Sha256],
            Attestation::Bitcoin { height: 1 },
        );
        assert!(upgrade(&mut ts, &completed));
        let a = attestations(&ts);
        assert_eq!(a.bitcoin.len(), 1);
        assert!(a.pending.is_empty());
        assert!(!upgrade(&mut ts, &completed));
    }
}
