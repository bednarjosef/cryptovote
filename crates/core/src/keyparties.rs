//! `secrecy = keyparties` glue between the items and `cv-vtc` (SPEC §10–§11).

use crate::crypto::field::{Fr, fr_to_bytes};
use crate::crypto::hash::tagged64;
use crate::items::*;
use cv_vtc::{
    Commitment, Opening, PartyPublic, Puzzle, RistrettoPoint, Scalar, from_bigint256,
    point_from_bytes, point_to_bytes, scalar_from_bytes, scalar_wide,
};
use std::collections::BTreeMap;

pub fn party_public(kp: &KeyParty) -> PartyPublic {
    PartyPublic {
        n: from_bigint256(&kp.modulus),
        g: from_bigint256(&kp.g),
        h: from_bigint256(&kp.h),
        poe: from_bigint256(&kp.poe),
        t: kp.delay_t,
    }
}

pub fn commitment_of(kp: &KeyParty) -> Commitment {
    Commitment {
        share_commitments: kp.share_commitments.clone(),
        puzzles: kp
            .puzzles
            .iter()
            .map(|p| Puzzle {
                u: from_bigint256(&p.u),
                ct: p.ct,
            })
            .collect(),
        openings: kp
            .openings
            .iter()
            .map(|o| Opening {
                share: o.share,
                r: from_bigint256(&o.r),
            })
            .collect(),
    }
}

/// SPEC §10.3 verification of a KeyParty item's commitment.
pub fn verify_keyparty(kp: &KeyParty) -> Result<(), String> {
    let p = party_public(kp);
    p.check_structure().map_err(|e| e.to_string())?;
    let pk = point_from_bytes(&kp.pk).ok_or("pk is not a canonical point")?;
    cv_vtc::verify_commitment(&kp.vote_id, &pk, &p, &commitment_of(kp)).map_err(|e| e.to_string())
}

/// `sk · G == pk` (SPEC §6.9).
pub fn verify_share(kp: &KeyParty, sk: &[u8; 32]) -> bool {
    scalar_from_bytes(sk).is_some_and(|s| point_to_bytes(&cv_vtc::public_key(&s)) == kp.pk)
}

/// Force open a party's commitment (SPEC §10.5); `T` sequential squarings.
pub fn force_open(kp: &KeyParty) -> Option<[u8; 32]> {
    let pk = point_from_bytes(&kp.pk)?;
    cv_vtc::force_open(&kp.vote_id, &pk, &party_public(kp), &commitment_of(kp))
        .map(|s| s.to_bytes())
}

/// `r = scalar_wide(H_B64("rand"; s_bytes || vote_id))` (SPEC §11.2).
pub fn ballot_randomness(secret: &Fr, vote_id: &Id) -> Scalar {
    let mut data = fr_to_bytes(secret).to_vec();
    data.extend_from_slice(vote_id);
    scalar_wide(&tagged64("rand", &data))
}

/// Encrypt an option index to the aggregate of the given party keys.
pub fn encrypt_option(
    party_pks: &[[u8; 32]],
    option: u8,
    r: &Scalar,
) -> Option<([u8; 32], [u8; 32])> {
    let pks: Vec<RistrettoPoint> = party_pks
        .iter()
        .map(point_from_bytes)
        .collect::<Option<_>>()?;
    let (c1, c2) = cv_vtc::encrypt(&cv_vtc::aggregate(&pks), option as u64, r);
    Some((point_to_bytes(&c1), point_to_bytes(&c2)))
}

/// SPEC §11.3: decrypt one ballot payload given the shares of its declared parties.
pub fn decrypt(
    payload: &KeyPartiesPayload,
    shares: &BTreeMap<Id, [u8; 32]>,
    options: usize,
) -> Option<usize> {
    let mut sk = Scalar::ZERO;
    for id in &payload.party_ids {
        sk += scalar_from_bytes(shares.get(id)?)?;
    }
    let c1 = point_from_bytes(&payload.c1)?;
    let c2 = point_from_bytes(&payload.c2)?;
    cv_vtc::decrypt(&sk, &c1, &c2, options)
}
