//! Round-trip tests for every item type, SPEC §17 vectors, and rejection of
//! non-canonical encodings.

use cv_core::constants::*;
use cv_core::crypto::field::Fr;
use cv_core::crypto::hash::{blake3_hash, tagged};
use cv_core::crypto::sig::{Domain, SigningKey, verify};
use cv_core::*;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fr_u64(x: u64) -> Fr {
    Fr::from(x)
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([1u8; 32])
}

fn rand32(r: &mut impl RngCore) -> [u8; 32] {
    let mut b = [0u8; 32];
    r.fill_bytes(&mut b);
    b
}

fn rand_fr(r: &mut impl RngCore) -> Fr {
    cv_core::crypto::field::fr_mod(&rand32(r))
}

fn rand_proof(r: &mut impl RngCore) -> Proof {
    let mut b = [0u8; 128];
    r.fill_bytes(&mut b);
    Proof(b)
}

fn rand_big(r: &mut impl RngCore) -> BigInt256 {
    let mut b = Box::new([0u8; 256]);
    r.fill_bytes(&mut b[..]);
    b
}

fn sample_vote(r: &mut impl RngCore) -> VoteDefinition {
    VoteDefinition {
        question: "Should the bridge be built?".into(),
        options: vec!["Yes".into(), "No".into()],
        registry_root: fr_u64(7),
        open_block: 900_000,
        close_block: 901_008,
        min_ballots: 100,
        secrecy: Secrecy::None,
        origin: Origin::Authority {
            authority_key: rand32(r),
            signature: [0u8; 64],
        },
    }
}

fn all_items() -> Vec<Item> {
    let mut r = rng();
    let mut leaves: Vec<Id> = (0..5).map(|_| rand32(&mut r)).collect();
    leaves.sort();
    let mut party_ids: Vec<Id> = (0..3).map(|_| rand32(&mut r)).collect();
    party_ids.sort();
    let kp_payload = KeyPartiesPayload {
        party_ids,
        c1: rand32(&mut r),
        c2: rand32(&mut r),
    }
    .encode();
    vec![
        Item::VoteDefinition(sample_vote(&mut r)),
        Item::VoteDefinition(VoteDefinition {
            secrecy: Secrecy::KeyParties,
            origin: Origin::Initiative {
                initiative_id: rand32(&mut r),
            },
            ..sample_vote(&mut r)
        }),
        Item::Initiative(Initiative {
            text: "Lower the voting age to 16 — unicode: žluťoučký".into(),
            registry_root: rand_fr(&mut r),
            threshold_n: 120_000,
            support_deadline_block: 905_000,
            secrecy: Secrecy::KeyParties,
            author: rand_fr(&mut r),
            proof: rand_proof(&mut r),
        }),
        Item::Support(Support {
            initiative_id: rand32(&mut r),
            nullifier: rand_fr(&mut r),
            proof: rand_proof(&mut r),
        }),
        Item::Ballot(Ballot {
            vote_id: rand32(&mut r),
            nullifier: rand_fr(&mut r),
            payload: vec![3],
            proof: rand_proof(&mut r),
        }),
        Item::Ballot(Ballot {
            vote_id: rand32(&mut r),
            nullifier: rand_fr(&mut r),
            payload: kp_payload,
            proof: rand_proof(&mut r),
        }),
        Item::Anchor(Anchor {
            leaves: leaves.clone(),
            proof: AnchorProof::Ots {
                height: 900_100,
                ots: vec![1, 2, 3],
            },
        }),
        Item::Anchor(Anchor {
            leaves: leaves.clone(),
            proof: AnchorProof::Direct {
                height: 900_101,
                raw_tx: vec![9; 200],
                partial_merkle_tree: vec![8; 90],
            },
        }),
        Item::Anchor(Anchor {
            leaves: leaves[..1].to_vec(),
            proof: AnchorProof::Dev { height: 900_102 },
        }),
        Item::KeyParty(KeyParty {
            vote_id: rand32(&mut r),
            pk: rand32(&mut r),
            modulus: rand_big(&mut r),
            g: rand_big(&mut r),
            h: rand_big(&mut r),
            poe: rand_big(&mut r),
            delay_t: 1 << 40,
            share_commitments: (0..VTC_N).map(|_| rand32(&mut r)).collect(),
            puzzles: (0..VTC_N)
                .map(|_| {
                    let mut ct = [0u8; 48];
                    r.fill_bytes(&mut ct);
                    Puzzle {
                        u: rand_big(&mut r),
                        ct,
                    }
                })
                .collect(),
            openings: (0..VTC_OPEN)
                .map(|_| Opening {
                    share: rand32(&mut r),
                    r: rand_big(&mut r),
                })
                .collect(),
            registry_root: rand_fr(&mut r),
            nullifier: rand_fr(&mut r),
            proof: rand_proof(&mut r),
        }),
        Item::NodeRegistration(NodeRegistration {
            node_key: rand32(&mut r),
            mix_key: rand32(&mut r),
            endpoint: "node.example.org:8443".into(),
            operator: "Example Operator".into(),
            country: *b"CZ",
            asn: 6830,
            registry_root: rand_fr(&mut r),
            nullifier: rand_fr(&mut r),
            proof: rand_proof(&mut r),
        }),
        Item::Witness(Witness {
            content_id: rand32(&mut r),
            vote_id: rand32(&mut r),
            node_key: rand32(&mut r),
            signature: [5u8; 64],
        }),
        Item::Share(Share {
            vote_id: rand32(&mut r),
            keyparty_id: rand32(&mut r),
            sk: rand32(&mut r),
        }),
    ]
}

#[test]
fn every_item_round_trips_and_is_deterministic() {
    for item in all_items() {
        let bytes = item.encode();
        assert_eq!(bytes[0], PROTOCOL_VERSION);
        assert_eq!(bytes[1], item.item_type() as u8);
        let decoded =
            Item::decode(&bytes).unwrap_or_else(|e| panic!("{:?}: {e}", item.item_type()));
        assert_eq!(decoded, item);
        assert_eq!(
            decoded.encode(),
            bytes,
            "re-encoding must be byte-identical"
        );
        assert_eq!(item.item_hash(), blake3_hash(&bytes));
    }
}

#[test]
fn content_id_excludes_proof_and_signature() {
    let mut r = rng();
    for item in all_items() {
        let id1 = item.content_id();
        // Mutate the trailing proof/signature: content id must not change.
        let mutated = match item.clone() {
            Item::VoteDefinition(mut v) => {
                if let Origin::Authority { signature, .. } = &mut v.origin {
                    *signature = [0xAA; 64];
                }
                Item::VoteDefinition(v)
            }
            Item::Initiative(mut v) => {
                v.proof = rand_proof(&mut r);
                Item::Initiative(v)
            }
            Item::Support(mut v) => {
                v.proof = rand_proof(&mut r);
                Item::Support(v)
            }
            Item::Ballot(mut v) => {
                v.proof = rand_proof(&mut r);
                Item::Ballot(v)
            }
            Item::KeyParty(mut v) => {
                v.proof = rand_proof(&mut r);
                Item::KeyParty(v)
            }
            Item::NodeRegistration(mut v) => {
                v.proof = rand_proof(&mut r);
                Item::NodeRegistration(v)
            }
            Item::Witness(mut v) => {
                v.signature = [0xBB; 64];
                Item::Witness(v)
            }
            other => other,
        };
        assert_eq!(mutated.content_id(), id1, "{:?}", item.item_type());
        if mutated != item {
            assert_ne!(mutated.item_hash(), item.item_hash());
        }
        // Mutating content changes the id.
        let (bytes, n) = item.encode_with_content_len();
        assert!(n <= bytes.len());
        assert_eq!(id1, blake3_hash(&bytes[..n]));
    }
}

#[test]
fn rejects_trailing_bytes_bad_version_bad_type_and_noncanonical_field() {
    let item = all_items().remove(0);
    let mut bytes = item.encode();
    bytes.push(0);
    assert_eq!(Item::decode(&bytes), Err(DecodeError::Trailing));
    let mut bytes = item.encode();
    bytes[0] = 2;
    assert_eq!(Item::decode(&bytes), Err(DecodeError::Version(2)));
    let mut bytes = item.encode();
    bytes[1] = 0x0A;
    assert_eq!(Item::decode(&bytes), Err(DecodeError::ItemType(0x0A)));
    assert_eq!(Item::decode(&bytes[..1]), Err(DecodeError::Eof));
    // Non-canonical field element: Support with nullifier bytes = 0xff * 32.
    let sup = Support {
        initiative_id: [1; 32],
        nullifier: fr_u64(1),
        proof: Proof([2; 128]),
    };
    let mut bytes = Item::Support(sup).encode();
    for b in &mut bytes[2 + 32..2 + 64] {
        *b = 0xff;
    }
    assert_eq!(Item::decode(&bytes), Err(DecodeError::NonCanonicalField));
}

#[test]
fn rejects_unsorted_anchor_leaves_and_bad_counts() {
    let a = Anchor {
        leaves: vec![[2u8; 32], [1u8; 32]],
        proof: AnchorProof::Dev { height: 1 },
    };
    assert_eq!(
        Item::decode(&Item::Anchor(a).encode()),
        Err(DecodeError::Unsorted)
    );
    let a = Anchor {
        leaves: vec![[2u8; 32], [2u8; 32]],
        proof: AnchorProof::Dev { height: 1 },
    };
    assert_eq!(
        Item::decode(&Item::Anchor(a).encode()),
        Err(DecodeError::Unsorted)
    );
    // Bad anchor proof discriminant.
    let a = Anchor {
        leaves: vec![[2u8; 32]],
        proof: AnchorProof::Dev { height: 1 },
    };
    let mut bytes = Item::Anchor(a).encode();
    let pos = bytes.len() - 5;
    bytes[pos] = 0x02;
    assert_eq!(Item::decode(&bytes), Err(DecodeError::Discriminant(0x02)));
    // KeyParty with the wrong number of openings.
    let Item::KeyParty(mut kp) = all_items()
        .into_iter()
        .find(|i| matches!(i, Item::KeyParty(_)))
        .unwrap()
    else {
        unreachable!()
    };
    kp.openings.pop();
    assert_eq!(
        Item::decode(&Item::KeyParty(kp).encode()),
        Err(DecodeError::Count {
            expected: VTC_OPEN,
            got: VTC_OPEN - 1
        })
    );
    // Invalid UTF-8 in a string.
    let v = sample_vote(&mut rng());
    let mut bytes = Item::VoteDefinition(v).encode();
    bytes[6] = 0xff; // first byte of the question
    assert_eq!(Item::decode(&bytes), Err(DecodeError::Utf8));
    // Bad secrecy byte.
    let v = sample_vote(&mut rng());
    let mut bytes = Item::VoteDefinition(v.clone()).encode();
    let (_, content_len) = Item::VoteDefinition(v).encode_with_content_len();
    // secrecy byte is 1 + 32 bytes before content end (origin tag + key)
    bytes[content_len - 34] = 0x07;
    assert_eq!(Item::decode(&bytes), Err(DecodeError::Discriminant(0x07)));
}

#[test]
fn keyparties_payload_roundtrip_and_rejections() {
    let mut r = rng();
    let mut ids: Vec<Id> = (0..4).map(|_| rand32(&mut r)).collect();
    ids.sort();
    let p = KeyPartiesPayload {
        party_ids: ids.clone(),
        c1: rand32(&mut r),
        c2: rand32(&mut r),
    };
    let bytes = p.encode();
    assert_eq!(bytes.len(), 4 + 4 * 32 + 64);
    assert_eq!(KeyPartiesPayload::decode(&bytes).unwrap(), p);
    let empty = KeyPartiesPayload {
        party_ids: vec![],
        c1: [0; 32],
        c2: [0; 32],
    };
    assert_eq!(KeyPartiesPayload::decode(&empty.encode()).unwrap(), empty);
    ids.swap(0, 1);
    let bad = KeyPartiesPayload {
        party_ids: ids,
        c1: [0; 32],
        c2: [0; 32],
    };
    assert_eq!(
        KeyPartiesPayload::decode(&bad.encode()),
        Err(DecodeError::Unsorted)
    );
    let mut too_many: Vec<Id> = (0..MAX_KEY_PARTIES as u8 + 1).map(|i| [i; 32]).collect();
    too_many.sort();
    let bad = KeyPartiesPayload {
        party_ids: too_many,
        c1: [0; 32],
        c2: [0; 32],
    };
    assert!(matches!(
        KeyPartiesPayload::decode(&bad.encode()),
        Err(DecodeError::TooLong(..))
    ));
}

// ---------------------------------------------------------------------------
// SPEC §17 vectors (generated independently of this crate).

#[test]
fn vector_17_1_tagged_hashes() {
    let s = cv_core::crypto::field::fr_to_bytes(&fr_u64(1));
    assert_eq!(
        hex(&s),
        "0100000000000000000000000000000000000000000000000000000000000000"
    );
    let vote_id = [0xabu8; 32];
    let mut sv = s.to_vec();
    sv.extend_from_slice(&vote_id);
    assert_eq!(
        hex(&tagged("rand", &sv)),
        "51b04684db6d0d3b11b4ec074b165ddc1a761f8a692b5341b571d56aa76a5049"
    );
    assert_eq!(
        hex(&tagged("proof-rand", &sv)),
        "f40b4e9cc884f373fbf42ed02a26aa0a3dfa83a62b98c1547f223e7a07fd7aed"
    );
    assert_eq!(
        hex(&blake3_hash(b"")),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    assert_eq!(
        hex(&blake3_hash(b"abc")),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );
}

fn vector_vote() -> (VoteDefinition, SigningKey) {
    let sk = SigningKey::from_seed(&[0x42u8; 32]);
    let mut v = VoteDefinition {
        question: "Should the bridge be built?".into(),
        options: vec!["Yes".into(), "No".into()],
        registry_root: fr_u64(7),
        open_block: 900_000,
        close_block: 901_008,
        min_ballots: 100,
        secrecy: Secrecy::None,
        origin: Origin::Authority {
            authority_key: sk.public_key(),
            signature: [0u8; 64],
        },
    };
    let vote_id = v.vote_id();
    let sig = sk.sign(Domain::Vote, &vote_id);
    v.origin = Origin::Authority {
        authority_key: sk.public_key(),
        signature: sig,
    };
    (v, sk)
}

#[test]
fn vector_17_2_vote_definition() {
    let (v, sk) = vector_vote();
    assert_eq!(
        hex(&sk.public_key()),
        "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
    );
    let item = Item::VoteDefinition(v.clone());
    let (bytes, content_len) = item.encode_with_content_len();
    assert_eq!(content_len, 128);
    assert_eq!(bytes.len(), 192);
    assert_eq!(
        hex(&bytes[..content_len]),
        "01011b00000053686f756c642074686520627269646765206265206275696c743f0200000003000000596573020000004e6f0700000000000000000000000000000000000000000000000000000000000000a0bb0d0090bf0d006400000000002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
    );
    let vote_id = v.vote_id();
    assert_eq!(
        hex(&vote_id),
        "1b85ac5e6f3d29dfca5f4a65c04054c7bec252db66ffaffd052e345ce1c1eb09"
    );
    let Origin::Authority {
        signature,
        authority_key,
    } = &v.origin
    else {
        unreachable!()
    };
    assert_eq!(
        hex(signature),
        "b2ec980b7597e063a7f65473ad0c9cead988dbc19c5279ae6ce2d75952cc6c662d069bb6df161d2133988b26ca4ad4203ca8c99a91685735e34e7f9dad764306"
    );
    assert!(verify(authority_key, Domain::Vote, &vote_id, signature));
    assert_eq!(
        hex(&item.item_hash()),
        "e0fdeb2c92f6d5b889ffc59dff319b7a673ce8fd42f03dba2004102dca69c038"
    );
    assert_eq!(Item::decode(&bytes).unwrap(), item);
}

#[test]
fn vector_17_3_ballot_content_id() {
    let (v, _) = vector_vote();
    let b = Ballot {
        vote_id: v.vote_id(),
        nullifier: fr_u64(5),
        payload: vec![0x01],
        proof: Proof([0u8; 128]),
    };
    let (bytes, n) = Item::Ballot(b.clone()).encode_with_content_len();
    assert_eq!(n, 71);
    assert_eq!(
        hex(&bytes[..n]),
        "01041b85ac5e6f3d29dfca5f4a65c04054c7bec252db66ffaffd052e345ce1c1eb0905000000000000000000000000000000000000000000000000000000000000000100000001"
    );
    assert_eq!(
        hex(&b.content_id()),
        "b855b6703818caf09bdc43425196236aef1cf4687fc0533ea0d3b7d34eac7aa5"
    );
}

fn vector_ids() -> Vec<Id> {
    let mut ids: Vec<Id> = ["a", "b", "c"]
        .iter()
        .map(|x| blake3_hash(x.as_bytes()))
        .collect();
    ids.sort();
    ids
}

#[test]
fn vector_17_4_anchor() {
    let ids = vector_ids();
    let a = Anchor {
        leaves: ids.clone(),
        proof: AnchorProof::Dev { height: 900_500 },
    };
    let bytes = Item::Anchor(a.clone()).encode();
    assert_eq!(bytes.len(), 107);
    assert_eq!(
        hex(&bytes),
        format!(
            "0105030000{}{}{}{}ff94bd0d00",
            "00",
            hex(&ids[0]),
            hex(&ids[1]),
            hex(&ids[2])
        )
    );
    assert_eq!(
        hex(&a.content_id()),
        "465ba7ed5a45d67b4c3ae199bc72273635fedb9c31167c5dbcdcefc7b14825dd"
    );
    assert_eq!(
        hex(&cv_core::crypto::merkle::anchor_root(&ids).unwrap()),
        "43aba690ee8b8ffc76eebc2b134cb0df5bfb4f547198a88ab31d16d52a334cf8"
    );
}

#[test]
fn vector_17_5_witness() {
    let (v, _) = vector_vote();
    let nk = SigningKey::from_seed(&[0x07u8; 32]);
    assert_eq!(
        hex(&nk.public_key()),
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    );
    let ids = vector_ids();
    let mut payload = ids[0].to_vec();
    payload.extend_from_slice(&v.vote_id());
    let w = Witness {
        content_id: ids[0],
        vote_id: v.vote_id(),
        node_key: nk.public_key(),
        signature: nk.sign(Domain::Witness, &payload),
    };
    let bytes = Item::Witness(w.clone()).encode();
    assert_eq!(bytes.len(), 162);
    assert_eq!(
        hex(&bytes),
        "010810e5cf3d3c8a4f9f3468c8cc58eea84892a22fdadbc1acb22410190044c1d5531b85ac5e6f3d29dfca5f4a65c04054c7bec252db66ffaffd052e345ce1c1eb09ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22cc718229e8a39151dd8168cca00e300b56070ab04ce1c1f028ec766a95360a49c4954025a9572fd16caf6aa2821420bc9005fa907c402ff9f4f3f9c192a5dd101"
    );
    assert_eq!(
        hex(&w.content_id()),
        "db8b09f07b50ede4d8caf6abd41afefd29c47870f469ba8707de6fdc7763bd64"
    );
}

#[test]
fn vector_17_6_receipt() {
    let n = cv_core::crypto::field::fr_to_bytes(&fr_u64(5));
    let mut nc = n.to_vec();
    nc.extend_from_slice(&[0x11u8; 17]);
    assert_eq!(
        hex(&tagged("receipt", &nc)),
        "625e131a87f09cf2935b4e702ff59a9514b2918fe8bf7e65c349f99e6fd36290"
    );
}

#[test]
fn random_items_survive_fuzzed_decoding_without_panics() {
    // Decoding arbitrary bytes must never panic.
    let mut r = rng();
    for _ in 0..2000 {
        let len = r.gen_range(0..300);
        let mut b = vec![0u8; len];
        r.fill_bytes(&mut b);
        if len > 1 {
            b[0] = 1;
            b[1] = r.gen_range(1..=9);
        }
        let _ = Item::decode(&b);
    }
}
