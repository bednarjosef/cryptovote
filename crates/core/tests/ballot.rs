//! Phase 3 (secrecy = none): ballot construction is deterministic, validity
//! rules accept correct items and reject wrong ones.

use cv_core::build::*;
use cv_core::constants::*;
use cv_core::context::*;
use cv_core::crypto::field::{Fr, fr_mod};
use cv_core::crypto::groth16::{self, dev_keys};
use cv_core::crypto::sig::SigningKey;
use cv_core::identity::commitment;
use cv_core::items::*;
use cv_core::registry::RegistryTree;
use cv_core::validate::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

struct World {
    ctx: MemoryContext,
    tree: RegistryTree,
    secrets: Vec<Fr>,
    authority: SigningKey,
    issuer_key: [u8; 32],
    vote: VoteDefinition,
    vote_id: Id,
}

fn world() -> World {
    let secrets: Vec<Fr> = (1..=20u64).map(|i| fr_mod(&[i as u8; 32])).collect();
    let tree = RegistryTree::from_leaves(secrets.iter().map(commitment).collect());
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let issuer = SigningKey::from_seed(&[0x11u8; 32]);
    let issuer_key = issuer.public_key();
    let deployment = Deployment {
        authority_keys: vec![authority.public_key()],
        issuer_keys: vec![issuer_key],
        dev_mode: true,
    };
    let mut ctx = MemoryContext::new(deployment, dev_keys());
    ctx.add_registry(issuer_key, tree.root(), tree.leaf_count());
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Build the bridge?".into(),
            options: vec!["Yes".into(), "No".into(), "Abstain".into()],
            issuer_key,
            registry_root: tree.root(),
            open_block: 100,
            close_block: 200,
            min_ballots: 1,
            secrecy: Secrecy::None,
            origin: Origin::Initiative {
                initiative_id: [0; 32],
            },
        },
    );
    let vote_id = ctx.add_vote(vote.clone());
    World {
        ctx,
        tree,
        secrets,
        authority,
        issuer_key,
        vote,
        vote_id,
    }
}

fn participant(w: &World, i: usize) -> Participant {
    Participant {
        secret: w.secrets[i],
        issuer_key: w.issuer_key,
        registry_root: w.tree.root(),
        index: i as u32,
        siblings: w.tree.path(i as u32).unwrap(),
    }
}

#[test]
fn vote_definition_validity() {
    let w = world();
    assert_eq!(
        validate(&Item::VoteDefinition(w.vote.clone()), &w.ctx),
        Ok(())
    );
    // Unknown authority.
    let other = SigningKey::from_seed(&[0x43u8; 32]);
    let v = sign_vote_definition(&other, w.vote.clone());
    assert_eq!(validate_vote(&v, &w.ctx), Err(Invalid::UnknownAuthority));
    // Tampered question → signature fails.
    let mut v = w.vote.clone();
    v.question.push('!');
    assert_eq!(validate_vote(&v, &w.ctx), Err(Invalid::BadSignature));
    // Structure.
    let mut v = w.vote.clone();
    v.options = vec!["Yes".into()];
    assert!(matches!(
        validate_vote(&sign_vote_definition(&w.authority, v), &w.ctx),
        Err(Invalid::Structure(_))
    ));
    let mut v = w.vote.clone();
    v.options = vec!["Yes".into(), "Yes".into()];
    assert!(matches!(
        validate_vote(&sign_vote_definition(&w.authority, v), &w.ctx),
        Err(Invalid::Structure(_))
    ));
    let mut v = w.vote.clone();
    v.close_block = v.open_block;
    assert!(matches!(
        validate_vote(&sign_vote_definition(&w.authority, v), &w.ctx),
        Err(Invalid::Structure(_))
    ));
    let mut v = w.vote.clone();
    v.close_block = v.open_block + MAX_VOTE_BLOCKS + 1;
    assert!(matches!(
        validate_vote(&sign_vote_definition(&w.authority, v), &w.ctx),
        Err(Invalid::Structure(_))
    ));
    // Unknown registry root → orphan.
    let mut v = w.vote.clone();
    v.registry_root = Fr::from(99u64);
    assert!(matches!(
        validate_vote(&sign_vote_definition(&w.authority, v), &w.ctx),
        Err(Invalid::MissingReference(Reference::Registry(..)))
    ));
    // Initiative origin without a derivable vote → orphan.
    let mut v = w.vote.clone();
    v.origin = Origin::Initiative {
        initiative_id: [7; 32],
    };
    assert!(matches!(
        validate_vote(&v, &w.ctx),
        Err(Invalid::MissingReference(Reference::Initiative(_)))
    ));
}

#[test]
fn ballots_are_deterministic_and_validated() {
    let w = world();
    let p = participant(&w, 3);
    let b1 = plaintext_ballot(dev_keys(), &p, &w.vote, 1).unwrap();
    let b2 = plaintext_ballot(dev_keys(), &p, &w.vote, 1).unwrap();
    assert_eq!(
        Item::Ballot(b1.clone()).encode(),
        Item::Ballot(b2.clone()).encode(),
        "two builds are byte-identical"
    );
    assert_eq!(validate(&Item::Ballot(b1.clone()), &w.ctx), Ok(()));

    // A different option is a different content id and a "different duplicate".
    let b3 = plaintext_ballot(dev_keys(), &p, &w.vote, 2).unwrap();
    assert_eq!(b3.nullifier, b1.nullifier);
    assert_ne!(b3.content_id(), b1.content_id());
    assert_eq!(validate_ballot(&b3, &w.ctx), Ok(()));

    // Option out of range / wrong payload length are rejected (structure, no proof needed).
    let bad = Ballot {
        payload: vec![3],
        ..b1.clone()
    };
    assert!(matches!(
        validate_ballot(&bad, &w.ctx),
        Err(Invalid::Structure(_))
    ));
    let bad = Ballot {
        payload: vec![1, 0],
        ..b1.clone()
    };
    assert!(matches!(
        validate_ballot(&bad, &w.ctx),
        Err(Invalid::Structure(_))
    ));
    // Tampered payload with the original proof → the signal no longer matches.
    let bad = Ballot {
        payload: vec![0],
        ..b1.clone()
    };
    assert_eq!(validate_ballot(&bad, &w.ctx), Err(Invalid::BadProof));
    // Unknown vote → orphan.
    let bad = Ballot {
        vote_id: [9; 32],
        ..b1.clone()
    };
    assert!(matches!(
        validate_ballot(&bad, &w.ctx),
        Err(Invalid::MissingReference(Reference::Vote(_)))
    ));
    // Proof transplanted to another participant's nullifier fails.
    let q = participant(&w, 4);
    let bq = plaintext_ballot(dev_keys(), &q, &w.vote, 1).unwrap();
    let bad = Ballot {
        nullifier: bq.nullifier,
        ..b1.clone()
    };
    assert_eq!(validate_ballot(&bad, &w.ctx), Err(Invalid::BadProof));
    // A non-member cannot build a ballot at all.
    let outsider = Participant {
        secret: fr_mod(&[77u8; 32]),
        ..participant(&w, 5)
    };
    assert!(plaintext_ballot(dev_keys(), &outsider, &w.vote, 0).is_err());

    // Re-randomized proof: still valid, same content id, different item hash (A3).
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    let rr = groth16::rerandomize(&dev_keys().verifier.vk, &b1.proof.0, &mut rng).unwrap();
    let b_rr = Ballot {
        proof: Proof(rr),
        ..b1.clone()
    };
    assert_ne!(b_rr.proof, b1.proof);
    assert_eq!(validate_ballot(&b_rr, &w.ctx), Ok(()));
    assert_eq!(b_rr.content_id(), b1.content_id());
    assert_ne!(
        Item::Ballot(b_rr).item_hash(),
        Item::Ballot(b1.clone()).item_hash()
    );

    // Ballot for a second vote by the same person: different nullifier, unlinkable.
    let mut v2 = w.vote.clone();
    v2.question = "Second question?".into();
    let v2 = sign_vote_definition(&w.authority, v2);
    let b_v2 = plaintext_ballot(dev_keys(), &p, &v2, 0).unwrap();
    assert_ne!(b_v2.nullifier, b1.nullifier);
    assert_eq!(w.vote_id, w.vote.vote_id());
}

/// Several Issuers coexist (SPEC §4.3, §6.1): an item's `registry_root` only
/// counts under the Issuer that item names, `vote_id` covers `issuer_key`,
/// and one person may legitimately hold a leaf in more than one registry.
#[test]
fn several_issuers_coexist() {
    let mut w = world();
    let issuer_b = SigningKey::from_seed(&[0x12u8; 32]).public_key();
    // A smaller electorate made of some of the same people.
    let tree_b = RegistryTree::from_leaves(w.secrets[..8].iter().map(commitment).collect());
    w.ctx.deployment.issuer_keys.push(issuer_b);
    w.ctx
        .add_registry(issuer_b, tree_b.root(), tree_b.leaf_count());

    // Issuer A's root is not Issuer B's root: naming B with A's root refers to
    // a registry that does not exist, rather than borrowing A's electorate.
    let mut v = w.vote.clone();
    v.issuer_key = issuer_b;
    assert!(matches!(
        validate_vote(&sign_vote_definition(&w.authority, v), &w.ctx),
        Err(Invalid::MissingReference(Reference::Registry(..)))
    ));

    // B's own vote: valid, and a different vote_id although question,
    // options and blocks are identical.
    let vote_b = sign_vote_definition(
        &w.authority,
        VoteDefinition {
            issuer_key: issuer_b,
            registry_root: tree_b.root(),
            ..w.vote.clone()
        },
    );
    assert_eq!(validate_vote(&vote_b, &w.ctx), Ok(()));
    assert_ne!(vote_b.vote_id(), w.vote_id);
    w.ctx.add_vote(vote_b.clone());

    // The same person votes in both electorates. Nullifiers are scoped per
    // vote, so the two ballots are independent and unlinkable.
    let p_a = participant(&w, 5);
    let p_b = Participant {
        secret: w.secrets[5],
        issuer_key: issuer_b,
        registry_root: tree_b.root(),
        index: 5,
        siblings: tree_b.path(5).unwrap(),
    };
    let ballot_a = plaintext_ballot(dev_keys(), &p_a, &w.vote, 1).unwrap();
    let ballot_b = plaintext_ballot(dev_keys(), &p_b, &vote_b, 1).unwrap();
    assert_ne!(ballot_a.nullifier, ballot_b.nullifier);
    assert_eq!(validate_ballot(&ballot_a, &w.ctx), Ok(()));
    assert_eq!(validate_ballot(&ballot_b, &w.ctx), Ok(()));
    // A ballot proven against B's registry is not valid for A's vote.
    let cross = Ballot {
        vote_id: w.vote_id,
        ..ballot_b.clone()
    };
    assert_eq!(validate_ballot(&cross, &w.ctx), Err(Invalid::BadProof));

    // Node registrations are scoped to the electorate too: one node per person
    // per Issuer, so someone enrolled with both can serve both networks
    // without the duplicate rule cancelling either, and the two registrations
    // do not link back to one person (A50).
    let node_sk = SigningKey::from_seed(&[0x56u8; 32]);
    let node = |p: &Participant| {
        build_node_registration(
            dev_keys(),
            p,
            node_sk.public_key(),
            [0x66; 32],
            "node.example:8443".into(),
            "Example".into(),
            *b"CZ",
            6830,
        )
        .unwrap()
    };
    let reg_a = node(&p_a);
    let reg_b = node(&p_b);
    assert_ne!(reg_a.nullifier, reg_b.nullifier);
    assert_eq!(validate_node_registration(&reg_a, &w.ctx), Ok(()));
    assert_eq!(validate_node_registration(&reg_b, &w.ctx), Ok(()));

    // Within one electorate it is still one per person: a second, differing
    // registration under the same Issuer shares the nullifier and the
    // duplicate rule (SPEC §7.1) drops both.
    let twice = build_node_registration(
        dev_keys(),
        &p_a,
        SigningKey::from_seed(&[0x57u8; 32]).public_key(),
        [0x66; 32],
        "other.example:8443".into(),
        "Example".into(),
        *b"CZ",
        6830,
    )
    .unwrap();
    assert_eq!(twice.nullifier, reg_a.nullifier);
    assert_ne!(twice.content_id(), reg_a.content_id());

    // The author pseudonym is scoped the same way: the same person authoring
    // in two electorates is two unlinkable pseudonyms.
    let n = initiative_threshold(w.tree.leaf_count());
    let init_a = build_initiative(dev_keys(), &p_a, "Text".into(), n, 300, Secrecy::None).unwrap();
    let init_b = build_initiative(
        dev_keys(),
        &p_b,
        "Text".into(),
        initiative_threshold(tree_b.leaf_count()),
        300,
        Secrecy::None,
    )
    .unwrap();
    assert_ne!(init_a.author, init_b.author);
    assert_eq!(validate_initiative(&init_a, &w.ctx), Ok(()));
    assert_eq!(validate_initiative(&init_b, &w.ctx), Ok(()));
}

#[test]
fn supports_initiatives_nodes_witnesses() {
    let mut w = world();
    let p = participant(&w, 6);
    let n = initiative_threshold(w.tree.leaf_count());
    let init = build_initiative(
        dev_keys(),
        &p,
        "Lower the voting age".into(),
        n,
        300,
        Secrecy::None,
    )
    .unwrap();
    assert_eq!(validate(&Item::Initiative(init.clone()), &w.ctx), Ok(()));
    let wrong_n = build_initiative(
        dev_keys(),
        &p,
        "Lower the voting age".into(),
        n + 1,
        300,
        Secrecy::None,
    )
    .unwrap();
    assert!(matches!(
        validate_initiative(&wrong_n, &w.ctx),
        Err(Invalid::Structure(_))
    ));
    // Same author pseudonym across initiatives (A9).
    let init2 = build_initiative(
        dev_keys(),
        &p,
        "Another question".into(),
        n,
        300,
        Secrecy::None,
    )
    .unwrap();
    assert_eq!(init2.author, init.author);
    assert_eq!(validate_initiative(&init2, &w.ctx), Ok(()));

    let init_id = w.ctx.add_initiative(init.clone());
    let s = build_support(dev_keys(), &participant(&w, 7), &init_id).unwrap();
    assert_eq!(validate(&Item::Support(s.clone()), &w.ctx), Ok(()));
    let s_again = build_support(dev_keys(), &participant(&w, 7), &init_id).unwrap();
    assert_eq!(
        Item::Support(s.clone()).encode(),
        Item::Support(s_again).encode()
    );
    let bad = Support {
        initiative_id: [1; 32],
        ..s.clone()
    };
    assert!(matches!(
        validate_support(&bad, &w.ctx),
        Err(Invalid::MissingReference(_))
    ));
    let bad = Support {
        proof: Proof([0; 128]),
        ..s.clone()
    };
    assert_eq!(validate_support(&bad, &w.ctx), Err(Invalid::BadProof));

    let node_sk = SigningKey::from_seed(&[0x55u8; 32]);
    let reg = build_node_registration(
        dev_keys(),
        &participant(&w, 8),
        node_sk.public_key(),
        [0x66; 32],
        "node.example:8443".into(),
        "Example".into(),
        *b"CZ",
        6830,
    )
    .unwrap();
    assert_eq!(
        validate(&Item::NodeRegistration(reg.clone()), &w.ctx),
        Ok(())
    );
    let bad = NodeRegistration {
        endpoint: String::new(),
        ..reg.clone()
    };
    assert!(matches!(
        validate_node_registration(&bad, &w.ctx),
        Err(Invalid::Structure(_))
    ));
    let bad = NodeRegistration {
        asn: 1,
        ..reg.clone()
    };
    assert_eq!(
        validate_node_registration(&bad, &w.ctx),
        Err(Invalid::BadProof)
    );
}

#[test]
fn dev_anchor_is_gated_by_dev_mode() {
    let mut w = world();
    let a = Anchor {
        leaves: vec![[1; 32]],
        proof: AnchorProof::Dev { height: 150 },
    };
    assert!(matches!(
        validate_anchor(&a, &w.ctx),
        Err(Invalid::MissingReference(Reference::Header(150)))
    ));
    w.ctx.headers.insert(150, [0; 32]);
    assert_eq!(validate_anchor(&a, &w.ctx), Ok(()));
    w.ctx.deployment.dev_mode = false;
    assert_eq!(validate_anchor(&a, &w.ctx), Err(Invalid::DevOnly));
    let bad = Anchor {
        leaves: vec![],
        proof: AnchorProof::Dev { height: 150 },
    };
    assert!(matches!(
        validate_anchor(&bad, &w.ctx),
        Err(Invalid::Structure(_))
    ));
}
