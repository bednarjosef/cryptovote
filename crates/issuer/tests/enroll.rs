//! The Issuer core is backend-agnostic: it takes a verdict and keeps only the
//! commitment, the dedup key and a timestamp (whitepaper §5).

use cv_core::crypto::field::{Fr, fr_mod};
use cv_core::crypto::sig::SigningKey;
use cv_issuer::{
    EnrollmentRequest, Issuer, IssuerError, MockBackend, Verification, VerificationBackend,
};

/// A backend that maps several credentials to one person and refuses one of
/// them — the two things the Issuer core has to react to.
struct TestBackend;

impl VerificationBackend for TestBackend {
    fn verify(&self, request: &EnrollmentRequest) -> Verification {
        match request.credential {
            "alice-phone" | "alice-laptop" => Verification::Verified {
                dedup_key: "alice".into(),
            },
            "bob" => Verification::Verified {
                dedup_key: "bob".into(),
            },
            other => Verification::Rejected {
                reason: format!("unknown credential {other}"),
            },
        }
    }
}

fn commitment(x: u64) -> Fr {
    fr_mod(&[x as u8; 32])
}

fn request(credential: &str, c: Fr) -> EnrollmentRequest<'_> {
    EnrollmentRequest {
        commitment: c,
        credential,
    }
}

#[test]
fn dedup_key_decides_insert_or_replace() {
    let mut issuer = Issuer::new(SigningKey::from_seed(&[0x11u8; 32]), Box::new(TestBackend));
    let first = issuer
        .enroll(&request("alice-phone", commitment(1)))
        .unwrap();
    assert_eq!((first.index, first.replaced), (0, false));
    let bob = issuer.enroll(&request("bob", commitment(2))).unwrap();
    assert_eq!((bob.index, bob.replaced), (1, false));

    // A different credential for the same person replaces her leaf in place.
    let root_before = issuer.tree().root();
    let epoch_before = issuer.epoch();
    let again = issuer
        .enroll(&request("alice-laptop", commitment(3)))
        .unwrap();
    assert_eq!((again.index, again.replaced), (0, true));
    assert_eq!(issuer.leaf_count(), 2, "no second leaf for the same person");
    assert_eq!(issuer.leaves()[0], commitment(3));
    assert_ne!(issuer.tree().root(), root_before);
    assert!(issuer.epoch() > epoch_before, "a new root is published");

    // Only the dedup key and a timestamp are kept next to each leaf.
    assert_eq!(issuer.records().len(), 2);
    assert_eq!(issuer.records()[0].dedup_key, "alice");
    assert!(issuer.records()[0].enrolled_unix > 0);

    // A rejection carries the backend's reason and changes nothing.
    let root = issuer.tree().root();
    let err = issuer
        .enroll(&request("mallory", commitment(4)))
        .unwrap_err();
    assert!(
        matches!(&err, IssuerError::Rejected(r) if r.contains("mallory")),
        "{err}"
    );
    assert_eq!(issuer.tree().root(), root);
    assert_eq!(issuer.leaf_count(), 2);
}

#[test]
fn snapshots_name_their_own_issuer_and_survive_a_restart() {
    let mut issuer = Issuer::new(SigningKey::from_seed(&[0x11u8; 32]), Box::new(TestBackend));
    issuer.enroll(&request("bob", commitment(2))).unwrap();
    let snapshot = issuer.snapshot();
    assert_eq!(snapshot.issuer_key, issuer.public_key());
    assert!(snapshot.verify());
    assert!(snapshot.verify_by(&issuer.public_key()));
    assert!(!snapshot.verify_by(&SigningKey::from_seed(&[0x12u8; 32]).public_key()));

    let path = std::env::temp_dir().join(format!("cv-issuer-{}.json", std::process::id()));
    issuer.save(&path).unwrap();
    let reloaded = Issuer::load(&path, Box::new(TestBackend)).unwrap();
    std::fs::remove_file(&path).ok();
    assert_eq!(reloaded.public_key(), issuer.public_key());
    assert_eq!(reloaded.snapshot(), snapshot);
    assert_eq!(reloaded.records(), issuer.records());
}

#[test]
fn the_mock_backend_accepts_anything_non_empty() {
    let mut issuer = Issuer::new(SigningKey::from_seed(&[1u8; 32]), Box::new(MockBackend));
    assert!(issuer.enroll(&request("whatever", commitment(1))).is_ok());
    // The same string is the same person, so this replaces rather than adds.
    let again = issuer.enroll(&request("whatever", commitment(2))).unwrap();
    assert!(again.replaced);
    assert!(matches!(
        issuer.enroll(&request("", commitment(3))),
        Err(IssuerError::Rejected(_))
    ));
}
