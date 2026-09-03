//! XChaCha20-Poly1305 (SPEC §1.5) via `chacha20poly1305`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

pub fn seal(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("encryption cannot fail")
}

pub fn open(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let k = [7u8; 32];
        let n = [9u8; 24];
        let ct = seal(&k, &n, b"ad", b"secret");
        assert_eq!(ct.len(), 6 + 16);
        assert_eq!(open(&k, &n, b"ad", &ct).unwrap(), b"secret");
        assert!(open(&k, &n, b"xx", &ct).is_none());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&k, &n, b"ad", &bad).is_none());
    }
}
