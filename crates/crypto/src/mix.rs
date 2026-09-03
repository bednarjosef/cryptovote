//! Sphinx onion packets for the mix (whitepaper §12), via Nym's
//! `sphinx-packet`, and the X25519 hop keys. A hop's *address* is its
//! registered Ed25519 node key; the hop looks up the next endpoint in its
//! own Log.

use sphinx_packet::header::delays::Delay;
use sphinx_packet::packet::builder::SphinxPacketBuilder;
use sphinx_packet::payload::PAYLOAD_OVERHEAD_SIZE;
use sphinx_packet::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes};
use sphinx_packet::{ProcessedPacketData, SphinxPacket};

/// Fixed payload size: every packet on the wire has the same length.
pub const PAYLOAD_SIZE: usize = 2048;
/// Longest item that fits through the mix; larger items go direct.
pub const MAX_MESSAGE_LEN: usize = PAYLOAD_SIZE - PAYLOAD_OVERHEAD_SIZE;
/// Final payloads starting with this are decoys and are dropped by the exit.
pub const DECOY_MARKER: &[u8; 8] = b"CVDECOY\0";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MixError {
    #[error("message too long for a mix packet ({0} > {MAX_MESSAGE_LEN})")]
    TooLong(usize),
    #[error("route must have 1 to 5 hops")]
    RouteLength,
    #[error("sphinx: {0}")]
    Sphinx(String),
}

/// X25519 secret of a mix hop.
#[derive(Clone)]
pub struct MixSecret(x25519_dalek::StaticSecret);

impl MixSecret {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        MixSecret(x25519_dalek::StaticSecret::from(seed))
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    pub fn public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    /// Registered node key (Ed25519 public key), used as the Sphinx address.
    pub address: [u8; 32],
    /// The hop's X25519 mix key from its NodeRegistration.
    pub mix_key: [u8; 32],
}

/// Build an onion packet for `route`; the last hop is the exit that
/// publishes the payload to the Log.
pub fn build_packet(message: &[u8], route: &[Hop]) -> Result<Vec<u8>, MixError> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(MixError::TooLong(message.len()));
    }
    if route.is_empty() || route.len() > 5 {
        return Err(MixError::RouteLength);
    }
    let nodes: Vec<Node> = route
        .iter()
        .map(|h| {
            Node::new(
                NodeAddressBytes::from_bytes(h.address),
                x25519_dalek::PublicKey::from(h.mix_key),
            )
        })
        .collect();
    let destination = Destination::new(DestinationAddressBytes::from_bytes([0u8; 32]), [0u8; 16]);
    let delays: Vec<Delay> = route.iter().map(|_| Delay::new_from_nanos(0)).collect();
    let packet = SphinxPacketBuilder::new()
        .with_payload_size(PAYLOAD_SIZE)
        .build_packet(message, &nodes, &destination, &delays)
        .map_err(|e| MixError::Sphinx(e.to_string()))?;
    Ok(packet.to_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Processed {
    /// Forward the inner packet to the hop with this address.
    Forward { packet: Vec<u8>, next: [u8; 32] },
    /// This hop is the exit: publish (or drop, if decoy) the payload.
    Final { payload: Vec<u8> },
}

/// Peel one layer with this hop's secret.
pub fn process(packet: &[u8], secret: &MixSecret) -> Result<Processed, MixError> {
    let p = SphinxPacket::from_bytes(packet).map_err(|e| MixError::Sphinx(e.to_string()))?;
    let processed = p
        .process(&secret.0)
        .map_err(|e| MixError::Sphinx(e.to_string()))?;
    Ok(match processed.data {
        ProcessedPacketData::ForwardHop {
            next_hop_packet,
            next_hop_address,
            ..
        } => Processed::Forward {
            packet: next_hop_packet.to_bytes(),
            next: *next_hop_address.as_bytes(),
        },
        ProcessedPacketData::FinalHop { payload, .. } => Processed::Final {
            payload: payload
                .recover_plaintext()
                .map_err(|e| MixError::Sphinx(e.to_string()))?,
        },
    })
}

pub fn is_decoy(payload: &[u8]) -> bool {
    payload.starts_with(DECOY_MARKER)
}

/// A decoy payload padded to `len` bytes.
pub fn decoy_payload<R: rand::RngCore>(rng: &mut R, len: usize) -> Vec<u8> {
    let mut v = DECOY_MARKER.to_vec();
    let mut pad = vec![0u8; len.saturating_sub(v.len())];
    rng.fill_bytes(&mut pad);
    v.extend_from_slice(&pad);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn three_hop_packet_peels_in_order_and_packets_are_fixed_size() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([3u8; 32]);
        let secrets: Vec<MixSecret> = (0..3).map(|_| MixSecret::generate(&mut rng)).collect();
        let route: Vec<Hop> = secrets
            .iter()
            .enumerate()
            .map(|(i, s)| Hop {
                address: [i as u8 + 1; 32],
                mix_key: s.public(),
            })
            .collect();
        let msg = b"hello log".to_vec();
        let p0 = build_packet(&msg, &route).unwrap();
        let p_short = build_packet(&[1u8; 600], &route[..1]).unwrap();
        assert_eq!(
            p0.len(),
            p_short.len(),
            "packet length does not depend on route length or message length"
        );
        let Processed::Forward { packet: p1, next } = process(&p0, &secrets[0]).unwrap() else {
            panic!()
        };
        assert_eq!(next, [2u8; 32]);
        assert_eq!(p1.len(), p0.len());
        let Processed::Forward { packet: p2, next } = process(&p1, &secrets[1]).unwrap() else {
            panic!()
        };
        assert_eq!(next, [3u8; 32]);
        let Processed::Final { payload } = process(&p2, &secrets[2]).unwrap() else {
            panic!()
        };
        assert_eq!(payload, msg);
        // Wrong key fails.
        assert!(process(&p0, &secrets[1]).is_err());
        assert!(build_packet(&[0u8; MAX_MESSAGE_LEN + 1], &route).is_err());
        assert!(is_decoy(&decoy_payload(&mut rng, 100)));
        assert!(!is_decoy(&msg));
    }
}
