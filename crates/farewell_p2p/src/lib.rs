//! P2P LAN transport for inter-device file transfer.
//!
//! # Status: stub (v0.1)
//!
//! Production design (ARCHITECTURE.md §11): Noise XX handshake over TCP on
//! LAN, restricted to RFC1918 / link-local / `fe80::/10`. Pairing via
//! single-use 32-byte token shared out-of-band. Phase 2 deliverable.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// A pairing token. Generated on the initiator, transmitted out-of-band.
#[derive(Debug, Clone)]
pub struct PairingToken(pub [u8; 32]);

impl PairingToken {
    /// Encode as base32 for human transmission (~52 characters).
    pub fn to_base32(&self) -> String {
        // Stub: hex is fine for v0.1, base32 in Phase 2.
        hex_lower(&self.0)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

// TODO(Phase 2): full Noise XX implementation, RFC1918 enforcement,
// fingerprint verification UI.
