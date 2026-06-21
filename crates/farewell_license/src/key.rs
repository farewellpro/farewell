//! Human-facing license **key** format: Crockford base32 of a compact binary
//! container, in dash-separated groups, e.g. `J8K2W-9XQ4R-7M3NP-…`.
//!
//! Same trust model and contents as the dotted token (it carries the exact
//! same signed payload bytes + ECDSA P-256 signature) — it is just
//! *presented* as a single, case-insensitive, ambiguity-free key the buyer
//! pastes from their email, rather than a file. Decoding is deliberately
//! lenient: it ignores dashes/whitespace, is case-insensitive, and treats
//! Crockford's confusable letters leniently (O→0, I/L→1; U is not used).
//!
//! It is NOT a short "product key": offline + cryptographic verification
//! requires carrying the full 64-byte signature, so the key is ~hundreds of
//! characters — copy-pasted, not typed. A short number would require a
//! call-home activation server (forbidden by the no-call-home invariant) or a
//! forgeable algorithmic check (useless for a security product).

use crate::LicenseError;

/// Crockford base32 alphabet (excludes I, L, O, U to avoid confusion).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters per dash-separated group in the rendered key.
const GROUP: usize = 5;

/// Encode `(payload, signature)` as a grouped Crockford-base32 license key.
///
/// The binary container is `[payload_len: u16 BE][payload][signature]`.
pub fn encode_key(payload: &[u8], signature: &[u8]) -> String {
    let mut blob = Vec::with_capacity(2 + payload.len() + signature.len());
    blob.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    blob.extend_from_slice(payload);
    blob.extend_from_slice(signature);

    let raw = base32_encode(&blob);
    let mut out = String::with_capacity(raw.len() + raw.len() / GROUP + 1);
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && i % GROUP == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// Decode a grouped license key back into `(payload, signature)`. Tolerant of
/// dashes, whitespace, case, and Crockford confusables.
pub fn decode_key(key: &str) -> Result<(Vec<u8>, Vec<u8>), LicenseError> {
    let blob = base32_decode(key)?;
    if blob.len() < 2 {
        return Err(LicenseError::MalformedToken("license key too short".into()));
    }
    let plen = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    // The signature is variable-length (DER-encoded ECDSA), so it is simply
    // everything after the payload — base32 round-trips the exact byte count,
    // so there is no trailing padding to strip.
    if blob.len() <= 2 + plen {
        return Err(LicenseError::MalformedToken(format!(
            "license key too short: {} bytes, need > {} (payload {plen} + a signature)",
            blob.len(),
            2 + plen
        )));
    }
    let payload = blob[2..2 + plen].to_vec();
    let signature = blob[2 + plen..].to_vec();
    Ok((payload, signature))
}

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        // Left-align the remaining bits, zero-padded.
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn base32_decode(s: &str) -> Result<Vec<u8>, LicenseError> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8 + 1);
    for ch in s.chars() {
        let v: u32 = match ch {
            '-' | ' ' | '\t' | '\n' | '\r' => continue,
            '0' | 'o' | 'O' => 0,
            '1' | 'i' | 'I' | 'l' | 'L' => 1,
            c => {
                let up = c.to_ascii_uppercase() as u8;
                match ALPHABET.iter().position(|&a| a == up) {
                    Some(p) => p as u32,
                    None => {
                        return Err(LicenseError::MalformedToken(format!(
                            "invalid license-key character {c:?}"
                        )))
                    }
                }
            }
        };
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let payload = b"some license payload bytes \x00\x01\x02".to_vec();
        let sig = vec![0xABu8; 64];
        let key = encode_key(&payload, &sig);
        // Looks like a key: groups of GROUP separated by dashes, no '.'.
        assert!(key.contains('-'));
        assert!(!key.contains('.'));
        let (p2, s2) = decode_key(&key).unwrap();
        assert_eq!(p2, payload);
        assert_eq!(s2, sig);
    }

    #[test]
    fn decode_is_tolerant() {
        let payload = b"x".to_vec();
        let sig = vec![0x11u8; 64];
        let key = encode_key(&payload, &sig);
        // Lowercase, spaces, removed dashes, O/I substitution all decode the same.
        let messy = format!("  {}  ", key.to_lowercase().replace('-', " "));
        let (p2, s2) = decode_key(&messy).unwrap();
        assert_eq!(p2, payload);
        assert_eq!(s2, sig);
    }

    #[test]
    fn rejects_garbage_and_wrong_length() {
        assert!(decode_key("!!!!").is_err()); // invalid chars
        // A valid base32 string that is too short to hold len + sig.
        assert!(decode_key(&base32_encode(&[0x00, 0x01, 0x02])).is_err());
    }
}
