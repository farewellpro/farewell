//! Token format: `base64url(payload_bytes) . base64url(signature_bytes)`.
//!
//! URL-safe base64 without padding (RFC 4648 §5) so the token is
//! copy-paste-safe in email, terminal, and URLs without quoting.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::LicenseError;

/// Encode the (payload bytes, signature bytes) pair into a single
/// compact token. The output looks like:
///
/// ```text
/// AbCd...payload...XyZ.AbC...sig...XyZ
/// ```
pub fn write_token(payload: &[u8], signature: &[u8]) -> String {
    let mut out = String::with_capacity((payload.len() + signature.len()) * 4 / 3 + 8);
    out.push_str(&URL_SAFE_NO_PAD.encode(payload));
    out.push('.');
    out.push_str(&URL_SAFE_NO_PAD.encode(signature));
    out
}

/// Split a token into its raw (payload, signature) byte buffers.
/// Does NOT verify the signature; callers must do that separately
/// via [`crate::verify::verify_token`].
pub fn parse_token(token: &str) -> Result<(Vec<u8>, Vec<u8>), LicenseError> {
    let trimmed = token.trim();

    // Allow PEM-style framing for human-friendly file storage.
    let body = strip_pem_framing(trimmed).unwrap_or(trimmed);
    let body: String = body.split_whitespace().collect();

    // Canonical form: a grouped Crockford-base32 license **key** (no '.'). The
    // legacy dotted base64url token (payload.signature) is still accepted.
    if !body.contains('.') {
        return crate::key::decode_key(&body);
    }

    let mut parts = body.split('.');
    let p = parts.next();
    let s = parts.next();
    if p.is_none() || s.is_none() || parts.next().is_some() {
        return Err(LicenseError::MalformedToken(format!(
            "token had {} segments, expected 2",
            body.split('.').count()
        )));
    }
    let payload = URL_SAFE_NO_PAD.decode(p.unwrap())?;
    let signature = URL_SAFE_NO_PAD.decode(s.unwrap())?;
    Ok((payload, signature))
}

/// Wrap a raw token in PEM-style human-friendly framing, for storage in
/// a license file or display in an email.
pub fn wrap_pem(token: &str) -> String {
    let mut out = String::with_capacity(token.len() + 64);
    out.push_str("-----BEGIN FAREWELL LICENSE-----\n");
    for chunk in token.as_bytes().chunks(64) {
        // Safe: token is ASCII (base64url + '.' separator).
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END FAREWELL LICENSE-----\n");
    out
}

fn strip_pem_framing(s: &str) -> Option<&str> {
    const BEGIN: &str = "-----BEGIN FAREWELL LICENSE-----";
    const END: &str = "-----END FAREWELL LICENSE-----";
    let start = s.find(BEGIN)? + BEGIN.len();
    let end = s.find(END)?;
    if end <= start {
        return None;
    }
    Some(&s[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_parse_roundtrip() {
        let payload = b"hello world payload";
        let signature = vec![0xABu8; 64];
        let token = write_token(payload, &signature);
        let (p2, s2) = parse_token(&token).unwrap();
        assert_eq!(payload, &p2[..]);
        assert_eq!(signature, s2);
    }

    #[test]
    fn parses_pem_framed_token() {
        let payload = b"abcdef";
        let signature = vec![0xCDu8; 64];
        let raw = write_token(payload, &signature);
        let framed = wrap_pem(&raw);
        let (p, s) = parse_token(&framed).unwrap();
        assert_eq!(payload, &p[..]);
        assert_eq!(signature, s);
    }

    #[test]
    fn parses_token_with_whitespace_and_newlines() {
        let raw = write_token(b"x", &[0xFF; 64]);
        let with_ws = format!("  {}\n  ", raw);
        parse_token(&with_ws).unwrap();
    }

    #[test]
    fn rejects_missing_separator() {
        let err = parse_token("nodot").unwrap_err();
        assert!(matches!(err, LicenseError::MalformedToken(_)));
    }

    #[test]
    fn rejects_three_segments() {
        let err = parse_token("a.b.c").unwrap_err();
        assert!(matches!(err, LicenseError::MalformedToken(_)));
    }

    #[test]
    fn rejects_invalid_base64() {
        // '!' is not in URL-safe base64 alphabet.
        let err = parse_token("validpart.!!notbase64!!").unwrap_err();
        assert!(matches!(err, LicenseError::Base64(_)));
    }
}
