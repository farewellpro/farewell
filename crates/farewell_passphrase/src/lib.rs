//! Passphrase strength policy + diceware generation for Farewell.
//!
//! Farewell has **no auto-wipe and no recovery** (see THREAT_MODEL §5.4):
//! once an attacker holds a copy of the vault, the *only* thing standing
//! between them and the contents is the cost of guessing the passphrase
//! (Argon2id per guess × passphrase entropy) — plus, optionally, a
//! hardware key. A weak passphrase therefore defeats the whole product.
//!
//! This crate is the single source of truth for "is this passphrase
//! strong enough?" and "give me a strong one". It is consumed by the
//! CLI, by the core (as a creation-time backstop), and by the macOS app
//! through the FFI, so every entry point enforces the *same* policy and
//! shows the *same* strength estimate.
//!
//! - [`estimate`] wraps **zxcvbn** (models dictionaries, keyboard walks,
//!   leetspeak, known-breach patterns — not naive composition rules,
//!   which NIST SP 800-63B explicitly discourages).
//! - [`generate`] draws an **EFF large-wordlist** diceware passphrase
//!   from the OS CSPRNG. At ~12.9 bits/word, the default 10 words give
//!   ~129 bits — comfortably future-proof even if today's KDF params
//!   look weak decades from now.
//! - [`meets_policy`] is the hard floor: zxcvbn score must be the
//!   maximum (4/4).

#![deny(missing_docs)]

use zeroize::Zeroize;

/// Embedded EFF large wordlist (one word per line).
///
/// Source: Electronic Frontier Foundation, "EFF's New Wordlists for
/// Random Passphrases" (2016), `eff_large_wordlist.txt`, licensed
/// CC-BY-3.0. Reduced here to the word column (the dice indices are
/// dropped). See `data/NOTICE`.
static WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

/// Minimum zxcvbn score (0–4) accepted by [`meets_policy`]. We require
/// the maximum: anything less is rejected at vault creation.
pub const MIN_SCORE: u8 = 4;

/// Default number of words in a generated passphrase.
pub const DEFAULT_WORDS: usize = 10;

/// Word separator used by [`generate`].
const SEPARATOR: char = '-';

/// Errors from passphrase generation.
#[derive(Debug)]
pub enum PassphraseError {
    /// The OS CSPRNG failed.
    Rng,
    /// Caller asked for zero words.
    ZeroWords,
}

impl std::fmt::Display for PassphraseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassphraseError::Rng => write!(f, "CSPRNG failure"),
            PassphraseError::ZeroWords => write!(f, "word count must be >= 1"),
        }
    }
}

impl std::error::Error for PassphraseError {}

/// A strength estimate for a candidate passphrase.
#[derive(Debug, Clone)]
pub struct Strength {
    /// zxcvbn score, 0 (weakest) to 4 (strongest).
    pub score: u8,
    /// log10 of the estimated number of guesses to crack.
    pub guesses_log10: f64,
    /// Short, human-readable guidance (warning or top suggestion), if any.
    pub feedback: Option<String>,
}

impl Strength {
    /// Whether this estimate satisfies the policy floor ([`MIN_SCORE`]).
    pub fn acceptable(&self) -> bool {
        self.score >= MIN_SCORE
    }
}

/// All words in the embedded wordlist.
fn words() -> Vec<&'static str> {
    WORDLIST.lines().filter(|l| !l.is_empty()).collect()
}

/// Number of words in the embedded wordlist.
pub fn wordlist_len() -> usize {
    words().len()
}

/// Entropy, in bits, of an `n`-word generated passphrase: `n · log2(N)`
/// where `N` is the wordlist size.
pub fn entropy_bits(n_words: usize) -> f64 {
    (wordlist_len() as f64).log2() * n_words as f64
}

/// Estimate the strength of `pw` with zxcvbn.
pub fn estimate(pw: &str) -> Strength {
    let e = zxcvbn::zxcvbn(pw, &[]);
    let score = u8::from(e.score());
    let feedback = e.feedback().and_then(|fb| {
        fb.warning()
            .map(|w| w.to_string())
            .or_else(|| fb.suggestions().first().map(|s| s.to_string()))
    });
    Strength {
        score,
        guesses_log10: e.guesses_log10(),
        feedback,
    }
}

/// Whether `pw` meets the creation-time policy (zxcvbn score ≥
/// [`MIN_SCORE`]). This is the hard floor enforced at every entry point.
pub fn meets_policy(pw: &str) -> bool {
    estimate(pw).score >= MIN_SCORE
}

/// Draw a uniform random index in `0..n` from the OS CSPRNG, using
/// rejection sampling to avoid modulo bias.
fn uniform_index(n: u32) -> Result<u32, PassphraseError> {
    debug_assert!(n > 0);
    // Largest multiple of n that fits in u32; reject anything at or above.
    let limit = (u32::MAX / n) * n;
    loop {
        let mut buf = [0u8; 4];
        farewell_crypto::rng::fill(&mut buf).map_err(|_| PassphraseError::Rng)?;
        let r = u32::from_le_bytes(buf);
        buf.zeroize();
        if r < limit {
            return Ok(r % n);
        }
    }
}

/// Generate an `n`-word EFF diceware passphrase (hyphen-separated).
pub fn generate(n_words: usize) -> Result<String, PassphraseError> {
    if n_words == 0 {
        return Err(PassphraseError::ZeroWords);
    }
    let list = words();
    let n = list.len() as u32;
    let mut chosen: Vec<&str> = Vec::with_capacity(n_words);
    for _ in 0..n_words {
        let idx = uniform_index(n)? as usize;
        chosen.push(list[idx]);
    }
    let mut out = String::new();
    for (i, w) in chosen.iter().enumerate() {
        if i > 0 {
            out.push(SEPARATOR);
        }
        out.push_str(w);
    }
    Ok(out)
}

/// Generate a passphrase with the default word count ([`DEFAULT_WORDS`]).
pub fn generate_default() -> Result<String, PassphraseError> {
    generate(DEFAULT_WORDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_large_and_clean() {
        let n = wordlist_len();
        assert!(n > 7000, "expected a large wordlist, got {n}");
        for w in words() {
            assert!(
                w.bytes().all(|b| b.is_ascii_lowercase()),
                "non a-z word: {w:?}"
            );
            assert!(w.len() >= 3);
        }
    }

    #[test]
    fn entropy_default_is_strong() {
        // 10 words from a ~7776-word list ≈ 129 bits.
        assert!(entropy_bits(DEFAULT_WORDS) > 120.0);
    }

    #[test]
    fn generated_default_passes_policy() {
        let pw = generate_default().unwrap();
        let parts: Vec<&str> = pw.split(SEPARATOR).collect();
        assert_eq!(parts.len(), DEFAULT_WORDS);
        assert!(
            meets_policy(&pw),
            "generated passphrase must pass policy: {pw:?} -> {:?}",
            estimate(&pw)
        );
    }

    #[test]
    fn generation_is_random() {
        let a = generate_default().unwrap();
        let b = generate_default().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn weak_passphrases_rejected() {
        for weak in ["password", "12345678", "qwerty", "letmein", "Summer2024"] {
            assert!(!meets_policy(weak), "should reject weak: {weak:?}");
        }
    }

    #[test]
    fn zero_words_errors() {
        assert!(matches!(generate(0), Err(PassphraseError::ZeroWords)));
    }
}
