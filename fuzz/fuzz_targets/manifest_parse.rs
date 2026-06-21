#![no_main]
//! Fuzz the manifest deserializer on arbitrary bytes.
//!
//! `Manifest::parse` turns a byte buffer into the in-memory directory tree.
//! In normal operation that buffer is AEAD-authenticated before parsing, so an
//! attacker cannot freely choose it — but defense in depth demands the parser
//! itself be total: it must reject any malformed input with an `Err`, never
//! panic, never over-allocate, never loop forever (a hostile length field must
//! not cause a multi-gigabyte allocation or an OOM).
//!
//! As a round-trip sanity check, anything that parses successfully is
//! re-serialized and re-parsed; the two parses must agree.

use libfuzzer_sys::fuzz_target;

use farewell_format::Manifest;

fuzz_target!(|data: &[u8]| {
    let Ok(m) = Manifest::parse(data) else {
        return; // malformed input → clean rejection, as required
    };

    // Round-trip: serialize what we parsed and parse it again. A parser that
    // accepts a buffer it cannot reproduce is inconsistent.
    if let Ok(bytes) = m.serialize() {
        let reparsed = Manifest::parse(&bytes).expect("re-parse of our own serialization must succeed");
        assert_eq!(
            m.entries.len(),
            reparsed.entries.len(),
            "entry count changed across a serialize/parse round-trip"
        );
        assert_eq!(
            m.counter, reparsed.counter,
            "counter changed across a serialize/parse round-trip"
        );
    }
});
