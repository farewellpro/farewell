#![no_main]
//! Fuzz the pure-Rust audio decoder on arbitrary bytes.
//!
//! `farewell_audio` is the only viewer codec that runs entirely in our own
//! code, on a file that may be fully attacker-controlled (e.g. a malicious
//! recording handed to a journalist). It is `#![forbid(unsafe_code)]`, so the
//! worst outcome is a panic or a hang (DoS) rather than memory corruption —
//! but a panic that propagates across the FFI boundary is still undefined
//! behaviour, so we want zero panics on any input.
//!
//! This target exercises the full path: probe/open, then a bounded number of
//! `read` calls and one `seek`, mirroring how the app actually drives it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(mut dec) = farewell_audio::AudioDecoder::open(data.to_vec()) else {
        return; // unsupported/garbage input is a clean rejection, not a bug
    };

    // Pull a bounded amount of PCM so a crafted "infinite" stream can't hang
    // the fuzzer; we only care that decoding never panics.
    let mut buf = vec![0f32; 4096];
    let mut budget = 256; // ≈ 1M samples max
    while budget > 0 {
        let n = dec.read(&mut buf);
        if n == 0 {
            break;
        }
        budget -= 1;
    }

    // A seek mid-stream then one more read — seek + decoder reset is its own
    // little state machine worth poking.
    let _ = dec.seek(1_000);
    let _ = dec.read(&mut buf);
});
