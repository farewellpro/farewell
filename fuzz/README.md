# Fuzzing Farewell's untrusted-input parsers

These targets exercise the two code paths that turn **attacker-controlled
bytes** into structured data. They are a developer/CI tool and live outside the
main workspace (their own `[workspace]`, a nightly toolchain, libFuzzer
instrumentation) so they never affect the pinned, reproducible release build.

## Targets

| Target | What it parses | Why it matters |
|---|---|---|
| `manifest_parse` | `farewell_format::Manifest::parse` | The directory tree deserialized from a vault. AEAD-authenticated in normal use, but the parser must still be total: reject malformed input with `Err`, never panic, never over-allocate. |
| `audio_decode` | `farewell_audio::AudioDecoder` (open + read + seek) | A media file handed to the in-app viewer may be fully attacker-controlled. The decode runs in our own pure-Rust code (Symphonia), so the worst case must be a clean rejection, not a crash. |

## Running

```sh
rustup toolchain install nightly          # one-time
cargo install cargo-fuzz                   # one-time

cargo +nightly fuzz build                  # compile all targets
cargo +nightly fuzz run manifest_parse -- -max_total_time=120
cargo +nightly fuzz run audio_decode   -- -max_total_time=120 -timeout=10
```

Reproduce / minimize a saved crash:

```sh
cargo +nightly fuzz run  audio_decode fuzz/artifacts/audio_decode/<id>
cargo +nightly fuzz tmin audio_decode fuzz/artifacts/audio_decode/<id>
```

## Findings (each fixed, with a pinned regression test)

- **`manifest_parse` — OOM on an untrusted length field.** A tiny buffer could
  declare a huge `entry_count`/`chunk_count`/`folder_count`, causing a
  multi-gigabyte `Vec::with_capacity` before any data was read. Fixed by
  bounding every pre-allocation to what the remaining bytes can hold
  (`ManifestParser::cap`). Regression: `manifest::tests::huge_entry_count_does_not_oom`.

- **`audio_decode` — panics inside a third-party codec.** Fuzzing found
  malformed AAC inputs that panic inside `symphonia-codec-aac`:
  - an arithmetic overflow in the ADTS header parser (`adts.rs:303`) — already
    reported upstream as pdeljanov/Symphonia#509 and **fixed in Symphonia 0.6**,
    which we upgraded to;
  - an index-out-of-bounds in the AAC section-data parser (`ics/mod.rs:246`),
    still present in 0.6.0 — we **reported it upstream as
    pdeljanov/Symphonia#512** with a self-contained reproducer.

  A panic crossing the FFI into the Swift app (or, under `panic = "abort"`,
  aborting it) would be a denial of service with the vault unlocked. Defended
  in two layers regardless of the upstream state: `farewell_audio` wraps its
  whole public API (`open`/`read`/`seek`) in `catch_unwind` (→
  `AudioError::Unsupported` / clean end-of-stream), and the release profile
  uses `panic = "unwind"` so the FFI's `catch_panic` shims actually catch.
  Regressions: `farewell_audio::tests::{malformed_aac_does_not_panic,
  malformed_aac_decode_does_not_panic}`.

### Note on `audio_decode` and libFuzzer

`libfuzzer-sys` installs a panic hook that **aborts on any panic, even one we
catch**. So `audio_decode` will still *report* an abort on inputs that trip an
upstream Symphonia panic, even though production handles them gracefully — the
proof of the production fix is the `cargo test` unit
`malformed_aac_does_not_panic`, which passes (the default hook prints but does
not abort, so our `catch_unwind` returns `Err`). Treat new `audio_decode`
aborts as *upstream codec panics already neutralized at our boundary*, not app
crashes; they are still worth collecting and reporting upstream. For this
reason CI only **builds** the fuzz targets and smoke-runs `manifest_parse`;
deep audio fuzzing is a manual/scheduled activity.
