//! Throwaway Argon2id timing bench. `cargo run --release -p farewell_crypto --example kdf_bench`
use farewell_crypto::kdf::{derive, KdfParams, DEV_PARAMS, PRODUCTION_PARAMS};
use std::time::Instant;

fn bench(name: &str, p: &KdfParams) {
    let salt = [7u8; 32];
    // warm + 3 runs
    let _ = derive(b"correct-horse-battery-staple-9", &salt, p).unwrap();
    let mut best = f64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        let _ = derive(b"correct-horse-battery-staple-9", &salt, p).unwrap();
        best = best.min(t.elapsed().as_secs_f64());
    }
    println!(
        "{name:12} m={:>5} MiB  t={}  p={}  -> {:.3}s",
        p.memory_kib / 1024,
        p.iterations,
        p.parallelism,
        best
    );
}

fn main() {
    bench("DEV", &DEV_PARAMS);
    bench("PRODUCTION", &PRODUCTION_PARAMS);
    // A couple of alternative profiles for comparison.
    bench("256MiB/t4", &KdfParams { memory_kib: 256 * 1024, iterations: 4, parallelism: 4 });
    bench("512MiB/t3", &KdfParams { memory_kib: 512 * 1024, iterations: 3, parallelism: 4 });
}
