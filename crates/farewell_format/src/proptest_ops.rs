//! Property-based test for the mutation surface added in v0.15 / v0.16 /
//! v0.16.1: `create_file`, `write_file_range`, `truncate_file`,
//! `rename_file`, `delete_file`, plus their read counterparts.
//!
//! Strategy: maintain a `HashMap<String, Vec<u8>>` as the ground-truth
//! "model" of what the vault should contain, then apply a randomly
//! generated sequence of operations to BOTH the model and the vault,
//! verifying after every mutation that the vault state matches the
//! model exactly.
//!
//! NOTE: lives in `src/` as a `#[cfg(test)]` module (not `tests/`) so it
//! compiles against the crate under `cfg(test)` — which selects the fast
//! Argon2id `DEV_PARAMS`. As an external integration test it would link
//! the production-params library and take minutes.

use std::collections::{BTreeSet, HashMap};

use farewell_fido2::MockAuthenticator;
use proptest::collection::vec;
use proptest::prelude::*;
use tempfile::tempdir;

use crate::{Vault, VaultBuilder, CHUNK_PLAINTEXT_LEN};

/// Names are drawn from a small pool so that collisions (create over
/// existing, write to deleted, rename to existing, etc.) actually
/// happen frequently rather than being statistically rare.
const NAMES: &[&str] = &["a", "b", "c", "d", "e"];

/// Total chunks for the test vault.
const TOTAL_CHUNKS: u64 = 96;

/// One operation in the generated sequence.
#[derive(Debug, Clone)]
enum Op {
    Create { name: String },
    Write { name: String, offset: u64, data: Vec<u8> },
    Truncate { name: String, size: u64 },
    Rename { old: String, new: String },
    Delete { name: String },
}

fn arb_name() -> impl Strategy<Value = String> {
    proptest::sample::select(NAMES).prop_map(|s| s.to_string())
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => arb_name().prop_map(|name| Op::Create { name }),
        4 => (arb_name(), 0u64..(3 * CHUNK_PLAINTEXT_LEN as u64), vec(any::<u8>(), 0..(CHUNK_PLAINTEXT_LEN + 50)))
                .prop_map(|(name, offset, data)| Op::Write { name, offset, data }),
        2 => (arb_name(), 0u64..(3 * CHUNK_PLAINTEXT_LEN as u64))
                .prop_map(|(name, size)| Op::Truncate { name, size }),
        1 => (arb_name(), arb_name()).prop_map(|(old, new)| Op::Rename { old, new }),
        1 => arb_name().prop_map(|name| Op::Delete { name }),
    ]
}

/// Apply `op` to both `model` and `vault`, then assert they agree.
fn apply_and_verify(
    op: &Op,
    model: &mut HashMap<String, Vec<u8>>,
    vault: &mut Vault,
) -> Result<(), TestCaseError> {
    match op {
        Op::Create { name } => {
            vault.create_file(name).expect("create_file");
            model.entry(name.clone()).or_insert_with(Vec::new);
        }
        Op::Write { name, offset, data } => {
            if !model.contains_key(name) {
                return Ok(());
            }
            let expected = model.get_mut(name).expect("present");
            let end = (offset + data.len() as u64) as usize;
            if expected.len() < end {
                expected.resize(end, 0);
            }
            expected[*offset as usize..*offset as usize + data.len()].copy_from_slice(data);
            vault
                .write_file_range(name, *offset, data)
                .expect("write_file_range");
        }
        Op::Truncate { name, size } => {
            if !model.contains_key(name) {
                return Ok(());
            }
            let expected = model.get_mut(name).expect("present");
            let new_size = *size as usize;
            if new_size > expected.len() {
                expected.resize(new_size, 0);
            } else {
                expected.truncate(new_size);
            }
            vault.truncate_file(name, *size).expect("truncate_file");
        }
        Op::Rename { old, new } => {
            if !model.contains_key(old) {
                return Ok(());
            }
            if old == new {
                vault.rename_file(old, new).expect("rename_file (no-op)");
                return Ok(());
            }
            let bytes = model.remove(old).expect("present");
            model.insert(new.clone(), bytes);
            vault.rename_file(old, new).expect("rename_file");
        }
        Op::Delete { name } => {
            if !model.contains_key(name) {
                return Ok(());
            }
            model.remove(name);
            vault.delete_file(name).expect("delete_file");
        }
    }

    let actual_names: BTreeSet<String> = vault.list().iter().map(|e| e.name.clone()).collect();
    let model_names: BTreeSet<String> = model.keys().cloned().collect();
    prop_assert_eq!(
        actual_names.clone(),
        model_names.clone(),
        "name-set mismatch after {:?}\n  vault: {:?}\n  model: {:?}",
        op,
        actual_names,
        model_names
    );

    for (name, expected) in model.iter() {
        let actual = vault.read_file(name).expect("read_file");
        prop_assert_eq!(&actual, expected, "content mismatch on {:?} after {:?}", name, op);
        let st = vault.stat_file(name).expect("stat_file");
        prop_assert_eq!(
            st.size as usize,
            expected.len(),
            "stat size mismatch on {:?} after {:?}",
            name,
            op
        );
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn random_ops_preserve_model_invariant(ops in vec(arb_op(), 1..40)) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("p.vault");
        let _ = VaultBuilder::single_passphrase(&path, b"alpha".to_vec())
            .total_chunks(TOTAL_CHUNKS)
            .build()
            .unwrap();
        let mut vault = Vault::open(&path, b"alpha".to_vec(), None::<&mut MockAuthenticator>)
            .unwrap();
        let mut model: HashMap<String, Vec<u8>> = HashMap::new();
        for op in &ops {
            apply_and_verify(op, &mut model, &mut vault)?;
        }
    }
}
