// Minimal end-to-end smoke test of the Rust → Swift bridge.
//
// Calls two extern "C" functions from `libfarewell_mount.a`:
//   - farewell_version() returns a static C string
//   - farewell_chunk_plaintext_len() returns a uint64
//
// If this program prints both values successfully, the Rust staticlib
// is being linked, the symbols are correctly exported, and the C ABI
// is talking to Swift via the systemLibrary module.

import Foundation
import FarewellMountFFI

guard let versionCStr = farewell_version() else {
    print("ERROR: farewell_version() returned NULL")
    exit(1)
}
let version = String(cString: versionCStr)
let chunkLen = farewell_chunk_plaintext_len()

print("Farewell FFI bridge OK")
print("  version              : \(version)")
print("  chunk plaintext len  : \(chunkLen) bytes (\(chunkLen / 1024) KiB)")
