// Smoke test for the v0.18 FFI: open a vault, stat a file, read it.
//
// Usage:
//     FarewellReadDemo <vault-path> <passphrase> <file-name>
//
// Companion bash script `scripts/read-demo.sh` builds a fixture vault
// via the Rust CLI and invokes this binary against it.

import Foundation
import FarewellMountFFI

guard CommandLine.arguments.count == 4 else {
    print("usage: FarewellReadDemo <vault-path> <passphrase> <file-name>")
    exit(2)
}
let vaultPath = CommandLine.arguments[1]
let passphrase = CommandLine.arguments[2]
let fileName = CommandLine.arguments[3]

// ---- Open ----------------------------------------------------------

var handle: OpaquePointer?
let passphraseBytes = Array(passphrase.utf8)
let openStatus = passphraseBytes.withUnsafeBufferPointer { ppBuf in
    farewell_open(
        vaultPath,
        ppBuf.baseAddress,
        UInt64(ppBuf.count),
        &handle
    )
}
guard openStatus == FAREWELL_OK.rawValue, let h = handle else {
    print("farewell_open failed: status=\(openStatus)")
    exit(1)
}
defer { farewell_close(h) }

// ---- Stat ----------------------------------------------------------

var stat = FarewellStat(size: 0)
let statStatus = farewell_stat(h, fileName, &stat)
guard statStatus == FAREWELL_OK.rawValue else {
    print("farewell_stat(\"\(fileName)\") failed: status=\(statStatus)")
    exit(1)
}
print("file        : \(fileName)")
print("size        : \(stat.size) bytes")

// ---- Read the full content via the range API -----------------------

var buf = [UInt8](repeating: 0, count: Int(stat.size))
var actual: UInt64 = 0
let readStatus = buf.withUnsafeMutableBufferPointer { bufPtr in
    farewell_read_range(
        h,
        fileName,
        0,
        UInt64(bufPtr.count),
        bufPtr.baseAddress,
        &actual
    )
}
guard readStatus == FAREWELL_OK.rawValue else {
    print("farewell_read_range failed: status=\(readStatus)")
    exit(1)
}
guard actual == stat.size else {
    print("short read: expected \(stat.size), got \(actual)")
    exit(1)
}
let content = String(decoding: buf, as: UTF8.self)
print("content     : \(content)")
print("Farewell FFI v0.18 read path OK.")
