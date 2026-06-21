// Smoke test for the v0.18 Phase B FFI: exercise the full mutation
// surface end-to-end through Swift.
//
// Usage:
//     FarewellWriteDemo <vault-path> <passphrase>
//
// Steps:
//   1. open the vault
//   2. create a fresh file "notes.txt"
//   3. write some bytes to it
//   4. read back, verify
//   5. truncate to a shorter size
//   6. read back, verify
//   7. rename to "notes.archived"
//   8. read back, verify
//   9. delete it
//  10. stat → expect NotFound
//  11. close
//
// Exits 0 if every step succeeds.

import Foundation
import FarewellMountFFI

guard CommandLine.arguments.count == 3 else {
    print("usage: FarewellWriteDemo <vault-path> <passphrase>")
    exit(2)
}
let vaultPath = CommandLine.arguments[1]
let passphrase = CommandLine.arguments[2]

// -- helpers --------------------------------------------------------

func checkOK(_ status: Int32, _ context: String) {
    guard status == FAREWELL_OK.rawValue else {
        print("FAIL: \(context) returned status \(status)")
        exit(1)
    }
}

func expectStatus(_ status: Int32, _ expected: FarewellStatus, _ context: String) {
    guard status == expected.rawValue else {
        print("FAIL: \(context) returned \(status), expected \(expected.rawValue)")
        exit(1)
    }
}

func readAll(_ h: OpaquePointer, _ name: String) -> [UInt8] {
    var stat = FarewellStat(size: 0)
    checkOK(farewell_stat(h, name, &stat), "stat(\"\(name)\")")
    var buf = [UInt8](repeating: 0, count: Int(stat.size))
    var actual: UInt64 = 0
    let st = buf.withUnsafeMutableBufferPointer { bufPtr in
        farewell_read_range(
            h, name, 0, UInt64(bufPtr.count),
            bufPtr.baseAddress, &actual
        )
    }
    checkOK(st, "read_range(\"\(name)\")")
    guard actual == stat.size else {
        print("FAIL: short read on \(name): expected \(stat.size), got \(actual)")
        exit(1)
    }
    return buf
}

// -- open -----------------------------------------------------------

var handle: OpaquePointer?
let passphraseBytes = Array(passphrase.utf8)
let openStatus = passphraseBytes.withUnsafeBufferPointer { ppBuf in
    farewell_open(vaultPath, ppBuf.baseAddress, UInt64(ppBuf.count), &handle)
}
checkOK(openStatus, "farewell_open")
guard let h = handle else {
    print("FAIL: open returned OK but null handle")
    exit(1)
}
defer { farewell_close(h) }
print("[1]  opened \(vaultPath)")

// -- create + write -------------------------------------------------

let name = "notes.txt"
checkOK(farewell_create(h, name), "create(\"\(name)\")")
print("[2]  created \"\(name)\"")

let payload = Array("the quick brown fox jumps over the lazy dog\n".utf8)
let writeStatus = payload.withUnsafeBufferPointer { pp in
    farewell_write_range(h, name, 0, pp.baseAddress, UInt64(pp.count))
}
checkOK(writeStatus, "write_range(\"\(name)\")")
print("[3]  wrote \(payload.count) bytes")

let rb1 = readAll(h, name)
guard rb1 == payload else {
    print("FAIL: read after write did not match. expected \(payload.count) bytes, got \(rb1.count)")
    exit(1)
}
print("[4]  read-back matches")

// -- truncate -------------------------------------------------------

let newSize: UInt64 = 19  // "the quick brown fox"
checkOK(farewell_truncate(h, name, newSize), "truncate")
let rb2 = readAll(h, name)
guard rb2 == Array(payload.prefix(Int(newSize))) else {
    print("FAIL: read after truncate did not match.")
    exit(1)
}
print("[5]  truncated to \(newSize) bytes; matches prefix")

// -- rename ---------------------------------------------------------

let renamed = "notes.archived"
checkOK(farewell_rename(h, name, renamed), "rename")
let rb3 = readAll(h, renamed)
guard rb3 == rb2 else {
    print("FAIL: read after rename does not equal pre-rename content.")
    exit(1)
}
print("[6]  renamed \"\(name)\" → \"\(renamed)\"; content preserved")

// -- delete ---------------------------------------------------------

checkOK(farewell_delete(h, renamed), "delete")
var statAfter = FarewellStat(size: 999)
let statStatusAfter = farewell_stat(h, renamed, &statAfter)
expectStatus(statStatusAfter, FAREWELL_NOT_FOUND, "stat after delete")
print("[7]  deleted; stat now returns NotFound")

print("Farewell FFI v0.18 Phase B (write + truncate + rename + delete) OK.")
