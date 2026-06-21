// Smoke test for the v0.18 Phase C FFI: readdir + info accessors.
//
// Usage:
//     FarewellInfoDemo <vault-path> <passphrase>
//
// Prints:
//   - the vault's public metadata (total chunks, counter, fingerprint)
//   - one line per file in the mounted level (name + size)
//
// This is the Swift equivalent of `farewell info` + `farewell list`
// combined, going through the FFI rather than calling the Rust CLI.

import Foundation
import FarewellMountFFI

guard CommandLine.arguments.count == 3 else {
    print("usage: FarewellInfoDemo <vault-path> <passphrase>")
    exit(2)
}
let vaultPath = CommandLine.arguments[1]
let passphrase = CommandLine.arguments[2]

// -- open -----------------------------------------------------------

var handle: OpaquePointer?
let passphraseBytes = Array(passphrase.utf8)
let openStatus = passphraseBytes.withUnsafeBufferPointer { pp in
    farewell_open(vaultPath, pp.baseAddress, UInt64(pp.count), &handle)
}
guard openStatus == FAREWELL_OK.rawValue, let h = handle else {
    print("FAIL: farewell_open returned status \(openStatus)")
    exit(1)
}
defer { farewell_close(h) }

// -- vault info -----------------------------------------------------

let totalChunks = farewell_total_chunks(h)

var counter: UInt64 = 0
let counterStatus = farewell_counter(h, &counter)
guard counterStatus == FAREWELL_OK.rawValue else {
    print("FAIL: farewell_counter returned status \(counterStatus)")
    exit(1)
}

var fp = [UInt8](repeating: 0, count: 32)
let fpStatus = fp.withUnsafeMutableBufferPointer { buf in
    farewell_fingerprint(h, buf.baseAddress)
}
guard fpStatus == FAREWELL_OK.rawValue else {
    print("FAIL: farewell_fingerprint returned status \(fpStatus)")
    exit(1)
}
let fingerprintHex = fp.map { String(format: "%02x", $0) }.joined()

print("Vault info")
print("  path          : \(vaultPath)")
print("  total chunks  : \(totalChunks)")
print("  counter       : \(counter)")
print("  fingerprint   : \(fingerprintHex)")

// -- readdir --------------------------------------------------------

// Box a Swift array into a heap-allocated reference so we can pass
// its pointer through the C `void *user_data`.
final class Bag {
    var items: [(name: String, size: UInt64)] = []
}
let bag = Bag()

// Convert Bag → raw pointer for the FFI. `passRetained` increments
// the refcount; we balance it with `release()` after the readdir
// call so the closure can borrow safely without worrying about
// Bag being deallocated mid-callback.
let unmanagedBag = Unmanaged.passRetained(bag)
let bagPtr = unmanagedBag.toOpaque()

// IMPORTANT: declare the callback as an explicitly C-conventioned
// function pointer. A bare inline closure cannot be passed as a
// `@convention(c)` pointer unless we annotate it this way, and
// Swift may otherwise crash at the call boundary by trying to
// dispatch a Swift closure through a C function-pointer slot.
let callback: @convention(c) (
    UnsafePointer<FarewellDirent>?,
    UnsafeMutableRawPointer?
) -> Void = { entryPtr, userData in
    guard let entryPtr = entryPtr, let userData = userData else { return }
    let entry = entryPtr.pointee
    let name = String(cString: entry.name_utf8)
    let bag: Bag = Unmanaged<Bag>.fromOpaque(userData).takeUnretainedValue()
    bag.items.append((name, entry.size))
}

let readdirStatus = farewell_readdir(h, callback, bagPtr)

// Drop the extra retain we added above.
unmanagedBag.release()

guard readdirStatus == FAREWELL_OK.rawValue else {
    print("FAIL: farewell_readdir returned status \(readdirStatus)")
    exit(1)
}

print("")
print("Files (\(bag.items.count))")
if bag.items.isEmpty {
    print("  (none)")
} else {
    for item in bag.items {
        print(String(format: "  %-30@  %12llu bytes", item.name as NSString, item.size))
    }
}

print("")
print("Farewell FFI v0.18 Phase C (readdir + info) OK.")
