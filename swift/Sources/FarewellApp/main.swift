// FarewellApp — v0.19.B.
//
// SwiftUI macOS app: open a vault via the v0.18 FFI, list files,
// preview text/markdown content in-app via a side panel.
//
// Layout: HSplitView with file list (left) + viewer panel (right).
//
// Streaming pattern (cf. THREAT_MODEL §5.10):
//   The viewer reads via `farewell_read_range` in 64 KB chunks
//   rather than slurping the whole file. For text files this is
//   essentially symbolic (one or two iterations), but the
//   discipline matters for PDF/audio/video viewers landing in
//   v0.19.C+, where slurping a 100 MB file would defeat the
//   minimization of plaintext-in-RAM. Establishing the pattern
//   here keeps later viewers honest.
//
// Launch:
//   FarewellApp                            (shows the unlock screen)
//   FarewellApp <vault-path> <passphrase>  (auto-unlocks for dev/test)

import AppKit
import AVFoundation
import IOKit
import IOKit.storage
import PDFKit
import Security
import SwiftUI
import UniformTypeIdentifiers
import FarewellMountFFI

// =============================================================================
// Convenience: bridge Swift Int32 ⇄ FAREWELL_OK (UInt32 raw on Swift import).
// =============================================================================

extension Int32 {
    /// Pre-computed equivalent of `Int32(FAREWELL_OK.rawValue)`,
    /// so callsites can write `status == .ffi_ok`.
    static let ffi_ok: Int32 = Int32(FAREWELL_OK.rawValue)
}

/// Map a `FarewellStatus` code to a user-readable message. Cast at
/// each case label because the C enum imports with UInt32 raw values
/// but our FFI returns are int32_t → Int32.
func humanError(status: Int32) -> String {
    switch status {
    case .ffi_ok:                                            return String(localized: "OK (unexpected)")
    case Int32(FAREWELL_INVALID_ARGUMENT.rawValue):          return String(localized: "Invalid argument")
    case Int32(FAREWELL_NOT_FOUND.rawValue):                 return String(localized: "Not found")
    case Int32(FAREWELL_IO.rawValue):                        return String(localized: "Couldn't read the vault file (missing or unreadable).")
    case Int32(FAREWELL_ALREADY_LOCKED.rawValue):            return String(localized: "This vault is already open in another window or process.")
    case Int32(FAREWELL_WIPED.rawValue):                     return String(localized: "Vault has been wiped — contents unrecoverable")
    // Deniability-safe: a correct passphrase on a key-required vault with
    // no key (or no PIN) also fails here, so we list the things to check
    // without ever revealing whether THIS vault actually needs a key.
    case Int32(FAREWELL_CRYPTO.rawValue):                    return String(localized: "Couldn't open it. Check the passphrase — and, if this vault uses a YubiKey, that it's plugged in and you entered its PIN.")
    case Int32(FAREWELL_HEADER_SIGNATURE_INVALID.rawValue):  return String(localized: "Vault header has been tampered with")
    case Int32(FAREWELL_COUNTER_ROLLBACK.rawValue):          return String(localized: "Counter rollback detected")
    case Int32(FAREWELL_WEAK_PASSPHRASE.rawValue):           return String(localized: "Passphrase too weak — use a stronger or generated one")
    case Int32(FAREWELL_HW_NOT_PRESENT.rawValue):            return String(localized: "No YubiKey detected — plug it in and try again.")
    case Int32(FAREWELL_HW_AUTH_FAILED.rawValue):            return String(localized: "YubiKey check failed — wrong PIN, or it wasn't touched in time.")
    case Int32(FAREWELL_HW_MULTIPLE_KEYS.rawValue):          return String(localized: "More than one key is plugged in. With a PIN, please leave only the key you're unlocking with plugged in (trying a PIN on the wrong key can lock it), then try again.")
    case Int32(FAREWELL_NOT_A_VAULT.rawValue):               return String(localized: "Not a Farewell vault file")
    case Int32(FAREWELL_UNSUPPORTED_VERSION.rawValue):       return String(localized: "Vault uses a format this build cannot read")
    default:                                                  return "Failed (status \(status))"
    }
}

/// Remembers the last folder used to open or create a vault, so the file
/// pickers start there next time. Only the **directory** is stored, never
/// the vault's filename — keeping the persistent trace as small as
/// possible (the folder is part of the surrounding context the user is
/// already responsible for; see THREAT_MODEL §6.9).
enum LastLocation {
    private static let key = "lastVaultDirectory"

    static var directoryURL: URL? {
        guard let p = UserDefaults.standard.string(forKey: key) else { return nil }
        return URL(fileURLWithPath: p, isDirectory: true)
    }

    /// Record the folder containing `fileURL` as the last-used location.
    static func remember(_ fileURL: URL) {
        UserDefaults.standard.set(fileURL.deletingLastPathComponent().path, forKey: key)
    }
}

/// Thread-safe URL accumulator for async drop handlers (NSItemProvider
/// completions fire on arbitrary threads).
final class URLBox: @unchecked Sendable {
    private let lock = NSLock()
    private var urls: [URL] = []
    func add(_ u: URL) { lock.lock(); urls.append(u); lock.unlock() }
    func take() -> [URL] { lock.lock(); defer { lock.unlock() }; return urls }
}

/// Format a byte count for the UI in decimal KB/MB/GB (1000-based), matching
/// what non-technical users see in Finder. The on-disk size is unchanged; only
/// the presentation is decimal so the numbers line up with the OS.
func formatBytes(_ b: UInt64) -> String {
    let f = ByteCountFormatter()
    f.allowedUnits = [.useKB, .useMB, .useGB, .useBytes]
    f.countStyle = .decimal
    return f.string(fromByteCount: Int64(b))
}

/// Map a file name extension to a system symbol used in the file list.
func iconName(for filename: String) -> String {
    let ext = (filename as NSString).pathExtension.lowercased()
    switch ext {
    case "pdf":                                                   return "doc.richtext"
    case "txt", "md", "markdown", "log", "rs", "swift", "py",
         "js", "ts", "sh", "conf", "ini", "toml", "yaml", "yml",
         "json", "xml", "html", "csv":                            return "doc.text"
    case "png", "jpg", "jpeg", "heic", "heif", "webp", "avif", "gif": return "photo"
    case "mp3", "m4a", "wav", "wave", "aac", "flac", "ogg", "oga",
         "opus", "aif", "aiff", "aifc", "caf", "alac":            return "waveform"
    case "mp4", "mov", "m4v", "qt", "webm", "mkv":               return "film"
    default:                                                       return "doc"
    }
}

/// Set every byte of `buf` to zero, in place. Best-effort: this
/// runs before the buffer is dropped so the allocator's free-list
/// receives zeroed memory rather than whatever plaintext lived there.
func secureZero(_ buf: inout [UInt8]) {
    for i in 0..<buf.count {
        buf[i] = 0
    }
}

// =============================================================================
// Secure delete of *source* files (the originals imported from disk)
// =============================================================================

/// The physical nature of the storage backing a path. This is what decides
/// whether an in-place overwrite is a real erase (rotational) or only a
/// best-effort hint (solid state / flash, where wear-leveling can leave the
/// original cells intact).
enum StorageMedium {
    case rotational   // HDD: in-place overwrite physically destroys the data.
    case solidState   // SSD/flash: overwrite is best-effort; no guarantee.
    case unknown      // Couldn't determine — treat conservatively as solidState.
}

/// Determine the storage medium for the volume that holds `url`, via IOKit's
/// "Device Characteristics" → "Medium Type". Returns `.unknown` on any failure
/// (which the caller treats with SSD-grade caution).
func detectStorageMedium(for url: URL) -> StorageMedium {
    var fs = statfs()
    guard statfs(url.path, &fs) == 0 else { return .unknown }
    // f_mntfromname is e.g. "/dev/disk3s1s1".
    let dev = withUnsafeBytes(of: &fs.f_mntfromname) { raw -> String in
        guard let base = raw.baseAddress else { return "" }
        return String(cString: base.assumingMemoryBound(to: CChar.self))
    }
    guard dev.hasPrefix("/dev/") else { return .unknown }
    let bsdName = String(dev.dropFirst("/dev/".count))

    let matching = IOBSDNameMatching(kIOMainPortDefault, 0, bsdName)
    let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
    guard service != IO_OBJECT_NULL else { return .unknown }
    defer { IOObjectRelease(service) }

    // Walk up the parent chain (IOMedia → … → IOBlockStorageDevice) for the
    // physical device's characteristics.
    let opts = IOOptionBits(kIORegistryIterateRecursively | kIORegistryIterateParents)
    guard let prop = IORegistryEntrySearchCFProperty(
        service, kIOServicePlane, "Device Characteristics" as CFString,
        kCFAllocatorDefault, opts
    ) as? [String: Any], let mediumType = prop["Medium Type"] as? String else {
        return .unknown
    }
    switch mediumType {
    case "Solid State": return .solidState
    case "Rotational": return .rotational
    default: return .unknown
    }
}

/// Flush a file descriptor all the way to durable media. Plain `fsync` on macOS
/// does NOT flush the drive's write cache; `F_FULLFSYNC` does. Falls back to a
/// best-effort `fsync` if the filesystem doesn't support it.
func fullFsync(_ fd: Int32) {
    if fcntl(fd, F_FULLFSYNC) == -1 {
        _ = fsync(fd)
    }
}

/// Best-effort hole-punch (deallocation) of the whole file, which on APFS+SSD
/// issues a TRIM/unmap for the underlying blocks so the controller can reclaim
/// (and eventually erase) them. Block-aligned; tolerant of failure.
func punchHole(_ fd: Int32, size: UInt64, blockSize: UInt64) {
    guard size > 0, blockSize > 0 else { return }
    let len = (size / blockSize) * blockSize   // round DOWN to a block boundary
    guard len > 0 else { return }
    var arg = fpunchhole_t(fp_flags: 0, reserved: 0, fp_offset: 0, fp_length: off_t(len))
    _ = fcntl(fd, F_PUNCHHOLE, &arg)
}

/// Run `body` with an array of `FarewellBytes` pointing into the
/// supplied byte arrays, keeping every buffer pinned for the call.
///
/// Swift arrays don't expose a stable pointer outside
/// `withUnsafeBufferPointer`, so we nest one such scope per array
/// recursively; by the time `body` runs, every buffer is pinned.
func withByteSlices<R>(_ arrays: [[UInt8]], _ body: ([FarewellBytes]) -> R) -> R {
    func recurse(_ index: Int, _ acc: [FarewellBytes]) -> R {
        if index == arrays.count {
            return body(acc)
        }
        return arrays[index].withUnsafeBufferPointer { buf in
            var next = acc
            next.append(FarewellBytes(ptr: buf.baseAddress, len: UInt64(buf.count)))
            return recurse(index + 1, next)
        }
    }
    return recurse(0, [])
}

// =============================================================================
// View model — owns the vault handle, the file list, the current selection,
// and the streamed content of the selected file.
// =============================================================================

/// A single long-lived thread with a **stable CFRunLoop** for all FIDO2 /
/// HID work.
///
/// macOS `hidapi` (used by `ctap-hid-fido2`) enumerates devices by
/// scheduling an `IOHIDManager` on the **calling thread's** run loop. On a
/// transient GCD worker thread (`DispatchQueue.global`), that run loop can
/// be torn down or recycled mid-call, which crashes inside
/// `CFRunLoopAddSource` with a pointer-authentication trap. Pinning all HID
/// work to one dedicated run-loop thread removes the race entirely.
final class HIDExecutor: @unchecked Sendable {
    static let shared = HIDExecutor()
    private var cfRunLoop: CFRunLoop!
    private let ready = DispatchSemaphore(value: 0)

    private init() {
        let t = Thread { [self] in
            cfRunLoop = CFRunLoopGetCurrent()
            // An attached port keeps the run loop from exiting when idle.
            RunLoop.current.add(NSMachPort(), forMode: .common)
            ready.signal()
            while !Thread.current.isCancelled {
                RunLoop.current.run(mode: .default, before: .distantFuture)
            }
        }
        t.name = "app.farewell.hid"
        t.qualityOfService = .userInitiated
        t.stackSize = 1 << 21
        t.start()
        ready.wait()
    }

    /// Run `work` on the HID thread without blocking the caller. The HID
    /// thread may then block (e.g. waiting for a key touch) without ever
    /// touching the main thread.
    func async(_ work: @escaping @Sendable () -> Void) {
        CFRunLoopPerformBlock(cfRunLoop, CFRunLoopMode.defaultMode.rawValue, work)
        CFRunLoopWakeUp(cfRunLoop)
    }
}

/// Run `work` on the main thread for a UI update, **waking the main run loop**.
///
/// A plain `DispatchQueue.main.async` only *enqueues* the block. When the app
/// is otherwise idle (no vault open → no timers firing), the main run loop is
/// parked asleep and may not service the main queue until the next input event
/// — so a background unlock that finished seconds ago appears to "hang" until
/// the user happens to click or move the mouse. Forcing a CFRunLoop wake (the
/// same primitive `HIDExecutor` uses for the HID thread) delivers the update
/// immediately, regardless of input. Always pairs the block with a wakeup.
func onMainWake(_ work: @MainActor @escaping () -> Void) {
    // The block runs on the main run loop's thread (the main thread), so the
    // main-actor isolation the closure needs is genuinely satisfied at runtime.
    CFRunLoopPerformBlock(CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue) {
        MainActor.assumeIsolated { work() }
    }
    CFRunLoopWakeUp(CFRunLoopGetMain())
}

@MainActor
final class VaultModel: ObservableObject {
    @Published var isOpen = false
    @Published var error: String?
    @Published var info = VaultInfo()
    @Published var files: [FileEntry] = []
    /// Folder paths (normalized, slash-separated), explicit + implied.
    @Published var folders: [String] = []
    @Published var selectedFileID: String? {
        didSet {
            if oldValue != selectedFileID {
                reloadSelectedContent()
            }
        }
    }
    @Published var selectedContent: ViewerContent?

    /// Set to a file name when that file should open straight into the text
    /// editor (e.g. a just-created note). The viewer consumes and clears it.
    @Published var pendingEditFile: String?

    /// Transient banner shown after an import attempt (success or error).
    @Published var importStatus: String?
    /// Banner shown after a migration (success summary or error).
    @Published var migrationStatus: String?
    /// One-line note shown after creation when the chosen name was already
    /// taken and we created a "-N" variant instead (we never overwrite).
    @Published var renameNotice: String?
    /// The vault's enrolled hardware keys (index + name), loaded by the
    /// keys-management panel via `farewell_key_list` (passphrase, no touch).
    @Published var keys: [KeyInfo] = []
    /// Status/error banner for the keys-management panel.
    @Published var keysStatus: String?
    /// True while a key operation that temporarily closes the open vault
    /// (add/revoke/convert) is in flight. It keeps the unlocked chrome — and
    /// therefore the Keys panel — mounted across the close→reopen cycle, so the
    /// panel hosts the live prompts and the result instead of flashing the
    /// Open/Create screen. Reset in `finishOpen` and on any reopen failure.
    @Published var keyOpInProgress = false
    /// True while the panel is loading the key list (the passphrase KDF can be
    /// slow for a passphrase-only vault), so the panel can show a spinner.
    @Published var keysLoading = false
    /// True only after a SUCCESSFUL key-list read. Distinguishes "loaded and
    /// the vault has no keys" (show the passphrase-only state) from "the read
    /// failed" (show only the error) — an empty `keys` means both otherwise.
    @Published var keysLoaded = false

    /// One enrolled hardware key, as shown in the keys-management panel.
    struct KeyInfo: Identifiable, Hashable {
        let index: Int
        let name: String
        var id: Int { index }
    }
    /// A leftover `.<name>.migrating` from an interrupted migration, surfaced
    /// so the user can discard it. The source vault is always intact.
    @Published var staleMigration: URL?
    /// Whether to securely overwrite + delete the source file after a
    /// successful import. OFF by default — deleting the user's original
    /// is destructive, and on SSDs the overwrite cannot guarantee
    /// physical erasure (honest caveat shown in the UI tooltip).
    @Published var shredOriginalsAfterImport = false
    /// Number of overwrite passes when shredding source originals. 1 is enough
    /// on any modern medium; 3/7 exist only for threat models / standards that
    /// mandate them (no real benefit on contemporary HDDs, none on SSDs).
    @Published var shredPasses: Int = 1
    /// True while a blocking hardware-key operation runs off the main
    /// thread (enroll / unlock). Drives the touch-your-key overlay.
    @Published var busy = false
    @Published var busyMessage = ""
    /// True while the overlay is waiting on the USER's key (insert / remove /
    /// touch) — drives the key icon. False while the app is *computing* (KDF,
    /// write, re-secure) — drives the gear icon. Decoupled from `progress` so a
    /// long indeterminate compute (e.g. the KDF after a touch) still shows the
    /// gear, not a stale "touch your key" symbol.
    @Published var busyIsKeyStep = false
    /// Determinate progress 0…1 (e.g. vault write), or nil for an
    /// indeterminate spinner (e.g. awaiting a key touch).
    @Published var progress: Double? = nil

    // Progress is decoupled from the worker thread: the FFI callback (any
    // thread) just stores the LATEST value under a lock; a steady main-
    // thread timer renders it at ~12 fps. Pushing each update via
    // DispatchQueue.main.async instead let the tight Rust write loop starve
    // the render (bar froze mid-write). The timer renders independently.
    private let progressLock = NSLock()
    /// Ordered queue of progress events from the worker thread. A QUEUE (not a
    /// single slot) so back-to-back events are never coalesced away: e.g. when
    /// the key is already plugged in, the core fires AWAIT_INSERT then
    /// AWAIT_TOUCH within one timer tick — the INSERT sets enrollKeyIndex/Total
    /// that the TOUCH prompt reads, so it must not be dropped.
    nonisolated(unsafe) private var pendingProgress: [(phase: UInt32, done: UInt64, total: UInt64)] = []
    /// The last event applied, re-applied on idle ticks so time-estimated bars
    /// keep animating even when no new event has arrived.
    private var lastProgress: (phase: UInt32, done: UInt64, total: UInt64)?
    private var progressTimer: Timer?
    /// Drives the *estimated* unlock bar (Argon2id reports no real progress).
    private var unlockTimer: Timer?
    /// When the convert/remove-last "re-securing" phase began, so its estimated
    /// bar can advance with elapsed time (that phase reports no real progress).
    private var writingEstimateStart: Date?
    /// Switches the progress wording between vault creation and migration.
    var progressIsMigration = false
    /// Which one-port-swap enrollment is running, so the insert/remove/touch
    /// prompts can name the right key ("your current key" vs "the new backup").
    enum EnrollFlow { case none, creation, backup, removal }
    var enrollFlow: EnrollFlow = .none
    /// True while the `.backup` flow is adding the FIRST hardware key to a
    /// passphrase-only vault (there is no current key to touch first), so the
    /// progress/result wording says "hardware key" instead of "backup key".
    var enrollIsFirstKey = false
    /// Key currently being inserted/touched (1-based) and the total in this
    /// enrollment, taken from the latest AWAIT_INSERT/REMOVE callback.
    var enrollKeyIndex = 0
    var enrollKeyTotal = 0

    /// Banner shown on the unlock screen after an automatic lock, so the user
    /// understands why they're back at the passphrase prompt.
    @Published var autoLockNotice: String?
    private var idleTimer: Timer?

    init() {
        // 5-minute idle default; the Settings window lets the user change it.
        UserDefaults.standard.register(defaults: ["autoLockMinutes": 5])
        setupAutoLock()
    }

    // MARK: - Auto-lock

    /// Lock the open vault on system sleep, screen lock, and (configurable)
    /// inactivity, so an unattended Mac doesn't leave a decrypted vault open.
    private func setupAutoLock() {
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.autoLock(reason: String(localized: "sleep")) }
        DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in self?.autoLock(reason: String(localized: "screen lock")) }
        // Poll inactivity — a cheap IORegistry read, and it avoids the
        // Input-Monitoring permission prompt a global event tap would trigger.
        let t = Timer(timeInterval: 15, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.checkIdle() }
        }
        RunLoop.main.add(t, forMode: .common)
        idleTimer = t
    }

    private func checkIdle() {
        guard isOpen else { return }
        let minutes = UserDefaults.standard.integer(forKey: "autoLockMinutes")
        guard minutes > 0 else { return }   // 0 = never
        if systemIdleSeconds() >= Double(minutes * 60) {
            autoLock(reason: String(localized: "inactivity"))
        }
    }

    /// Lock now if a vault is open and no key operation is in flight.
    func autoLock(reason: String) {
        guard isOpen, !busy else { return }
        close()
        autoLockNotice = String(localized: "Vault locked automatically (\(reason)). Unlock to continue.")
    }

    /// Seconds since the last system-wide user input, via IOHIDSystem — needs
    /// no special permission (unlike a global event tap).
    private func systemIdleSeconds() -> TimeInterval {
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(
            kIOMainPortDefault, IOServiceMatching("IOHIDSystem"), &iterator
        ) == KERN_SUCCESS else { return 0 }
        defer { IOObjectRelease(iterator) }
        let entry = IOIteratorNext(iterator)
        guard entry != 0 else { return 0 }
        defer { IOObjectRelease(entry) }
        var unmanaged: Unmanaged<CFMutableDictionary>?
        guard IORegistryEntryCreateCFProperties(entry, &unmanaged, kCFAllocatorDefault, 0) == KERN_SUCCESS,
              let props = unmanaged?.takeRetainedValue() as? [String: Any] else { return 0 }
        if let ns = props["HIDIdleTime"] as? UInt64 { return TimeInterval(ns) / 1_000_000_000 }
        if let ns = props["HIDIdleTime"] as? Int64 { return TimeInterval(ns) / 1_000_000_000 }
        return 0
    }

    /// Called from any thread (incl. the C progress callback on the HID
    /// thread) with the most recent progress. Cheap: just stores it under
    /// the lock; the main-thread timer does the UI work.
    nonisolated func reportProgress(phase: UInt32, done: UInt64, total: UInt64) {
        progressLock.lock()
        pendingProgress.append((phase, done, total))
        progressLock.unlock()
    }

    /// Begin rendering reported progress (call on the main thread before
    /// dispatching the worker).
    func startProgressUpdates() {
        pendingProgress = []
        lastProgress = nil
        enrollFlow = .none
        enrollIsFirstKey = false
        enrollKeyIndex = 0
        enrollKeyTotal = 0
        busyIsKeyStep = false
        writingEstimateStart = nil
        progressTimer?.invalidate()
        let t = Timer(timeInterval: 0.08, repeats: true) { [weak self] _ in
            // Added to RunLoop.main below, so this fires on the main actor.
            MainActor.assumeIsolated { self?.applyLatestProgress() }
        }
        // .common so it keeps firing during run-loop activity.
        RunLoop.main.add(t, forMode: .common)
        progressTimer = t
    }

    /// Stop rendering progress (call on the main thread when the worker
    /// finishes).
    func stopProgressUpdates() {
        progressTimer?.invalidate()
        progressTimer = nil
    }

    /// Animate an *estimated* unlock bar. The passphrase KDF (Argon2id) is one
    /// atomic call with no progress callback, so a faithful 0→100 % bar is
    /// impossible — instead we ease toward 95 % over a typical duration and let
    /// the real completion snap it to 100 %. On a slower machine it simply
    /// pauses near the end (honest: it never claims "done" before it is).
    func startUnlockEstimate() {
        let start = Date()
        let estimate = 4.0   // ~Argon2id (1 GiB) on Apple Silicon; just a guess
        progress = 0
        busyIsKeyStep = false
        unlockTimer?.invalidate()
        let t = Timer(timeInterval: 0.08, repeats: true) { [weak self] _ in
            // Added to RunLoop.main below, so this fires on the main actor.
            MainActor.assumeIsolated {
                let frac = Date().timeIntervalSince(start) / estimate
                self?.progress = min(0.95, frac * 0.95)
            }
        }
        RunLoop.main.add(t, forMode: .common)
        unlockTimer = t
    }

    /// Stop the estimated unlock bar (call on the main thread at completion).
    func stopUnlockEstimate() {
        unlockTimer?.invalidate()
        unlockTimer = nil
    }

    private func applyLatestProgress() {
        progressLock.lock()
        let events = pendingProgress
        pendingProgress.removeAll()
        progressLock.unlock()
        if events.isEmpty {
            // No new event this tick: re-apply the last one so time-estimated
            // bars keep animating (re-applying static prompts is idempotent).
            if let last = lastProgress { applyProgress(last) }
            return
        }
        // Apply every event IN ORDER so side-effects (e.g. AWAIT_INSERT setting
        // enrollKeyIndex/Total) land before later events that depend on them.
        for p in events { applyProgress(p) }
        lastProgress = events.last
    }

    private func applyProgress(_ p: (phase: UInt32, done: UInt64, total: UInt64)) {
        switch p.phase {
        case FAREWELL_PROGRESS_AWAIT_INSERT:
            enrollKeyIndex = Int(p.done)
            enrollKeyTotal = Int(p.total)
            busyMessage = insertPrompt()
            busyIsKeyStep = true   // waiting on the user's key → key icon
            progress = nil
        case FAREWELL_PROGRESS_AWAIT_REMOVE:
            enrollKeyIndex = Int(p.done)
            enrollKeyTotal = Int(p.total)
            busyMessage = removePrompt()
            busyIsKeyStep = true
            progress = nil
        case FAREWELL_PROGRESS_AWAIT_TOUCH:   // 0
            busyMessage = touchPrompt(touch: p.done, of: p.total)
            busyIsKeyStep = true
            progress = nil
        case FAREWELL_PROGRESS_MIGRATE_COPY where progressIsMigration:
            busyMessage = String(localized: "Copying files into the new vault…")
            busyIsKeyStep = false   // computing → gear icon
            progress = p.total > 0 ? Double(p.done) / Double(p.total) : nil
        case FAREWELL_PROGRESS_MIGRATE_VERIFY where progressIsMigration:
            busyMessage = String(localized: "Verifying the new vault…")
            busyIsKeyStep = false
            progress = p.total > 0 ? Double(p.done) / Double(p.total) : nil
        default:   // FAREWELL_PROGRESS_WRITING (and any fallback)
            // After the touch, the convert/remove-last flow re-derives the heavy
            // KDF + re-opens — pure computation, so the gear icon and a
            // "re-securing" message (not "touch your key").
            busyMessage = progressIsMigration ? String(localized: "Preparing the new vault…")
                : enrollFlow == .removal ? String(localized: "Removing the key — re-securing the vault…")
                : enrollFlow == .backup ? (enrollIsFirstKey
                    ? String(localized: "Adding your hardware key…")
                    : String(localized: "Adding your backup key…"))
                : String(localized: "Creating your Farewell vault…")
            busyIsKeyStep = false
            if p.total > 0 {
                // Real, countable work (vault creation writes N chunks).
                progress = Double(p.done) / Double(p.total)
            } else {
                // Atomic KDF work (convert / remove-last re-secure): two heavy
                // Argon2id derivations with no measurable internal progress, so
                // animate an *estimated* bar over the typical duration and let
                // completion clear it. Honest: it eases to 95 % and pauses there
                // rather than ever claiming done early.
                let start = writingEstimateStart ?? Date()
                writingEstimateStart = start
                let frac = Date().timeIntervalSince(start) / 7.0   // ~2× heavy KDF
                progress = min(0.95, frac * 0.95)
            }
        }
    }

    /// "Insert key N…" prompt, named per flow. Keys are enrolled one at a time
    /// on a single USB port, so only one is ever connected — the touch is
    /// always unambiguously the right key (no reliance on a blink).
    private func insertPrompt() -> String {
        switch enrollFlow {
        case .backup:
            if enrollKeyTotal <= 1 { return String(localized: "Insert your YubiKey…") }
            return enrollKeyIndex == 1
                ? String(localized: "Insert your CURRENT key (the one that already opens this vault)…")
                : String(localized: "Now insert the NEW backup key…")
        case .creation:
            return enrollKeyTotal > 1
                ? String(localized: "Insert key \(enrollKeyIndex) of \(enrollKeyTotal)…")
                : String(localized: "Insert your YubiKey…")
        case .removal:
            return String(localized: "Insert the key you're removing…")
        case .none:
            return String(localized: "Insert your YubiKey…")
        }
    }

    private func removePrompt() -> String {
        switch enrollFlow {
        case .backup:
            return String(localized: "Remove your current key, then insert the NEW backup key…")
        default:
            return String(localized: "Remove that key, then insert the next one…")
        }
    }

    private func touchPrompt(touch: UInt64, of total: UInt64) -> String {
        let suffix = total > 1 ? String(localized: " — touch \(Int(touch)) of \(Int(total))") : ""
        let lead: String
        switch enrollFlow {
        case .creation:
            lead = enrollKeyTotal > 1
                ? String(localized: "Key \(enrollKeyIndex) of \(enrollKeyTotal): touch it now")
                : String(localized: "Touch your YubiKey now")
        case .backup:
            if enrollIsFirstKey {
                // Adding the FIRST key (no current key to touch first).
                lead = String(localized: "Touch your new key now")
            } else if enrollKeyTotal > 1 && enrollKeyIndex == 1 {
                lead = String(localized: "Touch your CURRENT key now — not the new one yet")
            } else {
                lead = String(localized: "Touch the new backup key now")
            }
        case .removal:
            lead = String(localized: "Touch the key to remove it")
        case .none:
            lead = String(localized: "Touch your YubiKey now")
        }
        return lead + suffix
    }

    /// Opaque handle to the open vault. `nil` when locked.
    private var handle: OpaquePointer?

    struct VaultInfo {
        var path = ""
        var totalChunks: UInt64 = 0
        var counter: UInt64 = 0
        var fingerprintHex = ""
        /// Usable / free capacity of the open level, in plaintext bytes.
        var spaceTotal: UInt64 = 0
        var spaceFree: UInt64 = 0
        /// Hardware keys enrolled on this vault (0 = passphrase-only).
        var hwKeys: Int = 0
        /// Opt-in creator identity recorded at create time ("" = anonymous).
        var owner: String = ""
    }

    /// `id == name` so selection survives a `refreshFiles()` call
    /// (UUID-based ids would change every refresh).
    struct FileEntry: Identifiable, Hashable {
        let name: String
        let size: UInt64
        var id: String { name }
    }

    /// Decoded content payload of the currently-selected file. The
    /// enum forces the view layer to branch on type, which is also
    /// where future viewers (audio/video) will plug in.
    ///
    /// Not `Equatable`: it carries `Data` payloads (PDF/image) that we
    /// don't want to memcmp on every SwiftUI diff, and `@Published`
    /// does not require it.
    enum ViewerContent {
        /// Plain UTF-8 text; render with monospaced font.
        case text(String)
        /// Markdown source; render via `AttributedString(markdown:)`.
        case markdown(String)
        /// PDF bytes, handed to Apple's PDFKit in-memory (no disk trace,
        /// no QuickLook, no third-party C++ parser — see commit notes).
        case pdf(Data)
        /// Raster image bytes, decoded by AppKit's NSImage in-memory.
        case image(Data)
        /// Audio bytes, streamed to AVAudioEngine via our Rust (Symphonia)
        /// decoder — decoded in RAM, never written to disk.
        case audio(Data)
        /// Video bytes (+ extension), played by AVPlayer fed from RAM via a
        /// custom resource loader. Rendered in our own AVPlayerLayer — never
        /// AVKit/QuickTime, never a file URL, never on disk.
        case video(Data, String)
        /// Recognized extension but content wasn't decodable.
        case unsupported(reason: String)
        /// Read or stat failed during the streaming load.
        case loadFailed(reason: String)
    }

    /// Selected file, derived from `selectedFileID`.
    var selectedFile: FileEntry? {
        guard let id = selectedFileID else { return nil }
        return files.first(where: { $0.id == id })
    }

    // -- Passphrase strength + generation ----------------------------

    /// zxcvbn score (0–4) of `pw`, via the same estimator the core
    /// enforces at creation (4 is required). Returns 0 on any error.
    func passphraseScore(_ pw: String) -> Int {
        if pw.isEmpty { return 0 }
        let bytes = Array(pw.utf8)
        var score: UInt8 = 0
        let st = bytes.withUnsafeBufferPointer { buf in
            farewell_passphrase_score(buf.baseAddress, UInt64(buf.count), &score)
        }
        return st == .ffi_ok ? Int(score) : 0
    }

    /// Generate a strong EFF-diceware passphrase (10 words ≈ 129 bits) via
    /// the Rust core's CSPRNG. Returns nil on failure.
    func generatePassphrase() -> String? {
        final class Box { var s: String? }
        let box = Box()
        let ud = Unmanaged.passUnretained(box).toOpaque()
        let cb: @convention(c) (
            UnsafePointer<CChar>?,
            UnsafeMutableRawPointer?
        ) -> Void = { ptr, ud in
            guard let ptr = ptr, let ud = ud else { return }
            Unmanaged<Box>.fromOpaque(ud).takeUnretainedValue().s = String(cString: ptr)
        }
        let st = farewell_generate_passphrase(0, cb, ud)
        return st == .ffi_ok ? box.s : nil
    }

    // -- Lifecycle ----------------------------------------------------

    /// Open the vault with its passphrase (passphrase-only, no hardware
    /// key). For vaults that require a YubiKey, use `openHw`.
    func open(path: String, passphrase: String) {
        error = nil
        var h: OpaquePointer?
        let bytes = Array(passphrase.utf8)
        let status = bytes.withUnsafeBufferPointer { pp in
            farewell_open(path, pp.baseAddress, UInt64(pp.count), &h)
        }
        guard status == .ffi_ok, let handle = h else {
            error = humanError(status: status)
            return
        }
        finishOpen(handle: handle, path: path)
    }

    /// Open a vault, threading a connected YubiKey only if the vault actually
    /// needs one. Runs the (Argon2id-slow, possibly touch-blocking) FFI off the
    /// main thread behind the `busy` overlay.
    ///
    /// Two stages, so the overlay can show the *right* feedback without ever
    /// revealing — on a wrong passphrase — whether the vault uses a key:
    ///  1. `farewell_open` (passphrase-only, no USB, no touch). A passphrase-
    ///     only vault OPENS here, and the estimated bar matches its KDF wait.
    ///  2. Only if stage 1 reports `HwNotPresent` (correct passphrase, key
    ///     required) do we switch to a "touch your key" prompt and retry with
    ///     `farewell_open_hw`. A wrong passphrase yields `Crypto` in stage 1 —
    ///     same as a passphrase-only vault — so no touch prompt ever appears
    ///     for a bad passphrase (deniability preserved).
    func openHw(path: String, passphrase: String, pin: String) {
        error = nil
        busyMessage = String(localized: "Unlocking…\nThis takes a few seconds.")
        busy = true
        // The stage-1 wait is dominated by the passphrase KDF (Argon2id), which
        // gives no real progress — show an *estimated* bar that eases toward
        // 95 % and snaps to 100 % when the open finishes.
        startUnlockEstimate()
        let pp = Array(passphrase.utf8)
        let pn = Array(pin.utf8)
        // Runs on the dedicated HID run-loop thread (see HIDExecutor): the
        // FFI enumerates the YubiKey via hidapi, which is unsafe on a
        // transient GCD worker thread. Each hop back to the main thread uses
        // onMainWake so the finished work is delivered immediately (a plain
        // DispatchQueue.main.async would sit in the queue until the next click).
        HIDExecutor.shared.async {
            // ----- Stage 1: passphrase-only (no key, no touch) -----
            var h: OpaquePointer?
            let s1 = pp.withUnsafeBufferPointer { ppb in
                farewell_open(path, ppb.baseAddress, UInt64(ppb.count), &h)
            }
            if s1 == .ffi_ok, let handle = h {
                onMainWake {
                    self.stopUnlockEstimate(); self.progress = 1; self.busy = false
                    self.finishOpen(handle: handle, path: path)
                }
                return
            }
            // Anything other than "this vault needs a key" is a final result
            // (wrong passphrase, tamper, …) — report it without a key prompt.
            guard s1 == Int32(FAREWELL_HW_NOT_PRESENT.rawValue) else {
                onMainWake {
                    self.stopUnlockEstimate(); self.busy = false
                    self.keyOpInProgress = false
                    self.error = humanError(status: s1)
                }
                return
            }

            // ----- Stage 2: a key MIGHT be required. Don't pre-show the touch
            // prompt — the engine emits AWAIT_TOUCH only once it has passed every
            // fast refusal (wrong passphrase / no key / multiple keys), so the
            // prompt never flashes for a refusal that needs no touch. Until then
            // the estimated bar keeps running.
            let touchCb: @convention(c) (UInt32, UInt64, UInt64, UnsafeMutableRawPointer?) -> Void = {
                phase, _, _, ud in
                guard phase == FAREWELL_PROGRESS_AWAIT_TOUCH, let ud = ud else { return }
                let model = Unmanaged<VaultModel>.fromOpaque(ud).takeUnretainedValue()
                onMainWake {
                    model.stopUnlockEstimate()
                    model.progress = nil            // indeterminate: waiting on a touch
                    model.busyIsKeyStep = true      // key icon
                    model.busyMessage = String(localized: "Touch your key now — it should be blinking.")
                }
            }
            let ud = Unmanaged.passUnretained(self).toOpaque()
            var h2: OpaquePointer?
            let s2 = pp.withUnsafeBufferPointer { ppb in
                pn.withUnsafeBufferPointer { pnb in
                    farewell_open_hw(
                        path,
                        ppb.baseAddress, UInt64(ppb.count),
                        pnb.baseAddress, UInt64(pnb.count),
                        touchCb, ud,
                        &h2)
                }
            }
            onMainWake {
                self.stopUnlockEstimate()
                self.busy = false
                guard s2 == .ffi_ok, let handle = h2 else {
                    self.keyOpInProgress = false
                    self.error = humanError(status: s2)
                    return
                }
                self.finishOpen(handle: handle, path: path)
            }
        }
    }

    /// Create a single-domain vault, optionally enrolling `hwKeys`
    /// YubiKey credentials. Runs off the main thread behind the `busy`
    /// overlay (enrollment blocks on a touch). On success, opens it.
    func createVaultHw(
        path: String,
        passphrase: String,
        totalChunks: UInt64,
        hwKeys: UInt32,
        pin: String,
        owner: String? = nil
    ) {
        error = nil
        guard !passphrase.isEmpty else {
            error = "Enter a passphrase."
            return
        }
        let nonEmpty = [passphrase]
        busyMessage = hwKeys > 0
            ? String(localized: "Enrolling your key…")
            : String(localized: "Creating vault…")
        progress = nil
        busy = true
        startProgressUpdates()
        if hwKeys > 0 { enrollFlow = .creation }   // names the swap prompts
        let byteArrays = nonEmpty.map { Array($0.utf8) }
        let pn = Array(pin.utf8)
        // Dedicated HID run-loop thread (see HIDExecutor): enrollment
        // enumerates the YubiKey via hidapi, unsafe on a GCD worker thread.
        HIDExecutor.shared.async {
            // Progress callback: distinct per-touch prompts, then a REAL
            // bar for the file write.
            let progressCb: @convention(c) (UInt32, UInt64, UInt64, UnsafeMutableRawPointer?) -> Void = { phase, done, total, ud in
                guard let ud = ud else { return }
                Unmanaged<VaultModel>.fromOpaque(ud)
                    .takeUnretainedValue()
                    .reportProgress(phase: phase, done: done, total: total)
            }
            let progressUd = Unmanaged.passUnretained(self).toOpaque()
            var h: OpaquePointer?
            // Trimmed opt-in owner; nil/empty → anonymous (engine records none).
            let ownerArg = owner?.trimmingCharacters(in: .whitespacesAndNewlines)
            let status = withByteSlices(byteArrays) { slices in
                slices.withUnsafeBufferPointer { buf in
                    pn.withUnsafeBufferPointer { pnb in
                        let runCreate: (UnsafePointer<CChar>?) -> Int32 = { ownerPtr in
                            farewell_create_vault_hw(
                                path,
                                totalChunks,
                                buf.baseAddress,
                                UInt64(buf.count),
                                hwKeys,
                                pnb.baseAddress,
                                UInt64(pnb.count),
                                ownerPtr,
                                &h,
                                progressCb,
                                progressUd)
                        }
                        if let o = ownerArg, !o.isEmpty {
                            return o.withCString { runCreate($0) }
                        }
                        return runCreate(nil)
                    }
                }
            }
            DispatchQueue.main.async {
                self.stopProgressUpdates()
                self.busy = false
                self.progress = nil
                guard status == .ffi_ok, let handle = h else {
                    self.error = "Could not create vault: \(humanError(status: status))"
                    return
                }
                // The vault comes back ALREADY OPEN (primary level mounted
                // at creation) — no re-open, so no extra YubiKey touch.
                self.finishOpen(handle: handle, path: path)
            }
        }
    }

    /// Shared post-open setup: record handle + vault info, list files.
    private func finishOpen(handle: OpaquePointer, path: String) {
        self.handle = handle
        self.keyOpInProgress = false   // close→reopen cycle (if any) is done
        self.info.path = path
        self.autoLockNotice = nil   // clear any "locked automatically" banner
        // Remember the folder so the pickers start there next time (covers
        // typed paths too, not just the file panels).
        LastLocation.remember(URL(fileURLWithPath: path))
        self.info.totalChunks = farewell_total_chunks(handle)

        var c: UInt64 = 0
        if farewell_counter(handle, &c) == .ffi_ok {
            self.info.counter = c
        }

        var hk: UInt32 = 0
        self.info.hwKeys = farewell_hw_key_count(handle, &hk) == .ffi_ok ? Int(hk) : 0

        // Opt-in creator identity, if one was recorded at create time.
        var olen: UInt64 = 0
        var obuf = [CChar](repeating: 0, count: 512)
        if farewell_owner(handle, &obuf, UInt64(obuf.count), &olen) == .ffi_ok, olen > 0 {
            self.info.owner = String(cString: obuf)
        } else {
            self.info.owner = ""
        }

        var fp = [UInt8](repeating: 0, count: 32)
        let fpStatus = fp.withUnsafeMutableBufferPointer { buf in
            farewell_fingerprint(handle, buf.baseAddress)
        }
        if fpStatus == .ffi_ok {
            self.info.fingerprintHex = fp.map { String(format: "%02x", $0) }.joined()
        }

        refreshFiles()
        refreshFolders()
        refreshSpace()
        isOpen = true

        // Surface a leftover temp from an interrupted migration (the source —
        // this vault — was never modified, so the user is safe either way).
        let url = URL(fileURLWithPath: path)
        let leftover = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).migrating")
        staleMigration = FileManager.default.fileExists(atPath: leftover.path) ? leftover : nil
    }

    /// Discard a leftover interrupted-migration temp file.
    func discardStaleMigration() {
        if let url = staleMigration {
            try? FileManager.default.removeItem(at: url)
            staleMigration = nil
        }
    }

    func close() {
        // Clear selection and decrypted content BEFORE closing the
        // handle, so any future read attempts hit `nil` handle
        // rather than UAF.
        selectedFileID = nil
        selectedContent = nil
        if let h = handle {
            farewell_close(h)
            handle = nil
        }
        isOpen = false
        files.removeAll()
        info = VaultInfo()
        renameNotice = nil
    }

    // -- Migration (crypto-agility / rotation) ------------------------

    /// Destination capacity for a migration.
    enum MigrateCapacity {
        case same    // keep the source's capacity (≈ same file size)
        case shrink  // shrink to just fit the contents (+ margin)
    }

    /// Estimated bytes the destination vault will occupy, for the space
    /// pre-flight. `.same` ≈ the current file size; `.shrink` ≈ used + 30%.
    func estimatedNewVaultBytes(_ capacity: MigrateCapacity) -> UInt64 {
        switch capacity {
        case .same:
            let attrs = try? FileManager.default.attributesOfItem(atPath: info.path)
            return (attrs?[.size] as? NSNumber)?.uint64Value ?? info.spaceTotal
        case .shrink:
            let used = info.spaceTotal > info.spaceFree ? info.spaceTotal - info.spaceFree : 0
            // +30% headroom, +16 MiB floor, plus chunk/AEAD overhead slack.
            let est = max(UInt64(Double(used) * 1.3), used + 16 * 1024 * 1024)
            return max(est, 16 * 1024 * 1024)
        }
    }

    /// Free space (bytes) available for important use on the volume of `dir`.
    func freeBytes(at dir: URL) -> UInt64 {
        let vals = try? dir.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        if let v = vals?.volumeAvailableCapacityForImportantUsage, v >= 0 {
            return UInt64(v)
        }
        return UInt64.max // unknown → don't block (the migration still verifies)
    }

    /// Re-encrypt the open vault into a fresh file in `destDir` and switch to
    /// it. The source is opened read-only by the engine and only replaced
    /// (atomic rename) after the new vault is built **and verified**; on any
    /// failure the original is reopened so the user is never locked out.
    ///
    /// When `destDir` is the source's own folder, the old file is renamed to
    /// `<name>.bak` (kept until the user deletes it). When it's a different
    /// folder/drive, a new file is written there and the original is left in
    /// place. A hard space pre-flight refuses to start if the destination
    /// can't hold the new vault.
    func migrate(capacity: MigrateCapacity, destDir: URL, passphrase: String, useHw: Bool, pin: String) {
        migrationStatus = nil
        error = nil
        guard !passphrase.isEmpty else {
            migrationStatus = "Enter your passphrase to migrate."
            return
        }
        let srcPath = info.path
        let srcURL = URL(fileURLWithPath: srcPath)
        let name = srcURL.lastPathComponent
        let srcDir = srcURL.deletingLastPathComponent()
        let sameFolder = destDir.standardizedFileURL == srcDir.standardizedFileURL

        // Pre-flight: never start a migration the destination can't hold.
        let needed = estimatedNewVaultBytes(capacity)
        let free = freeBytes(at: destDir)
        if needed > free {
            migrationStatus = String(localized: "Not enough space on \(destDir.lastPathComponent): the new vault needs about \(formatBytes(needed)) but only \(formatBytes(free)) is free. Choose “Shrink to fit” or a different drive.")
            return
        }
        // Refuse to overwrite an existing file when migrating to another folder.
        let finalDst = sameFolder ? srcURL : destDir.appendingPathComponent(name)
        if !sameFolder, FileManager.default.fileExists(atPath: finalDst.path) {
            migrationStatus = String(localized: "A file named “\(name)” already exists in that folder. Pick another destination.")
            return
        }
        let tempDst = destDir.appendingPathComponent(".\(name).migrating")
        try? FileManager.default.removeItem(at: tempDst) // clear any stale temp

        let capCode: UInt64 = (capacity == .shrink) ? UInt64.max : 0
        let pp = Array(passphrase.utf8)
        let pn = Array(pin.utf8)
        let hwKeys: UInt32 = useHw ? 1 : 0

        // Close our handle so the engine can open the source (releases the lock).
        close()
        busyMessage = useHw
            ? String(localized: "Migrating… touch your YubiKey when it blinks.")
            : String(localized: "Preparing the new vault…")
        progress = nil
        progressIsMigration = true
        busy = true
        startProgressUpdates()

        HIDExecutor.shared.async {
            let progressCb: @convention(c) (UInt32, UInt64, UInt64, UnsafeMutableRawPointer?) -> Void = { phase, done, total, ud in
                guard let ud = ud else { return }
                Unmanaged<VaultModel>.fromOpaque(ud).takeUnretainedValue()
                    .reportProgress(phase: phase, done: done, total: total)
            }
            let ud = Unmanaged.passUnretained(self).toOpaque()
            let status = pp.withUnsafeBufferPointer { ppb in
                pn.withUnsafeBufferPointer { pnb in
                    farewell_migrate(
                        srcPath,
                        tempDst.path,
                        ppb.baseAddress, UInt64(ppb.count),
                        hwKeys,
                        pnb.baseAddress, UInt64(pnb.count),
                        capCode,
                        progressCb, ud)
                }
            }
            DispatchQueue.main.async {
                self.stopProgressUpdates()
                self.busy = false
                self.progress = nil
                self.progressIsMigration = false

                guard status == .ffi_ok else {
                    // Engine failed: discard the temp, reopen the untouched source.
                    try? FileManager.default.removeItem(at: tempDst)
                    self.migrationStatus = String(localized: "Migration failed: \(humanError(status: status)). Your original vault is unchanged.")
                    self.reopenAfterMigration(path: srcPath, passphrase: passphrase, useHw: useHw, pin: pin)
                    return
                }

                // Engine succeeded + verified. Put the new vault in place.
                let fm = FileManager.default
                do {
                    if sameFolder {
                        let bak = srcDir.appendingPathComponent(".\(name).bak")
                        try? fm.removeItem(at: bak)
                        try fm.moveItem(at: srcURL, to: bak)     // keep the old, just in case
                        try fm.moveItem(at: tempDst, to: srcURL) // new takes the original name
                        self.migrationStatus = String(localized: "Migrated. The previous vault is kept as “\(bak.lastPathComponent)” — delete it once you’ve confirmed this one works.")
                    } else {
                        try fm.moveItem(at: tempDst, to: finalDst)
                        self.migrationStatus = String(localized: "Migrated to \(finalDst.path). Your original vault is unchanged — delete it when ready.")
                    }
                } catch {
                    try? fm.removeItem(at: tempDst)
                    self.migrationStatus = String(localized: "Migration verified but the file swap failed: \(error.localizedDescription). Your original vault is unchanged.")
                    self.reopenAfterMigration(path: srcPath, passphrase: passphrase, useHw: useHw, pin: pin)
                    return
                }
                // Open the freshly-migrated vault.
                self.reopenAfterMigration(path: finalDst.path, passphrase: passphrase, useHw: useHw, pin: pin)
            }
        }
    }

    /// Reopen a vault after a migration (success or rollback), choosing the
    /// hardware or passphrase-only path.
    private func reopenAfterMigration(path: String, passphrase: String, useHw: Bool, pin: String) {
        if useHw {
            openHw(path: path, passphrase: passphrase, pin: pin)
        } else {
            open(path: path, passphrase: passphrase)
        }
    }

    // -- Backup hardware key ------------------------------------------

    /// Enroll a *second* YubiKey on the currently-open vault so either key
    /// opens it. Keys are handled one at a time on a single USB port: insert the
    /// current key (one touch recovers the wrapping secret), then swap to the
    /// new key, which is enrolled into the slot in place — the vault data is
    /// never re-encrypted.
    ///
    /// Mirrors `migrate`'s threading: closes the handle to release the lock,
    /// runs the blocking enrollment on the dedicated HID thread behind the busy
    /// overlay. The engine hands back an already-open vault (re-mounted by
    /// replaying the key response it just captured), so there is NO extra touch
    /// to re-open. Keys are handled one at a time on a single USB port (insert
    /// current → swap → insert new), so the user is told exactly which key to
    /// insert/touch.
    func addBackupKey(name: String, passphrase: String, pin: String, newPin: String,
                      isFirst: Bool = false) {
        keysStatus = nil
        error = nil
        guard !passphrase.isEmpty else {
            keysStatus = isFirst
                ? String(localized: "Enter your passphrase to add a hardware key.")
                : String(localized: "Enter your passphrase to add a backup key.")
            return
        }
        let srcPath = info.path
        let pp = Array(passphrase.utf8)
        let pn = Array(pin.utf8)        // current key's PIN (step 2a)
        let npn = Array(newPin.utf8)    // new backup key's PIN (its own, independent)
        // Trimmed name; empty → engine assigns a default ("Key N").
        let keyName = name.trimmingCharacters(in: .whitespacesAndNewlines)

        // Release our lock so the engine can open the file read/write.
        close()
        busyMessage = isFirst
            ? String(localized: "Enrolling your hardware key…")
            : String(localized: "Enrolling backup key…")
        progress = nil
        busy = true
        keyOpInProgress = true   // keep the Keys panel mounted to host the flow
        startProgressUpdates()
        enrollFlow = .backup   // names the insert/remove/touch prompts
        enrollIsFirstKey = isFirst

        HIDExecutor.shared.async {
            let progressCb: @convention(c) (UInt32, UInt64, UInt64, UnsafeMutableRawPointer?) -> Void = { phase, done, total, ud in
                guard let ud = ud else { return }
                Unmanaged<VaultModel>.fromOpaque(ud).takeUnretainedValue()
                    .reportProgress(phase: phase, done: done, total: total)
            }
            let ud = Unmanaged.passUnretained(self).toOpaque()
            var h: OpaquePointer?
            let status = pp.withUnsafeBufferPointer { ppb in
                pn.withUnsafeBufferPointer { pnb in
                    npn.withUnsafeBufferPointer { npnb in
                        // Pass the name as a C string (nil when empty → "Key N").
                        let runWith: (UnsafePointer<CChar>?) -> Int32 = { labelPtr in
                            farewell_add_backup_key(
                                srcPath,
                                ppb.baseAddress, UInt64(ppb.count),
                                pnb.baseAddress, UInt64(pnb.count),
                                npnb.baseAddress, UInt64(npnb.count),
                                labelPtr,
                                progressCb, ud, &h)
                        }
                        return keyName.isEmpty
                            ? runWith(nil)
                            : keyName.withCString { runWith($0) }
                    }
                }
            }
            DispatchQueue.main.async {
                self.stopProgressUpdates()
                self.busy = false
                self.progress = nil
                if status == .ffi_ok, let handle = h {
                    self.keysStatus = isFirst
                        ? String(localized: "Hardware key enrolled. This vault now needs that key plus your passphrase to open. Enrol a backup key too — lose your only key and the vault is gone, with no recovery.")
                        : String(localized: "Backup key enrolled. Either key now opens this vault — keep the backup somewhere safe and separate. There is still no recovery if you lose both.")
                    // The engine handed back an ALREADY-OPEN vault (re-mounted
                    // without a second touch), so just adopt it.
                    self.finishOpen(handle: handle, path: srcPath)
                } else if status == .ffi_ok {
                    // Enrolled, but the convenience re-open didn't return a
                    // handle — fall back to a normal unlock (one touch).
                    self.keysStatus = isFirst
                        ? String(localized: "Hardware key enrolled. Unlock again to continue.")
                        : String(localized: "Backup key enrolled. Unlock again to continue.")
                    self.openHw(path: srcPath, passphrase: passphrase, pin: pin)
                } else {
                    self.keysStatus = isFirst
                        ? String(localized: "Could not add the hardware key: \(humanError(status: status)). Your vault is unchanged.")
                        : String(localized: "Could not add the backup key: \(humanError(status: status)). Your vault is unchanged.")
                    // Re-open the untouched vault so the user isn't left locked out.
                    self.openHw(path: srcPath, passphrase: passphrase, pin: pin)
                }
            }
        }
    }

    // -- Keys management ---------------------------------------------

    /// Load the vault's enrolled keys (index + name) using the passphrase
    /// alone — no hardware touch. The KDF runs off the main thread because a
    /// passphrase-only vault uses the heavy profile (seconds).
    func loadKeys(passphrase: String) {
        // NB: does NOT clear keysStatus — the panel reloads the list right after
        // an op (add/revoke/convert) and must keep that op's result banner. The
        // user-initiated reload() clears it explicitly before calling this.
        guard !passphrase.isEmpty else {
            keys = []
            return
        }
        let srcPath = info.path
        let pp = Array(passphrase.utf8)
        keysLoading = true
        DispatchQueue.global(qos: .userInitiated).async {
            // Collect into a local array via the C callback, then publish.
            final class Sink { var items: [VaultModel.KeyInfo] = [] }
            let sink = Sink()
            let ud = Unmanaged.passUnretained(sink).toOpaque()
            let cb: @convention(c) (UInt32, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = {
                index, labelPtr, ud in
                guard let ud = ud else { return }
                let sink = Unmanaged<Sink>.fromOpaque(ud).takeUnretainedValue()
                let name = labelPtr.map { String(cString: $0) } ?? ""
                sink.items.append(VaultModel.KeyInfo(index: Int(index), name: name))
            }
            let status = pp.withUnsafeBufferPointer { ppb in
                farewell_key_list(srcPath, ppb.baseAddress, UInt64(ppb.count), cb, ud)
            }
            let items = sink.items
            DispatchQueue.main.async {
                self.keysLoading = false
                if status == .ffi_ok {
                    self.keys = items
                    self.keysLoaded = true
                } else {
                    self.keys = []
                    self.keysLoaded = false
                    self.keysStatus = String(localized: "Could not read keys: \(humanError(status: status)).")
                }
            }
        }
    }

    /// Revoke the key at `index` with the passphrase alone (no touch) — for a
    /// lost or stolen key. Only valid when at least two keys remain enrolled;
    /// removing the last key goes through `convertToPassphraseOnly`.
    ///
    /// Writing the slot needs the exclusive file lock the OPEN vault already
    /// holds, so we release it first (`close()`), do the passphrase-only
    /// revoke, then reopen — a key is still required afterwards, so the reopen
    /// asks for one touch. `pin` is forwarded to that reopen.
    func removeKey(index: Int, passphrase: String, pin: String) {
        keysStatus = nil
        error = nil
        guard !passphrase.isEmpty else {
            keysStatus = String(localized: "Enter your passphrase to remove a key.")
            return
        }
        let srcPath = info.path
        let pp = Array(passphrase.utf8)
        // Release our exclusive lock so the engine can open the file read/write.
        close()
        keyOpInProgress = true   // keep the Keys panel mounted to host the flow
        keysLoading = true
        DispatchQueue.global(qos: .userInitiated).async {
            let status = pp.withUnsafeBufferPointer { ppb in
                farewell_remove_hw_key(srcPath, ppb.baseAddress, UInt64(ppb.count), UInt32(index))
            }
            DispatchQueue.main.async {
                self.keysLoading = false
                self.keysStatus = status == .ffi_ok
                    ? String(localized: "Key revoked — it no longer opens this vault. Unlock again to continue.")
                    : String(localized: "Could not revoke the key: \(humanError(status: status)). Your vault is unchanged.")
                // Reopen either way so the user isn't left locked out (a
                // remaining key is still required → one touch).
                self.openHw(path: srcPath, passphrase: passphrase, pin: pin)
            }
        }
    }

    /// Convert a hardware vault back to passphrase-only by removing its LAST
    /// key. The key must be present (one touch) so the master can be re-wrapped
    /// under the passphrase; opening is slower afterwards (heavy KDF restored).
    /// Mirrors `addBackupKey`'s busy/progress handling and re-adopts the
    /// already-open handle the engine hands back.
    func convertToPassphraseOnly(passphrase: String, pin: String) {
        keysStatus = nil
        error = nil
        guard !passphrase.isEmpty else {
            keysStatus = String(localized: "Enter your passphrase to remove the last key.")
            return
        }
        let srcPath = info.path
        let pp = Array(passphrase.utf8)
        let pn = Array(pin.utf8)

        close()
        busyMessage = String(localized: "Removing the last key…")
        progress = nil
        busy = true
        keyOpInProgress = true   // keep the Keys panel mounted to host the flow
        startProgressUpdates()
        enrollFlow = .removal

        HIDExecutor.shared.async {
            let progressCb: @convention(c) (UInt32, UInt64, UInt64, UnsafeMutableRawPointer?) -> Void = {
                phase, done, total, ud in
                guard let ud = ud else { return }
                Unmanaged<VaultModel>.fromOpaque(ud).takeUnretainedValue()
                    .reportProgress(phase: phase, done: done, total: total)
            }
            let ud = Unmanaged.passUnretained(self).toOpaque()
            var h: OpaquePointer?
            let status = pp.withUnsafeBufferPointer { ppb in
                pn.withUnsafeBufferPointer { pnb in
                    farewell_convert_to_passphrase_only(
                        srcPath,
                        ppb.baseAddress, UInt64(ppb.count),
                        pnb.baseAddress, UInt64(pnb.count),
                        progressCb, ud, &h)
                }
            }
            DispatchQueue.main.async {
                self.stopProgressUpdates()
                self.busy = false
                self.progress = nil
                if status == .ffi_ok, let handle = h {
                    self.keysStatus = String(localized: "Last key removed. This vault now opens with the passphrase alone — and opening is slower again, by design.")
                    self.finishOpen(handle: handle, path: srcPath)
                } else if status == .ffi_ok {
                    self.keysStatus = String(localized: "Last key removed. Unlock again with your passphrase.")
                    self.openHw(path: srcPath, passphrase: passphrase, pin: pin)
                } else {
                    self.keysStatus = String(localized: "Could not remove the last key: \(humanError(status: status)). Your vault is unchanged.")
                    self.openHw(path: srcPath, passphrase: passphrase, pin: pin)
                }
            }
        }
    }

    // -- File enumeration --------------------------------------------

    func refreshFiles() {
        guard let h = handle else { return }
        files.removeAll()

        let userData = Unmanaged.passUnretained(self).toOpaque()
        let cb: @convention(c) (
            UnsafePointer<FarewellDirent>?,
            UnsafeMutableRawPointer?
        ) -> Void = { entryPtr, userData in
            guard let entryPtr = entryPtr, let userData = userData else { return }
            let entry = entryPtr.pointee
            let name = String(cString: entry.name_utf8)
            let model: VaultModel = Unmanaged<VaultModel>
                .fromOpaque(userData)
                .takeUnretainedValue()
            model.files.append(FileEntry(name: name, size: entry.size))
        }
        _ = farewell_readdir(h, cb, userData)
    }

    func refreshFolders() {
        guard let h = handle else { return }
        folders.removeAll()
        let userData = Unmanaged.passUnretained(self).toOpaque()
        let cb: @convention(c) (
            UnsafePointer<CChar>?,
            UnsafeMutableRawPointer?
        ) -> Void = { pathPtr, userData in
            guard let pathPtr = pathPtr, let userData = userData else { return }
            let path = String(cString: pathPtr)
            let model: VaultModel = Unmanaged<VaultModel>
                .fromOpaque(userData)
                .takeUnretainedValue()
            model.folders.append(path)
        }
        _ = farewell_folders(h, cb, userData)
    }

    // -- Folders ------------------------------------------------------

    func createFolder(_ path: String) {
        guard let h = handle else { return }
        let status = path.withCString { farewell_create_folder(h, $0) }
        guard status == .ffi_ok else {
            importStatus = "Could not create folder: \(humanError(status: status))"
            return
        }
        refreshFolders()
        refreshCounter()
    }

    func deleteFolder(_ path: String) {
        guard let h = handle else { return }
        let status = path.withCString { farewell_delete_folder(h, $0) }
        guard status == .ffi_ok else {
            importStatus = "Could not delete folder: \(humanError(status: status))"
            return
        }
        if let sel = selectedFileID, sel.hasPrefix(path + "/") {
            selectedFileID = nil
        }
        refreshFiles(); refreshFolders(); refreshCounter(); refreshSpace()
    }

    func renameFolder(_ old: String, to new: String) {
        guard let h = handle else { return }
        let trimmed = new.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let status = old.withCString { o in
            trimmed.withCString { n in farewell_rename_folder(h, o, n) }
        }
        guard status == .ffi_ok else {
            importStatus = "Could not rename folder: \(humanError(status: status))"
            return
        }
        selectedFileID = nil
        refreshFiles(); refreshFolders(); refreshCounter()
    }

    /// Move either a file or a folder into `folder` (empty = root).
    /// Dispatches to moveFile / renameFolder, with a guard against
    /// dropping a folder into itself or one of its own descendants.
    func moveItem(_ path: String, intoFolder folder: String) {
        if folders.contains(path) {
            // It's a folder. Refuse self / descendant targets.
            if folder == path || folder.hasPrefix(path + "/") {
                importStatus = "Can't move a folder into itself."
                return
            }
            let leaf = (path as NSString).lastPathComponent
            let target = folder.isEmpty ? leaf : "\(folder)/\(leaf)"
            if target == path { return }
            if folders.contains(target) {
                importStatus = "A folder named “\(leaf)” already exists there."
                return
            }
            renameFolder(path, to: target)
        } else {
            moveFile(path, toFolder: folder)
        }
    }

    /// Move a file into `folder` (empty string = root) by renaming it
    /// with the new path prefix. Metadata only — no chunk movement.
    func moveFile(_ name: String, toFolder folder: String) {
        guard let h = handle else { return }
        let leaf = (name as NSString).lastPathComponent
        let target = folder.isEmpty ? leaf : "\(folder)/\(leaf)"
        if target == name { return }
        if files.contains(where: { $0.name == target }) {
            importStatus = "“\(leaf)” already exists in that folder."
            return
        }
        let status = name.withCString { o in
            target.withCString { n in farewell_rename(h, o, n) }
        }
        guard status == .ffi_ok else {
            importStatus = "Could not move file: \(humanError(status: status))"
            return
        }
        if selectedFileID == name { selectedFileID = target }
        refreshFiles(); refreshFolders(); refreshCounter()
    }

    // -- Import -------------------------------------------------------

    /// Import one or more files from disk into the vault. Each file is
    /// streamed in 64 KB windows from source → vault via the FFI, so
    /// neither the import path nor the source ever materializes a
    /// second plaintext copy beyond what already exists on disk.
    ///
    /// Name collisions are resolved by appending " 2", " 3", … before
    /// the extension, so an import never silently overwrites an
    /// existing vault file.
    ///
    /// If `shredOriginalsAfterImport` is set, each successfully
    /// imported source is overwritten with random bytes and unlinked
    /// (best-effort; see `secureShred` caveats).
    func importFiles(_ urls: [URL]) {
        guard handle != nil else { return }
        var imported = 0
        var lastError: String?
        var shredMedium: StorageMedium?

        for url in urls {
            switch importOne(url) {
            case .success:
                imported += 1
                if shredOriginalsAfterImport {
                    shredMedium = secureShred(url)
                }
            case .failure(let msg):
                lastError = msg
            }
        }

        refreshFiles()
        refreshCounter()
        refreshSpace()

        if let err = lastError {
            importStatus = String(localized: "Imported \(imported); last error: \(err)")
        } else if imported == 1 {
            importStatus = String(localized: "Imported 1 file.")
        } else if imported > 1 {
            importStatus = String(localized: "Imported \(imported) files.")
        }
        // Append an honest note about what shredding the originals achieved on
        // this storage medium.
        if let m = shredMedium {
            let note = shredNote(for: m, passes: max(1, shredPasses))
            importStatus = [importStatus, note].compactMap { $0 }.joined(separator: " ")
        }
    }

    private enum ImportResult {
        case success
        case failure(String)
    }

    private func importOne(_ url: URL) -> ImportResult {
        guard let h = handle else { return .failure(String(localized: "vault not open")) }

        let base = url.lastPathComponent
        guard !base.isEmpty else { return .failure(String(localized: "empty name")) }

        // Determine the source size for a pre-flight capacity check.
        let fileSize: UInt64
        do {
            let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
            fileSize = (attrs[.size] as? NSNumber)?.uint64Value ?? 0
        } catch {
            return .failure(String(localized: "cannot stat \(base)"))
        }

        // Pre-flight: refuse the WHOLE file up front if it doesn't fit,
        // rather than writing a partial, truncated copy. Re-read free
        // space now (it shrinks as earlier files in a multi-file import
        // are stored).
        var total: UInt64 = 0
        var free: UInt64 = 0
        if farewell_space(h, &total, &free) == .ffi_ok, fileSize > free {
            return .failure(
                String(localized: "“\(base)” is \(formatBytes(fileSize)) but only \(formatBytes(free)) is free in this level.")
            )
        }

        let name = uniqueName(for: base)

        guard let fh = try? FileHandle(forReadingFrom: url) else {
            return .failure(String(localized: "cannot read \(base)"))
        }
        defer { try? fh.close() }

        var st = farewell_create(h, name)
        guard st == .ffi_ok else { return .failure(humanError(status: st)) }
        st = farewell_truncate(h, name, 0)
        guard st == .ffi_ok else { return .failure(humanError(status: st)) }

        var offset: UInt64 = 0
        let chunkSize = 64 * 1024
        while true {
            let data = (try? fh.read(upToCount: chunkSize)) ?? Data()
            if data.isEmpty { break }
            let writeStatus = data.withUnsafeBytes { raw -> Int32 in
                let ptr = raw.bindMemory(to: UInt8.self).baseAddress
                return farewell_write_range(h, name, offset, ptr, UInt64(data.count))
            }
            guard writeStatus == .ffi_ok else {
                // Mid-write failure (should be rare after the pre-flight,
                // but possible on edge cases). Roll back the partial
                // file so we never leave a truncated import behind.
                _ = name.withCString { farewell_delete(h, $0) }
                return .failure(humanError(status: writeStatus))
            }
            offset += UInt64(data.count)
        }

        return .success
    }

    /// Overwrite an existing vault file with new UTF-8 `content` (the in-app
    /// text editor). Returns `nil` on success, else a human-readable error.
    ///
    /// The new bytes are written straight into the encrypted vault — never to
    /// a temp file on disk. We truncate to zero first, so the space the old
    /// content used becomes available again (relevant for the capacity check).
    @discardableResult
    func saveText(name: String, content: String) -> String? {
        guard let h = handle else { return String(localized: "The vault isn’t open.") }
        let data = Data(content.utf8)
        let newSize = UInt64(data.count)

        // Capacity pre-flight: overwriting frees the old content first, so the
        // budget is (free + old size). Refuse up front rather than leaving a
        // half-written file behind.
        let oldSize = files.first(where: { $0.name == name })?.size ?? 0
        var total: UInt64 = 0
        var free: UInt64 = 0
        if farewell_space(h, &total, &free) == .ffi_ok {
            let available = free + oldSize
            if newSize > available {
                return String(localized: "Not enough space: the edit needs \(formatBytes(newSize)) but only \(formatBytes(available)) is available.")
            }
        }

        var st = farewell_truncate(h, name, 0)
        guard st == .ffi_ok else { return humanError(status: st) }

        var offset: UInt64 = 0
        let chunkSize = 64 * 1024
        var start = data.startIndex
        while start < data.endIndex {
            let end = data.index(start, offsetBy: chunkSize, limitedBy: data.endIndex)
                ?? data.endIndex
            let chunk = data[start..<end]
            st = chunk.withUnsafeBytes { raw -> Int32 in
                let ptr = raw.bindMemory(to: UInt8.self).baseAddress
                return farewell_write_range(h, name, offset, ptr, UInt64(chunk.count))
            }
            guard st == .ffi_ok else { return humanError(status: st) }
            offset += UInt64(chunk.count)
            start = end
        }

        refreshFiles()
        refreshCounter()
        refreshSpace()
        reloadSelectedContent()
        return nil
    }

    /// Create a new, empty markdown note, select it, and request that the
    /// viewer open it straight into the editor. Nothing touches disk.
    func newNote() {
        guard let h = handle else { return }
        let name = uniqueName(for: "Untitled.md")
        let st = farewell_create(h, name)
        guard st == .ffi_ok else {
            importStatus = "Couldn’t create a note: \(humanError(status: st))"
            return
        }
        refreshFiles()
        refreshCounter()
        refreshSpace()
        // Select it (drives reloadSelectedContent) and ask the viewer to edit.
        pendingEditFile = name
        selectedFileID = name
    }

    /// Return `base` if no vault file has that name, else `base` with
    /// " 2", " 3", … inserted before the extension.
    private func uniqueName(for base: String) -> String {
        let existing = Set(files.map { $0.name })
        if !existing.contains(base) { return base }

        let ns = base as NSString
        let ext = ns.pathExtension
        let stem = ns.deletingPathExtension
        var n = 2
        while true {
            let candidate = ext.isEmpty ? "\(stem) \(n)" : "\(stem) \(n).\(ext)"
            if !existing.contains(candidate) { return candidate }
            n += 1
        }
    }

    /// Securely delete a source file, returning the storage medium so the
    /// caller can be honest about what the erase actually achieves.
    ///
    /// - **Rotational (HDD):** `shredPasses` random-overwrite passes, each
    ///   forced to durable media with `F_FULLFSYNC`. The original bytes are
    ///   physically destroyed.
    /// - **Solid state / unknown (SSD/flash):** the overwrite is *best-effort*
    ///   — wear-leveling means the controller may write the random bytes to a
    ///   fresh page and leave the old cells intact. We still overwrite, force
    ///   it durable, and punch-hole the file (a TRIM hint) before unlinking,
    ///   but make **no guarantee**. The real protection is never having written
    ///   the plaintext original (keep content in the vault / in-app viewer).
    @discardableResult
    private func secureShred(_ url: URL) -> StorageMedium {
        let medium = detectStorageMedium(for: url)
        let passes = max(1, shredPasses)

        guard let fh = try? FileHandle(forUpdating: url) else { return medium }
        let fd = fh.fileDescriptor
        let size = (try? fh.seekToEnd()) ?? 0

        var blockSize: UInt64 = 4096
        var fs = statfs()
        if statfs(url.path, &fs) == 0, fs.f_bsize > 0 {
            blockSize = UInt64(fs.f_bsize)
        }

        for _ in 0..<passes {
            try? fh.seek(toOffset: 0)
            var remaining = size
            let chunkSize = 1 << 20  // 1 MiB
            while remaining > 0 {
                let n = Int(min(UInt64(chunkSize), remaining))
                var random = Data(count: n)
                let ok = random.withUnsafeMutableBytes { raw -> Bool in
                    guard let base = raw.baseAddress else { return false }
                    return SecRandomCopyBytes(kSecRandomDefault, n, base) == errSecSuccess
                }
                if !ok { break }
                fh.write(random)
                remaining -= UInt64(n)
            }
            // Force this pass to durable media (F_FULLFSYNC) before the next
            // pass / before we consider the original overwritten.
            fullFsync(fd)
        }

        // On SSD/flash (or unknown), hint the controller to discard the blocks.
        if medium != .rotational {
            punchHole(fd, size: size, blockSize: blockSize)
            fullFsync(fd)
        }

        try? fh.close()
        try? FileManager.default.removeItem(at: url)
        return medium
    }

    /// An honest one-line summary of what a shred achieved, per medium.
    private func shredNote(for medium: StorageMedium, passes: Int) -> String {
        switch medium {
        case .rotational:
            return String(localized: "Original securely erased (overwritten \(passes)× in place on a hard disk).")
        case .solidState:
            return String(localized: "Original overwritten + deleted — but this is an SSD: wear-leveling means the cells may persist. The real protection is the encrypted vault, not the wipe.")
        case .unknown:
            return String(localized: "Original overwritten + deleted (storage type unknown; treated as flash — no physical-erase guarantee).")
        }
    }

    private func refreshCounter() {
        guard let h = handle else { return }
        var c: UInt64 = 0
        if farewell_counter(h, &c) == .ffi_ok {
            info.counter = c
        }
    }

    /// Refresh the open level's usable / free capacity.
    func refreshSpace() {
        guard let h = handle else { return }
        var total: UInt64 = 0
        var free: UInt64 = 0
        if farewell_space(h, &total, &free) == .ffi_ok {
            info.spaceTotal = total
            info.spaceFree = free
        }
    }

    // -- Export -------------------------------------------------------

    /// Stream a decrypted copy of `name` out to `url` on disk.
    ///
    /// This deliberately leaves the Farewell perimeter: the written
    /// file is plaintext on the host filesystem, subject to every OS
    /// cache vector (Spotlight, QuickLook, Time Machine, Recent
    /// Items, …). The caller is responsible for warning the user
    /// BEFORE invoking this (see ExportWarningSheet); the model does
    /// not gate it.
    ///
    /// Reads in 64 KB windows and writes incrementally, so a large
    /// file is not fully buffered in RAM during export.
    @discardableResult
    func exportFile(_ name: String, to url: URL) -> Bool {
        guard let h = handle else { return false }

        var stat = FarewellStat(size: 0)
        guard farewell_stat(h, name, &stat) == .ffi_ok else {
            importStatus = "Export failed: could not stat \(name)."
            return false
        }

        // Create/truncate the destination.
        FileManager.default.createFile(atPath: url.path, contents: nil)
        guard let fh = try? FileHandle(forWritingTo: url) else {
            importStatus = "Export failed: cannot write to \(url.lastPathComponent)."
            return false
        }
        defer { try? fh.close() }

        var offset: UInt64 = 0
        let chunkSize: UInt64 = 64 * 1024
        var buf = [UInt8](repeating: 0, count: Int(chunkSize))

        while offset < stat.size {
            let want = min(chunkSize, stat.size - offset)
            var actual: UInt64 = 0
            let st = buf.withUnsafeMutableBufferPointer { p in
                farewell_read_range(h, name, offset, want, p.baseAddress, &actual)
            }
            guard st == .ffi_ok, actual > 0 else {
                secureZeroLocal(&buf)
                importStatus = "Export failed during read of \(name)."
                return false
            }
            fh.write(Data(buf[0..<Int(actual)]))
            offset += actual
        }
        secureZeroLocal(&buf)

        importStatus = "Exported \(name) to \(url.path) — now a plaintext file outside the vault."
        return offset == stat.size
    }

    private func secureZeroLocal(_ buf: inout [UInt8]) {
        for i in 0..<buf.count { buf[i] = 0 }
    }

    // -- Delete / rename ----------------------------------------------

    /// Securely delete a file from the vault. Its chunks are random-
    /// filled on disk by the core (cryptographic shred) and its
    /// manifest entry removed; the counter advances.
    func deleteFile(_ name: String) {
        guard let h = handle else { return }
        let st = farewell_delete(h, name)
        guard st == .ffi_ok else {
            importStatus = "Delete failed: \(humanError(status: st))"
            return
        }
        if selectedFileID == name {
            selectedFileID = nil
        }
        refreshFiles()
        refreshFolders()
        refreshCounter()
        refreshSpace()
        importStatus = "Deleted “\(name)” — its chunks were securely shredded."
    }

    /// Rename a file. Refuses if the destination name already exists
    /// (the core's rename would otherwise replace + shred it; we make
    /// the UI path non-destructive and require the user to delete the
    /// target explicitly first).
    func renameFile(_ old: String, to proposed: String) {
        guard let h = handle else { return }
        let new = proposed.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !new.isEmpty else {
            importStatus = "Rename cancelled: empty name."
            return
        }
        if new == old { return }
        if files.contains(where: { $0.name == new }) {
            importStatus = "Rename failed: “\(new)” already exists. Delete it first if you mean to replace it."
            return
        }
        let st = farewell_rename(h, old, new)
        guard st == .ffi_ok else {
            importStatus = "Rename failed: \(humanError(status: st))"
            return
        }
        let wasSelected = (selectedFileID == old)
        refreshFiles()
        refreshCounter()
        refreshSpace()
        if wasSelected { selectedFileID = new }
        importStatus = "Renamed “\(old)” → “\(new)”."
    }

    // -- Streaming read of the selected file --------------------------

    /// Triggered whenever `selectedFileID` changes. Streams the
    /// selected file's bytes via `read_range` in 64 KB chunks,
    /// decodes per the extension, and publishes a `ViewerContent`.
    ///
    /// The 64 KB chunk size matches `CHUNK_PLAINTEXT_LEN`, so a
    /// well-aligned read decrypts exactly one vault chunk per
    /// iteration. For text files we typically loop once or twice;
    /// the discipline matters more for the PDF / audio / video
    /// viewers planned in v0.19.C+ where a multi-MB file is
    /// realistic.
    private func reloadSelectedContent() {
        selectedContent = nil
        guard let h = handle, let f = selectedFile else { return }

        var stat = FarewellStat(size: 0)
        let ss = farewell_stat(h, f.name, &stat)
        guard ss == .ffi_ok else {
            selectedContent = .loadFailed(reason: humanError(status: ss))
            return
        }

        let ext = (f.name as NSString).pathExtension.lowercased()

        let textExts: Set<String> = [
            "txt", "log", "json", "yaml", "yml", "toml", "csv",
            "xml", "html", "rs", "swift", "py", "js", "ts", "sh",
            "conf", "ini", "cfg", "rb", "go", "c", "h", "cpp", "hpp"
        ]
        let mdExts: Set<String> = ["md", "markdown", "mdown", "mkd"]
        let pdfExts: Set<String> = ["pdf"]
        let imageExts: Set<String> = [
            "png", "jpg", "jpeg", "heic", "heif", "gif", "bmp",
            "tiff", "tif", "webp", "avif"
        ]
        let audioExts: Set<String> = [
            "mp3", "m4a", "aac", "flac", "wav", "wave", "aif", "aiff",
            "aifc", "caf", "ogg", "oga", "opus", "alac"
        ]
        // AVFoundation-native containers only (VideoToolbox decodes these
        // in-process). mkv/webm/avi aren't supported → handled below.
        let videoExts: Set<String> = ["mp4", "m4v", "mov", "qt"]

        // Per-type size cap. Media can legitimately be larger than a text
        // note, but we still bound RAM use; a genuinely huge file is more
        // likely an attack or a mistake than a document to view on screen.
        let isMedia = pdfExts.contains(ext) || imageExts.contains(ext)
            || audioExts.contains(ext) || videoExts.contains(ext)
        let displayCap: UInt64 = videoExts.contains(ext) ? (1024 * 1024 * 1024)
            : (isMedia ? (256 * 1024 * 1024) : (8 * 1024 * 1024))
        if stat.size > displayCap {
            selectedContent = .unsupported(
                reason: "File is \(formatBytes(stat.size)); the in-app viewer caps at \(formatBytes(displayCap)) for this type."
            )
            return
        }

        // Stream the bytes in 64 KB windows (== one vault chunk per
        // iteration when aligned). The full decrypted file ends up in
        // `assembled` — acceptable per THREAT_MODEL §5.10 (in-RAM, never
        // on disk; mlock of these buffers is the planned hardening).
        let chunkSize: UInt64 = 64 * 1024
        var assembled = Data()
        assembled.reserveCapacity(Int(stat.size))
        var offset: UInt64 = 0
        var buf = [UInt8](repeating: 0, count: Int(chunkSize))

        while offset < stat.size {
            let want = min(chunkSize, stat.size - offset)
            var actual: UInt64 = 0
            let status = buf.withUnsafeMutableBufferPointer { p in
                farewell_read_range(h, f.name, offset, want, p.baseAddress, &actual)
            }
            guard status == .ffi_ok else {
                secureZero(&buf)
                selectedContent = .loadFailed(reason: humanError(status: status))
                return
            }
            if actual == 0 { break } // EOF safety
            assembled.append(buf, count: Int(actual))
            offset += actual
        }
        secureZero(&buf)

        // PDF / image: hand the bytes to the Apple framework in-memory.
        // We keep `assembled` (PDFKit/NSImage may reference it), so we
        // do NOT zeroize here — the bytes live in RAM for as long as the
        // file is displayed. That's the §5.10 in-RAM tradeoff; the disk
        // guarantee is preserved (nothing is ever written out).
        if pdfExts.contains(ext) {
            selectedContent = .pdf(assembled)
            return
        }
        if imageExts.contains(ext) {
            selectedContent = .image(assembled)
            return
        }
        // Audio: hand the compressed bytes to the Rust streaming decoder
        // (kept in RAM for the player's lifetime; nothing on disk).
        if audioExts.contains(ext) {
            selectedContent = .audio(assembled)
            return
        }
        // Video: AVPlayer fed from RAM (custom resource loader), rendered in
        // our own layer — never a file URL, never QuickTime.
        if videoExts.contains(ext) {
            selectedContent = .video(assembled, ext)
            return
        }

        // Text-like: decode UTF-8, then best-effort zeroize the byte
        // buffer (the String has its own copy).
        let asString = String(data: assembled, encoding: .utf8)
        assembled.withUnsafeMutableBytes { rawBuf in
            if let base = rawBuf.baseAddress {
                memset(base, 0, rawBuf.count)
            }
        }

        if mdExts.contains(ext), let s = asString {
            selectedContent = .markdown(s)
        } else if textExts.contains(ext), let s = asString {
            selectedContent = .text(s)
        } else if let s = asString, !s.isEmpty {
            selectedContent = .text(s) // unknown ext but valid UTF-8
        } else {
            selectedContent = .unsupported(
                reason: "Binary content of an unrecognized type. A video viewer is coming in a later iteration."
            )
        }
    }
}

// =============================================================================
// PDFKit bridge
// =============================================================================

/// Read-only, selectable monospaced text view backed by NSTextView.
///
/// Used instead of SwiftUI `Text(...).textSelection(.enabled)` because
/// the latter re-lays the text out when a selection begins, visibly
/// changing line spacing on click. NSTextView renders once and keeps a
/// stable layout while supporting native selection / copy.
struct CodeTextView: NSViewRepresentable {
    let text: String

    func makeNSView(context: Context) -> NSScrollView {
        let textView = NSTextView()
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.drawsBackground = false
        textView.font = NSFont.monospacedSystemFont(
            ofSize: NSFont.systemFontSize, weight: .regular)
        textView.textContainerInset = NSSize(width: 16, height: 16)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        textView.string = text

        let scroll = NSScrollView()
        scroll.documentView = textView
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        return scroll
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        guard let textView = nsView.documentView as? NSTextView else { return }
        if textView.string != text {
            textView.string = text
        }
    }
}

/// Editable monospaced text view backed by NSTextView, bound to a `String`.
///
/// The in-app editor for text/markdown files. While editing, the NSTextView is
/// the source of truth (we don't push SwiftUI updates back into it mid-edit, to
/// avoid clobbering the caret). Smart quotes/dashes/replacements are off so the
/// stored bytes are exactly what the user typed.
struct EditableTextView: NSViewRepresentable {
    @Binding var text: String

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let textView = NSTextView()
        textView.isEditable = true
        textView.isSelectable = true
        textView.isRichText = false
        textView.allowsUndo = true
        textView.drawsBackground = false
        textView.font = NSFont.monospacedSystemFont(
            ofSize: NSFont.systemFontSize, weight: .regular)
        textView.textContainerInset = NSSize(width: 16, height: 16)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.isAutomaticSpellingCorrectionEnabled = false
        textView.delegate = context.coordinator
        textView.string = text

        let scroll = NSScrollView()
        scroll.documentView = textView
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        // Put the caret in the editor as soon as it appears.
        DispatchQueue.main.async { [weak textView] in
            textView?.window?.makeFirstResponder(textView)
        }
        return scroll
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        // Intentionally empty: the NSTextView owns the text while editing.
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        let parent: EditableTextView
        init(_ parent: EditableTextView) { self.parent = parent }
        func textDidChange(_ notification: Notification) {
            guard let tv = notification.object as? NSTextView else { return }
            parent.text = tv.string
        }
    }
}

/// Wraps AppKit's `PDFView` for SwiftUI. The document is built from
/// in-memory `Data` via `PDFDocument(data:)`, which never touches the
/// filesystem — no temp file, no QuickLook, no disk trace.
struct PDFKitView: NSViewRepresentable {
    let data: Data

    func makeNSView(context: Context) -> PDFView {
        let view = PDFView()
        // Fit the whole current page to the view, preserving aspect
        // ratio. `.singlePage` shows one page at a time (whole page
        // visible); `autoScales` keeps it fitted and re-fits live as
        // the window resizes. Multi-page PDFs are navigated with the
        // arrow keys / swipe.
        view.displayMode = .singlePage
        view.autoScales = true
        view.backgroundColor = .clear
        view.document = PDFDocument(data: data)
        return view
    }

    func updateNSView(_ nsView: PDFView, context: Context) {
        if nsView.document == nil {
            nsView.document = PDFDocument(data: data)
        }
        // Keep auto-scaling on so the page re-fits after layout changes.
        nsView.autoScales = true
    }
}

// =============================================================================
// Views
// =============================================================================

/// Offline license state: reads/verifies the installed license and activates a
/// pasted key, both via the Rust FFI (no network — the serial check and the
/// Ed25519 verification are local). Non-blocking: the app works regardless;
/// this just surfaces status and lets the user activate.
@MainActor
final class LicenseModel: ObservableObject {
    enum Verdict {
        case valid, none, badSignature, wrongVersion, serialMismatch, malformed, error, unknown
    }
    @Published var verdict: Verdict = .none
    @Published var email = ""
    @Published var licenseType: UInt32 = 0
    @Published var message: String?
    @Published var working = false

    var isLicensed: Bool { verdict == .valid }

    /// Read + verify the installed license (off the main thread; the serial
    /// lookup can take a moment).
    func refresh() {
        DispatchQueue.global(qos: .userInitiated).async {
            var info = FarewellLicenseInfo()
            _ = farewell_license_status(&info)
            let snapshot = LicenseModel.snapshot(info)
            DispatchQueue.main.async {
                MainActor.assumeIsolated { self.apply(snapshot, note: nil) }
            }
        }
    }

    /// Verify a pasted key and install it on success.
    func activate(_ key: String) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            message = String(localized: "Paste your license key first.")
            return
        }
        working = true
        DispatchQueue.global(qos: .userInitiated).async {
            var info = FarewellLicenseInfo()
            let st = trimmed.withCString { farewell_license_activate($0, &info) }
            let snapshot = LicenseModel.snapshot(info)
            let ok = st == .ffi_ok
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self.working = false
                    if !ok {
                        self.message = String(localized: "Couldn't read the license input.")
                        return
                    }
                    self.apply(snapshot, note: LicenseModel.note(for: snapshot.verdict))
                }
            }
        }
    }

    private struct Snapshot { let verdict: Verdict; let email: String; let type: UInt32 }

    private func apply(_ s: Snapshot, note: String?) {
        verdict = s.verdict
        email = s.email
        licenseType = s.type
        if let note { message = note }
    }

    nonisolated private static func snapshot(_ info: FarewellLicenseInfo) -> Snapshot {
        var email = ""
        withUnsafeBytes(of: info.email) { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            let upto = bytes.prefix(while: { $0 != 0 })
            email = String(decoding: Array(upto), as: UTF8.self)
        }
        return Snapshot(verdict: mapVerdict(info.verdict), email: email, type: info.license_type)
    }

    nonisolated static func mapVerdict(_ v: Int32) -> Verdict {
        switch v {
        case FAREWELL_LICENSE_VALID: return .valid
        case FAREWELL_LICENSE_NONE: return .none
        case FAREWELL_LICENSE_BAD_SIGNATURE: return .badSignature
        case FAREWELL_LICENSE_WRONG_VERSION: return .wrongVersion
        case FAREWELL_LICENSE_SERIAL_MISMATCH: return .serialMismatch
        case FAREWELL_LICENSE_MALFORMED: return .malformed
        case FAREWELL_LICENSE_ERROR: return .error
        default: return .unknown
        }
    }

    nonisolated static func note(for v: Verdict) -> String {
        switch v {
        case .valid: return String(localized: "Activated. Thank you for supporting Farewell.")
        case .none: return String(localized: "No license installed.")
        case .badSignature:
            return String(localized: "This key isn’t valid for this build (wrong key, or the key was altered).")
        case .wrongVersion: return String(localized: "This license is for a different major version of Farewell.")
        case .serialMismatch:
            return String(localized: "This license isn’t authorized for this Mac. A free re-issue is available — see farewell.pro/license-policy.")
        case .malformed: return String(localized: "That doesn’t look like a valid license key.")
        case .error: return String(localized: "Couldn’t verify (couldn’t read this Mac’s serial number).")
        case .unknown: return String(localized: "Unknown license state.")
        }
    }

    /// This Mac's hardware serial number, read locally via the FFI (no
    /// network). `nil` if it couldn't be read. Same value the license check
    /// uses, so what the buyer sends us matches what activation verifies.
    nonisolated static func thisMacSerial() -> String? {
        var buf = [UInt8](repeating: 0, count: 64)
        guard farewell_read_serial(&buf, buf.count) == .ffi_ok else { return nil }
        let upto = buf.prefix(while: { $0 != 0 })
        let s = String(decoding: Array(upto), as: UTF8.self)
        return s.isEmpty ? nil : s
    }

    func typeName() -> String {
        switch licenseType {
        case 0: return String(localized: "Single")
        case 1: return String(localized: "Duo")
        case 2: return String(localized: "Quintet")
        case 3: return String(localized: "Grant")
        default: return String(localized: "License")
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var vault: VaultModel

    var body: some View {
        Group {
            // Stay on the unlocked chrome during a key operation that briefly
            // closes the vault (add/revoke/convert), so the Keys panel hosts the
            // whole flow instead of being torn down (which flashed the panel and
            // bounced to the Open/Create screen mid-operation).
            if vault.isOpen || vault.keyOpInProgress {
                VStack(spacing: 0) {
                    HeaderView()
                    Divider()
                    HSplitView {
                        FileListView()
                            .frame(minWidth: 240, idealWidth: 280, maxWidth: 480)
                        ViewerPanel()
                            .frame(minWidth: 320)
                    }
                }
            } else {
                // Centre the form when the window has spare height, but
                // scroll (never clip) when it doesn't. Robust to any
                // window size, including a restored/persisted frame.
                GeometryReader { geo in
                    ScrollView {
                        UnlockView()
                            .frame(maxWidth: .infinity, minHeight: geo.size.height)
                    }
                }
            }
        }
        // Disable the content while a key operation runs so no text field
        // keeps its focus ring glowing through the overlay.
        .disabled(vault.busy)
        .overlay {
            // Suppressed during a panel-driven key op: the Keys panel (a sheet
            // presented above this view) hosts the prompts itself, so the
            // full-window overlay would only sit behind it and double-dim.
            if vault.busy && !vault.keyOpInProgress {
                ZStack {
                    Color.black.opacity(0.55).ignoresSafeArea()
                    VStack(spacing: 14) {
                        // Key symbol only while we're waiting on the user's key
                        // (insert / remove / touch); a "working" gear while the
                        // app is computing (KDF, write, re-secure) — even when
                        // that compute is indeterminate (e.g. the heavy KDF that
                        // runs right after a touch).
                        Image(systemName: vault.busyIsKeyStep
                                ? "key.radiowaves.forward" : "gearshape.2")
                            .font(.system(size: 34))
                            .symbolEffect(.pulse)
                        if let p = vault.progress {
                            // Real, determinate progress bar (e.g. vault write).
                            ProgressView(value: p)
                                .progressViewStyle(.linear)
                                .frame(width: 240)
                            Text("\(Int(p * 100)) %")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                        } else {
                            // Indeterminate (e.g. awaiting a key touch).
                            ProgressView()
                        }
                        Text(vault.busyMessage)
                            .font(.callout)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: 280)
                    }
                    .padding(28)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
                }
                .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.15), value: vault.busy)
        .task {
            let args = CommandLine.arguments
            if args.count == 3, !vault.isOpen {
                // Threads a connected key automatically; harmless for K=0.
                vault.openHw(path: args[1], passphrase: args[2], pin: "")
            }
        }
    }
}

struct UnlockView: View {
    @EnvironmentObject var vault: VaultModel
    @EnvironmentObject var license: LicenseModel
    private enum Mode { case open, create }
    @State private var mode: Mode = .open
    @State private var showLicense = false

    var body: some View {
        VStack(spacing: 16) {
            Text("Farewell")
                .font(.system(size: 32, weight: .light))

            if let note = vault.autoLockNotice {
                Label(note, systemImage: "lock.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Picker("", selection: $mode) {
                Text("Open vault").tag(Mode.open)
                Text("Create vault").tag(Mode.create)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 260)

            switch mode {
            case .open:   OpenVaultForm()
            case .create: CreateVaultForm()
            }

            if let err = vault.error {
                Text(err)
                    .foregroundStyle(.red)
                    .font(.caption)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Divider().padding(.top, 8)
            HStack(spacing: 8) {
                Image(systemName: license.isLicensed ? "checkmark.seal.fill" : "seal")
                    .foregroundStyle(license.isLicensed ? .green : .secondary)
                if license.isLicensed {
                    Text("Licensed to \(license.email)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                } else {
                    Text("Not activated")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Manage license…") { showLicense = true }
                    .font(.caption)
            }
        }
        .padding(.horizontal, 44)
        .padding(.vertical, 32)
        .frame(maxWidth: 540)
        .sheet(isPresented: $showLicense) { LicenseSheet() }
    }
}

/// Activation sheet: paste the emailed license key (or drop a .flw file),
/// activate, and see the status — all offline.
struct LicenseSheet: View {
    @EnvironmentObject var license: LicenseModel
    @Environment(\.dismiss) private var dismiss
    @State private var keyText = ""
    @State private var serialCopied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("License")
                .font(.title3.weight(.semibold))

            statusRow

            Text("Paste the license key you received by email, then Activate. Everything is verified locally — Farewell never contacts a server.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Button {
                copyThisMacSerial()
            } label: {
                Label("Copy this Mac’s serial number",
                      systemImage: serialCopied ? "checkmark.circle.fill" : "doc.on.doc")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .tint(serialCopied ? .green : .accentColor)

            TextEditor(text: $keyText)
                .font(.system(.body, design: .monospaced))
                .frame(height: 110)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.secondary.opacity(0.3)))

            // Only surface a message when NOT licensed (errors / hints). When
            // licensed, the status row above already says so — no redundant
            // "Activated" line.
            if let msg = license.message, !license.isLicensed {
                Text(msg)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Open file…") { chooseFile() }
                    .disabled(license.isLicensed || license.working)
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Activate") { license.activate(keyText) }
                    .keyboardShortcut(.defaultAction)
                    // Nothing left to do once a valid license is installed:
                    // only Close stays active.
                    .disabled(license.isLicensed
                        || license.working
                        || keyText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 520)
        .onAppear { license.refresh() }
    }

    /// Copy this Mac's serial number to the clipboard so the buyer can paste
    /// it where their license is generated. Reads locally via the FFI — no
    /// network. Shows a brief checkmark on success.
    private func copyThisMacSerial() {
        guard let sn = LicenseModel.thisMacSerial() else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(sn, forType: .string)
        serialCopied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { serialCopied = false }
    }

    @ViewBuilder
    private var statusRow: some View {
        HStack(spacing: 8) {
            Image(systemName: license.isLicensed ? "checkmark.seal.fill" : "seal")
                .foregroundStyle(license.isLicensed ? .green : .secondary)
            if license.isLicensed {
                Text("Licensed to \(license.email) — \(license.typeName())")
            } else {
                Text("Not activated on this Mac")
                    .foregroundStyle(.secondary)
            }
        }
        .font(.callout)
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url,
           let s = try? String(contentsOf: url, encoding: .utf8) {
            keyText = s
        }
    }
}

/// Open an existing vault with its passphrase.
///
/// Deliberately minimal: one path, one passphrase, one button.
struct OpenVaultForm: View {
    @EnvironmentObject var vault: VaultModel
    @State private var path: String = ""
    @State private var passphrase: String = ""
    @State private var useHwPin: Bool = false
    @State private var hwPin: String = ""

    var body: some View {
        VStack(spacing: 12) {
            HStack {
                TextField("Vault path", text: $path)
                    .textFieldStyle(.roundedBorder)
                Button("Choose…", action: chooseFile)
            }
            SecureField("Passphrase", text: $passphrase)
                .textFieldStyle(.roundedBorder)
                .onSubmit(tryUnlock)

            // A connected YubiKey is always threaded automatically; this
            // disclosure is only needed when the key requires a PIN.
            DisclosureGroup("Using a hardware key with a PIN?", isExpanded: $useHwPin) {
                SecureField("YubiKey PIN", text: $hwPin)
                    .textFieldStyle(.roundedBorder)
                Text("Leave the PIN blank if your key has none. You'll be asked to touch the key if this vault requires it.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .font(.caption)

            Button("Unlock", action: tryUnlock)
                .keyboardShortcut(.defaultAction)
                .disabled(path.isEmpty || passphrase.isEmpty || vault.busy)
        }
        // After any failed open, reveal the PIN field so a user whose key
        // needs a PIN can enter it and retry. Expands on every failure
        // (not just key-required ones), so it leaks nothing about whether
        // this vault actually uses a key.
        .onChange(of: vault.error) { _, err in
            if err != nil { useHwPin = true }
        }
    }

    func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.directoryURL = LastLocation.directoryURL
        if let vaultType = UTType(filenameExtension: "vault") {
            panel.allowedContentTypes = [vaultType]
        }
        if panel.runModal() == .OK, let url = panel.url {
            path = url.path
            LastLocation.remember(url)
        }
    }

    func tryUnlock() {
        guard !path.isEmpty && !passphrase.isEmpty else { return }
        guard FileManager.default.fileExists(atPath: path) else {
            vault.error = String(localized: "No vault at this path. Check the location, or use Choose….")
            return
        }
        vault.openHw(path: path, passphrase: passphrase, pin: useHwPin ? hwPin : "")
        passphrase = ""
        hwPin = ""
    }
}

/// Create a new single-domain vault: one passphrase, optional YubiKey,
/// any size you choose.
enum PassMode: Hashable { case generated, custom }

struct CreateVaultForm: View {
    @EnvironmentObject var vault: VaultModel
    @EnvironmentObject var license: LicenseModel
    @State private var path: String = ""
    @State private var capacityMB: Int = 256   // user-chosen on-disk size (decimal MB)
    /// Opt-in: record the license identity of the creator inside the vault.
    /// OFF by default — it attributes the vault if it's ever decrypted.
    @State private var recordOwner: Bool = false

    @State private var mode: PassMode = .generated
    // Generated path
    @State private var generatedPass: String = ""
    @State private var savedConfirmed: Bool = false
    // Custom path
    @State private var customPass: String = ""
    @State private var customConfirm: String = ""
    // Hardware key (on by default — a second factor for free)
    @State private var useHw: Bool = true
    @State private var useBackupKey: Bool = false
    @State private var hwPin: String = ""

    /// The passphrase that will actually be used.
    private var effectivePass: String {
        mode == .generated ? generatedPass : customPass
    }

    /// Live zxcvbn score (0–4) of the custom passphrase.
    private var customScore: Int { vault.passphraseScore(customPass) }

    /// Why the Create button is disabled, or nil if it's ready.
    private var disabledReason: String? {
        // Creating a NEW vault requires an active license. Opening existing
        // vaults is never gated — we don't lock anyone out of their own data.
        if !license.isLicensed {
            return String(localized: "Creating a vault needs an active license. Activate one with “Manage license…” below. (Opening existing vaults always works.)")
        }
        if path.isEmpty { return String(localized: "Choose where to save the vault (Choose…).") }
        switch mode {
        case .generated:
            if generatedPass.isEmpty { return String(localized: "Generate a passphrase.") }
            if !savedConfirmed { return String(localized: "Tick the box confirming you saved the passphrase.") }
        case .custom:
            if customPass.isEmpty { return String(localized: "Enter a passphrase.") }
            if customPass != customConfirm { return String(localized: "Passphrases don't match.") }
            if customScore < 4 { return String(localized: "Passphrase must reach “Very strong” (4/4).") }
        }
        return nil
    }

    private var canCreate: Bool {
        guard license.isLicensed, !path.isEmpty else { return false }
        switch mode {
        case .generated:
            return !generatedPass.isEmpty && savedConfirmed
        case .custom:
            return !customPass.isEmpty
                && customPass == customConfirm
                && customScore >= 4
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField("New vault path (…/my.vault)", text: $path)
                    .textFieldStyle(.roundedBorder)
                Button("Choose…", action: chooseSavePath)
            }

            HStack(spacing: 8) {
                Text("Capacity")
                TextField("size", value: $capacityMB, format: .number)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 90)
                    .multilineTextAlignment(.trailing)
                Text("MB")
                Spacer()
            }
            Text("Choose any size you want (e.g. 64, 512, 4096…). The vault file is always exactly this size on disk, no matter how much you store — that's part of the deniability.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            Picker("Passphrase", selection: $mode) {
                Text("Generated (recommended)").tag(PassMode.generated)
                Text("My own").tag(PassMode.custom)
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            if mode == .generated {
                generatedSection
            } else {
                customSection
            }

            Text("There is no recovery, and there is no self-destruct: the file looks like random data and your passphrase is the ONLY thing protecting it. That is why it must be strong — and why you must not lose it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            // Optional second factor: a YubiKey. With it enrolled, a copy
            // of the file is uncrackable without the physical key — even
            // if the passphrase is guessed.
            Toggle(isOn: $useHw) {
                Text("Also require a YubiKey (hardware key)")
            }
            .toggleStyle(.switch)

            if useHw {
                SecureField("YubiKey PIN (leave blank if none)", text: $hwPin)
                    .textFieldStyle(.roundedBorder)
                Toggle(isOn: $useBackupKey) {
                    Text("Also enrol a backup key now")
                }
                .toggleStyle(.checkbox)
                if useBackupKey {
                    Text("You'll enrol the keys one at a time: insert the first key and touch it, then swap to the second when asked. Either key will open the vault — keep the backup somewhere safe and separate.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("You'll be asked to TOUCH the key to enrol it. Then a copy of this vault can't be brute-forced without the physical key. Lose your only key and the vault is gone — there is no recovery, so a backup key is recommended.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // Opt-in ownership — OFF by default. Records the creator's license
            // identity INSIDE the encrypted vault (only visible after unlock).
            Divider()
            Toggle(isOn: $recordOwner) {
                Text("Record my identity in this vault")
            }
            .toggleStyle(.checkbox)
            .disabled(!license.isLicensed)
            Text(license.isLicensed
                ? "Stores “\(license.email)” inside the encrypted vault — visible only after unlock. ⚠︎ This ATTRIBUTES the vault to you if it is ever decrypted. Leave OFF if you need deniability."
                : "Activate a license first to record your identity.")
                .font(.caption)
                .foregroundStyle((recordOwner && license.isLicensed) ? .orange : .secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 8) {
                Button("Create and open", action: tryCreate)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canCreate || vault.busy)
                if let reason = disabledReason {
                    Text(reason)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .onAppear { if generatedPass.isEmpty { regenerate() } }
    }

    @ViewBuilder private var generatedSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(generatedPass)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(nsColor: .textBackgroundColor))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))

            HStack {
                Button { regenerate() } label: {
                    Label("Regenerate", systemImage: "arrow.clockwise")
                }
                Spacer()
                Text("≈ 129 bits — 10 random words")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Toggle("I have written this passphrase down somewhere safe",
                   isOn: $savedConfirmed)
        }
    }

    @ViewBuilder private var customSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SecureField("Passphrase", text: $customPass)
                .textFieldStyle(.roundedBorder)
            SecureField("Confirm passphrase", text: $customConfirm)
                .textFieldStyle(.roundedBorder)
                .onSubmit(tryCreate)

            // Strength meter (uses the same estimator the core enforces).
            StrengthMeter(score: customScore)

            if customScore < 4 && !customPass.isEmpty {
                Text("Must reach “Very strong” (4/4). Tip: 5+ random, unrelated words beat any short clever password.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !customConfirm.isEmpty && customPass != customConfirm {
                Text("Passphrases don't match.")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }

    private func regenerate() {
        if let g = vault.generatePassphrase() {
            generatedPass = g
            savedConfirmed = false
        }
    }

    func chooseSavePath() {
        // A FOLDER picker, deliberately — NOT a save panel. A save panel would
        // offer "Replace?", but we never overwrite a vault (irreversible data
        // loss). The name lives in the editable field below, and a collision is
        // auto-suffixed (-2, -3, …) at create time.
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = String(localized: "Choose Folder")
        panel.message = String(localized: "Choose the folder for the new vault. You'll set its name back in the Farewell window. An existing vault is never overwritten.")
        panel.directoryURL = LastLocation.directoryURL
        if panel.runModal() == .OK, let dir = panel.url {
            // Keep whatever name the field already had, else a clean "my".
            // The ".vault" extension is added (exactly once) at create time.
            let current = (path as NSString).lastPathComponent
            let name = current.isEmpty ? "my" : current
            let url = dir.appendingPathComponent(name)
            path = url.path
            LastLocation.remember(url)
        }
    }

    /// Ensure the path ends with exactly one ".vault" extension — so "my",
    /// "my.vault", and an accidental "my.vault.vault" all normalize to
    /// "my.vault". The engine doesn't add the extension, so the app must.
    private func withVaultExtension(_ p: String) -> String {
        var url = URL(fileURLWithPath: p)
        while url.pathExtension.lowercased() == "vault" {
            url = url.deletingPathExtension()
        }
        return url.appendingPathExtension("vault").path
    }

    /// First path that does not yet exist, by inserting `-2`, `-3`, … before the
    /// extension. We NEVER overwrite an existing vault, so creation falls back
    /// to a free name rather than replacing one.
    private func nonCollidingPath(_ p: String) -> String {
        let fm = FileManager.default
        guard fm.fileExists(atPath: p) else { return p }
        let url = URL(fileURLWithPath: p)
        let dir = url.deletingLastPathComponent()
        let ext = url.pathExtension                              // "vault"
        let stem = url.deletingPathExtension().lastPathComponent // "my"
        var n = 2
        while true {
            let candidateName = ext.isEmpty ? "\(stem)-\(n)" : "\(stem)-\(n).\(ext)"
            let candidate = dir.appendingPathComponent(candidateName).path
            if !fm.fileExists(atPath: candidate) { return candidate }
            n += 1
        }
    }

    func tryCreate() {
        guard canCreate else { return }
        // Decimal MB (as shown in Finder) → chunks. CHUNK_PLAINTEXT_LEN is
        // 64 KiB (65_536 bytes); 1 MB is 1_000_000 bytes. Round to the nearest
        // whole chunk silently — the on-disk size stays exact, the label is
        // just decimal. Clamp to a sane floor so a stray 0 can't make an
        // unusable vault.
        let mb = max(1, capacityMB)
        let chunkBytes: Double = 65_536           // 64 KiB
        let totalChunks = max(1, UInt64((Double(mb) * 1_000_000 / chunkBytes).rounded()))
        // Normalize to exactly one ".vault" extension, then never overwrite: if
        // the chosen name is taken, fall back to the next free "-N" name and
        // tell the user the final name.
        let target = withVaultExtension(path)
        let resolved = nonCollidingPath(target)
        if resolved != target {
            vault.renameNotice = String(localized: "“\((target as NSString).lastPathComponent)” already existed — created “\((resolved as NSString).lastPathComponent)” instead. A vault is never overwritten.")
        } else {
            vault.renameNotice = nil
        }
        vault.createVaultHw(
            path: resolved,
            passphrase: effectivePass,
            totalChunks: totalChunks,
            hwKeys: useHw ? (useBackupKey ? 2 : 1) : 0,
            pin: useHw ? hwPin : "",
            owner: (recordOwner && license.isLicensed) ? license.email : nil
        )
        customPass = ""
        customConfirm = ""
        generatedPass = ""
        savedConfirmed = false
        hwPin = ""
    }
}

/// A four-segment passphrase strength meter (zxcvbn 0–4).
struct StrengthMeter: View {
    let score: Int

    private var label: String {
        switch score {
        case 0: return "Very weak"
        case 1: return "Weak"
        case 2: return "Fair"
        case 3: return "Strong"
        default: return "Very strong"
        }
    }
    private var tint: Color {
        switch score {
        case 0, 1: return .red
        case 2: return .orange
        case 3: return .yellow
        default: return .green
        }
    }

    var body: some View {
        HStack(spacing: 8) {
            HStack(spacing: 3) {
                ForEach(0..<4) { i in
                    RoundedRectangle(cornerRadius: 2)
                        .fill(i < score ? tint : Color.secondary.opacity(0.25))
                        .frame(height: 6)
                }
            }
            Text(label)
                .font(.caption)
                .foregroundStyle(tint)
                .frame(width: 80, alignment: .leading)
        }
    }
}

struct HeaderView: View {
    @EnvironmentObject var vault: VaultModel
    @State private var showMigrate = false
    @State private var showKeysPanel = false

    /// Capacity-bar colour: turns amber past 75 % full, red past 90 %.
    private var capacityTint: Color {
        guard vault.info.spaceTotal > 0 else { return .accentColor }
        let used = Double(vault.info.spaceTotal - vault.info.spaceFree)
            / Double(vault.info.spaceTotal)
        if used >= 0.90 { return .red }
        if used >= 0.75 { return .orange }
        return .accentColor
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(URL(fileURLWithPath: vault.info.path).lastPathComponent)
                        .font(.headline)
                    Text(vault.info.path)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                Button {
                    showMigrate = true
                } label: {
                    Label("Migrate…", systemImage: "arrow.triangle.2.circlepath")
                }
                .help("Re-encrypt this vault into a fresh file (new keys, or a smaller size). Used to rotate keys or upgrade the format. The original is kept until you confirm.")
                // Keys management is always available on an open vault — to add
                // a first key (passphrase-only → hardware), add a backup, name
                // or revoke keys, or convert back to passphrase-only.
                Button {
                    vault.keysStatus = nil
                    showKeysPanel = true
                } label: {
                    Label("Keys…", systemImage: "key.fill")
                }
                .disabled(vault.busy)
                .help(vault.info.hwKeys == 0
                    ? "Add a hardware key so a physical key is required to open this vault — or just review that it's passphrase-only."
                    : "Name, add, or revoke the hardware keys that open this vault (\(vault.info.hwKeys) of \(Int(FAREWELL_MAX_HW_KEYS)) enrolled), or convert back to passphrase-only.")
                Button(role: .destructive) {
                    vault.close()
                } label: {
                    Label("Lock", systemImage: "lock.fill")
                }
            }
            if let url = vault.staleMigration {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    Text("An interrupted migration left “\(url.lastPathComponent)”. Your vault is intact.")
                        .font(.caption)
                    Button("Discard") { vault.discardStaleMigration() }
                        .font(.caption)
                }
            }
            if let status = vault.migrationStatus {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let note = vault.renameNotice {
                HStack(spacing: 6) {
                    Image(systemName: "info.circle").foregroundStyle(.blue)
                    Text(note).fixedSize(horizontal: false, vertical: true)
                    Button("Dismiss") { vault.renameNotice = nil }.font(.caption)
                }
                .font(.caption)
            }
            HStack(spacing: 14) {
                Label(
                    "\(formatBytes(vault.info.spaceFree)) free of \(formatBytes(vault.info.spaceTotal))",
                    systemImage: "internaldrive"
                )
                Label("counter \(vault.info.counter)", systemImage: "number")
                if vault.info.hwKeys == 1 {
                    // Single key = single point of failure: a tappable nudge to
                    // enrol a backup (opens the Keys panel).
                    Button {
                        vault.keysStatus = nil
                        showKeysPanel = true
                    } label: {
                        Label("1 key — add a backup", systemImage: "exclamationmark.triangle.fill")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.orange)
                    .help("This vault has only one hardware key. Lose it and the vault is gone — enrol a backup key.")
                } else if vault.info.hwKeys >= 2 {
                    Label("\(vault.info.hwKeys) hardware keys", systemImage: "key.fill")
                }
                if !vault.info.owner.isEmpty {
                    Label("created by \(vault.info.owner)", systemImage: "person.crop.circle")
                        .help("This vault records its creator's identity (opt-in).")
                        .lineLimit(1).truncationMode(.middle)
                }
                Spacer()
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            // Capacity bar.
            ProgressView(
                value: vault.info.spaceTotal > 0
                    ? Double(vault.info.spaceTotal - vault.info.spaceFree) / Double(vault.info.spaceTotal)
                    : 0
            )
            .progressViewStyle(.linear)
            .tint(capacityTint)
        }
        .padding(12)
        .sheet(isPresented: $showMigrate) {
            MigrateSheet()
        }
        .sheet(isPresented: $showKeysPanel) {
            KeysManagementSheet()
        }
    }
}

/// Sheet to enroll a second (backup) YubiKey on the open vault. Keys are
/// handled one at a time on a single USB port (insert current → swap → insert
/// new); the new key's entry is written into the slot in place. The sheet shows
/// the live step-by-step prompt itself, so the user follows it here (the
/// window's busy overlay is hidden behind this sheet).
/// The vault's "Keys" panel: review the hardware keys that open this vault,
/// name/add/revoke them, and convert between passphrase-only and
/// hardware-protected. Every operation needs the passphrase; revoking a
/// non-last key is passphrase-only (no touch), while adding a key or removing
/// the last one require the key to be present (a touch).
struct KeysManagementSheet: View {
    @EnvironmentObject var vault: VaultModel
    @Environment(\.dismiss) private var dismiss

    @State private var passphrase = ""
    @State private var pin = ""            // the CURRENT key's PIN (existing key)
    @State private var newKeyName = ""
    @State private var newKeyPin = ""      // the NEW key's own PIN (add-backup)
    /// We've attempted a key-list load at least once (so we can show the list
    /// area rather than just the passphrase prompt).
    @State private var loadedOnce = false
    /// Set while a touch flow (add / convert) runs, so we keep showing the
    /// live/result view across the brief busy toggles.
    @State private var touchFlowActive = false
    /// Pending confirmations.
    @State private var confirmRevokeIndex: Int? = nil
    @State private var confirmConvert = false

    private var maxKeys: Int { Int(FAREWELL_MAX_HW_KEYS) }
    private var atCap: Bool { vault.keys.count >= maxKeys }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Keys")
                .font(.title2).bold()

            if vault.busy {
                runningView
            } else {
                mainView
            }
        }
        .padding(22)
        .frame(width: 480)
        // When a touch flow finishes (busy true→false), refresh the list and
        // drop back to it with the result banner.
        .onChange(of: vault.busy) { _, isBusy in
            if !isBusy && touchFlowActive {
                touchFlowActive = false
                newKeyName = ""
                newKeyPin = ""
                if !passphrase.isEmpty { vault.loadKeys(passphrase: passphrase) }
            }
        }
        .onDisappear {
            passphrase = ""; pin = ""; newKeyName = ""; newKeyPin = ""
            vault.keysStatus = nil
        }
    }

    // -- Main: passphrase + key list + add/convert -------------------------
    @ViewBuilder private var mainView: some View {
        Text("Hardware-key management.")
            .fixedSize(horizontal: false, vertical: true)

        SecureField("Vault passphrase", text: $passphrase)
            .textFieldStyle(.roundedBorder)
            .onSubmit { reload() }
        SecureField("Current key's PIN (leave blank if no PIN or no key)", text: $pin)
            .textFieldStyle(.roundedBorder)

        if !loadedOnce {
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Show keys") { reload() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(passphrase.isEmpty)
            }
        } else {
            if vault.keysLoading {
                HStack(spacing: 8) { ProgressView().controlSize(.small); Text("Reading keys…") }
                    .foregroundStyle(.secondary)
            } else if vault.keysLoaded {
                // Only show the list + Add section once a read has SUCCEEDED, so
                // a failed read doesn't masquerade as "passphrase-only".
                keyListSection
                Divider()
                addSection
            }
            if let status = vault.keysStatus {
                Label(status, systemImage: status.hasPrefix("Could not")
                        ? "exclamationmark.triangle.fill" : "checkmark.seal.fill")
                    .font(.callout)
                    .foregroundStyle(status.hasPrefix("Could not") ? .orange : .green)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
    }

    @ViewBuilder private var keyListSection: some View {
        if vault.keys.isEmpty {
            Label("Passphrase-only — no hardware key enrolled.", systemImage: "lock")
                .foregroundStyle(.secondary)
        } else {
            if vault.keys.count == 1 {
                // No-recovery safety: a single key is a single point of failure.
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    Text("Only one key opens this vault. **Lose it and the vault is gone forever — there is no recovery.** Enrol a backup key below so either key works.")
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.callout)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            }
            VStack(alignment: .leading, spacing: 6) {
                ForEach(vault.keys) { key in
                    HStack(spacing: 10) {
                        Image(systemName: "key.fill").foregroundStyle(.secondary)
                        Text(key.name.isEmpty ? "Key \(key.index + 1)" : key.name)
                        Spacer()
                        Button(role: .destructive) {
                            // Removing the only key converts to passphrase-only
                            // (needs the key present); any other key is an
                            // instant, passphrase-only revoke.
                            if vault.keys.count <= 1 { confirmConvert = true }
                            else { confirmRevokeIndex = key.index }
                        } label: {
                            Text(vault.keys.count <= 1 ? "Remove (last)" : "Revoke")
                        }
                        .disabled(passphrase.isEmpty)
                    }
                    .padding(.vertical, 2)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .textBackgroundColor),
                        in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(.quaternary))
            .alert("Revoke this key?", isPresented: Binding(
                get: { confirmRevokeIndex != nil },
                set: { if !$0 { confirmRevokeIndex = nil } })) {
                Button("Cancel", role: .cancel) { confirmRevokeIndex = nil }
                Button("Revoke", role: .destructive) {
                    if let i = confirmRevokeIndex {
                        touchFlowActive = true   // reload the list when the op finishes
                        vault.removeKey(index: i, passphrase: passphrase, pin: pin)
                    }
                    confirmRevokeIndex = nil
                }
            } message: {
                Text("It will no longer open this vault; the other keys still will. Revoking uses only your passphrase, then you'll touch a remaining key once to reopen the vault.")
            }
            .alert("Remove your last key?", isPresented: $confirmConvert) {
                Button("Cancel", role: .cancel) { confirmConvert = false }
                Button("Remove last key", role: .destructive) {
                    confirmConvert = false
                    touchFlowActive = true
                    vault.convertToPassphraseOnly(passphrase: passphrase, pin: pin)
                }
            } message: {
                Text("This turns the vault back into passphrase-only: the passphrase alone will open it, and opening becomes slower again (by design). Insert the key now — you'll touch it once so it can be safely removed.")
            }
        }
    }

    @ViewBuilder private var addSection: some View {
        let isFirst = vault.keys.isEmpty
        VStack(alignment: .leading, spacing: 8) {
            Text(isFirst ? "Add a hardware key" : "Add a backup key")
                .font(.callout).fontWeight(.semibold)
            if isFirst {
                Text("Require a physical key (plus your passphrase) to open this vault. Insert the new key and touch it twice to enrol.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                // The #1 point of confusion: the first key to insert and touch is
                // the CURRENT one, NOT the new backup. Make the order impossible
                // to miss with a highlighted, numbered callout right above the
                // button — the buried gray caption was not enough.
                VStack(alignment: .leading, spacing: 6) {
                    Text("Adding a backup happens in two steps — and the order matters:")
                        .fontWeight(.semibold)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("**1.** First insert your **current key** (the one that already opens this vault) and touch it — **not the new key yet**.")
                        .fixedSize(horizontal: false, vertical: true)
                    Text("**2.** Only then, when asked, swap to the **new backup key** and touch it twice.")
                        .fixedSize(horizontal: false, vertical: true)
                    Text("Either key will then open the vault. Keep the backup somewhere safe and separate — there's no recovery if you lose every key.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.caption)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.accentColor.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.accentColor.opacity(0.35)))
            }
            // The new key carries its OWN PIN — never assume it matches the
            // current key's. (For the first key there is no current key, so the
            // field above is irrelevant and only this one is used.)
            SecureField(isFirst ? "Set/enter this key's PIN (leave blank if none)"
                               : "New key's PIN (leave blank if none)",
                        text: $newKeyPin)
                .textFieldStyle(.roundedBorder)
            HStack {
                TextField("Name (optional)", text: $newKeyName)
                    .textFieldStyle(.roundedBorder)
                Button(isFirst ? "Add key…" : "Add backup…") {
                    touchFlowActive = true
                    vault.addBackupKey(name: newKeyName, passphrase: passphrase,
                                       pin: pin, newPin: newKeyPin, isFirst: isFirst)
                }
                .disabled(passphrase.isEmpty || atCap)
            }
            if atCap {
                Text("This vault already has the maximum of \(maxKeys) keys.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    // -- Live view while a touch flow runs (this panel hosts the whole flow:
    // the live insert/remove/touch prompts, then the result banner). ---------
    @ViewBuilder private var runningView: some View {
        HStack(spacing: 12) {
            // Key icon while waiting on the user's key; gear while computing —
            // mirrors the main-window overlay so the cue is consistent.
            Image(systemName: vault.busyIsKeyStep ? "key.radiowaves.forward" : "gearshape.2")
                .font(.system(size: 22))
                .symbolEffect(.pulse)
            Text(vault.busyMessage.isEmpty ? "Working…" : vault.busyMessage)
                .font(.headline)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 4)

        Text("Follow the prompts on your key — insert, swap, and touch as asked. Don't unplug a key unless you're told to.")
            .font(.callout)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .textBackgroundColor),
                        in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(.quaternary))
    }

    private func reload() {
        guard !passphrase.isEmpty else { return }
        loadedOnce = true
        vault.keysStatus = nil   // user-initiated reload clears any stale banner
        vault.loadKeys(passphrase: passphrase)
    }
}

/// Wizard for migrating / rotating the open vault into a fresh file, with the
/// disk-space pre-flight surfaced live.
struct MigrateSheet: View {
    @EnvironmentObject var vault: VaultModel
    @Environment(\.dismiss) private var dismiss

    @State private var capacity: VaultModel.MigrateCapacity = .same
    @State private var destDir: URL
    @State private var passphrase = ""
    @State private var useHw = false
    @State private var pin = ""

    init() {
        // Default destination = the current vault's own folder (enables the
        // atomic in-place swap).
        let dir = URL(fileURLWithPath: "")
        _destDir = State(initialValue: dir)
    }

    private var needed: UInt64 { vault.estimatedNewVaultBytes(capacity) }
    private var free: UInt64 { vault.freeBytes(at: destDir) }
    private var fits: Bool { needed <= free }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            sizeSection
            destinationSection
            spacePreflight
            Divider()
            authSection
            buttons
        }
        .padding(24)
        .frame(width: 480)
        .onAppear {
            // Default the destination to the vault's own folder.
            destDir = URL(fileURLWithPath: vault.info.path).deletingLastPathComponent()
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Migrate / rotate vault")
                .font(.title3.weight(.semibold))
            Text(explainer)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var explainer: String {
        String(localized: "Re-encrypts everything into a brand-new vault file with fresh keys (the same passphrase). Your files are copied and verified before anything is replaced; nothing is written to disk in the clear. The original is kept until you delete it.")
    }

    private var sizeSection: some View {
        Picker("New size", selection: $capacity) {
            Text("Keep current capacity").tag(VaultModel.MigrateCapacity.same)
            Text("Shrink to fit contents").tag(VaultModel.MigrateCapacity.shrink)
        }
        .pickerStyle(.radioGroup)
    }

    private var destinationSection: some View {
        HStack {
            Text("Destination:")
            Text(destDir.path)
                .lineLimit(1)
                .truncationMode(.middle)
                .foregroundStyle(.secondary)
            Button("Choose…") { chooseDestination() }
        }
        .font(.callout)
    }

    private var spacePreflight: some View {
        let icon = fits ? "internaldrive" : "exclamationmark.triangle.fill"
        let tint: Color = fits ? .secondary : .orange
        return HStack(spacing: 6) {
            Image(systemName: icon).foregroundStyle(tint)
            Text("Needs about \(formatBytes(needed)); \(formatBytes(free)) free here.")
                .font(.caption)
                .foregroundStyle(tint)
        }
    }

    @ViewBuilder
    private var authSection: some View {
        SecureField("Passphrase", text: $passphrase)
            .textFieldStyle(.roundedBorder)
        Toggle("This vault requires a YubiKey", isOn: $useHw)
            .toggleStyle(.checkbox)
        if useHw {
            SecureField("YubiKey PIN", text: $pin)
                .textFieldStyle(.roundedBorder)
        }
    }

    private var buttons: some View {
        HStack {
            Spacer()
            Button("Cancel", role: .cancel) { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button("Migrate") {
                vault.migrate(
                    capacity: capacity, destDir: destDir,
                    passphrase: passphrase, useHw: useHw, pin: pin)
                dismiss()
            }
            .keyboardShortcut(.defaultAction)
            .disabled(passphrase.isEmpty || !fits)
        }
    }

    private func chooseDestination() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = String(localized: "Use Folder")
        panel.directoryURL = destDir
        if panel.runModal() == .OK, let url = panel.url {
            destDir = url
        }
    }
}

/// A node in the file/folder tree shown in the left pane.
struct TreeNode: Identifiable {
    let id: String          // folder path, or file's full name
    let title: String       // leaf component
    let isFolder: Bool
    let size: UInt64
    var children: [TreeNode]?   // nil = file (leaf); non-nil = folder
}

/// Build a folder/file tree from the flat manifest (file names with
/// slash prefixes) plus the explicit folder list.
func buildTree(files: [VaultModel.FileEntry], folders: [String]) -> [TreeNode] {
    func parentKey(_ path: String) -> String {
        if let i = path.lastIndex(of: "/") { return String(path[..<i]) }
        return ""
    }
    func leaf(_ path: String) -> String {
        if let i = path.lastIndex(of: "/") { return String(path[path.index(after: i)...]) }
        return path
    }
    var folderChildren: [String: [String]] = [:]
    for f in folders { folderChildren[parentKey(f), default: []].append(f) }
    var fileChildren: [String: [VaultModel.FileEntry]] = [:]
    for e in files { fileChildren[parentKey(e.name), default: []].append(e) }

    func nodes(under parent: String) -> [TreeNode] {
        var out: [TreeNode] = []
        for fp in (folderChildren[parent] ?? []).sorted() {
            out.append(TreeNode(
                id: fp, title: leaf(fp), isFolder: true, size: 0,
                children: nodes(under: fp)))
        }
        for e in (fileChildren[parent] ?? []).sorted(by: { $0.name < $1.name }) {
            out.append(TreeNode(
                id: e.name, title: leaf(e.name), isFolder: false,
                size: e.size, children: nil))
        }
        return out
    }
    return nodes(under: "")
}

struct FileListView: View {
    @EnvironmentObject var vault: VaultModel
    @State private var isDropTargeted = false

    // File rename / delete.
    @State private var renameTarget: String?
    @State private var renameText: String = ""
    @State private var deleteTarget: String?

    // Folder ops.
    @State private var newFolderParent: String?     // nil = sheet hidden; "" = root
    @State private var newFolderName: String = ""
    @State private var folderRenameTarget: String?
    @State private var folderRenameText: String = ""
    @State private var deleteFolderTarget: String?

    /// Live filter over file names. Empty → show the normal folder tree.
    @State private var searchText: String = ""

    private var roots: [TreeNode] {
        buildTree(files: vault.files, folders: vault.folders)
    }

    /// Files whose name (incl. folder prefix) contains the search query,
    /// case-insensitive, sorted. Empty query → no flat results (tree is shown).
    private var matchingFiles: [VaultModel.FileEntry] {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return [] }
        return vault.files
            .filter { $0.name.lowercased().contains(q) }
            .sorted { $0.name.lowercased() < $1.name.lowercased() }
    }

    private func fileRow(_ file: VaultModel.FileEntry) -> some View {
        HStack(spacing: 8) {
            Image(systemName: iconName(for: file.name)).foregroundStyle(.secondary)
            Text(file.name).lineLimit(1).truncationMode(.middle)
            Spacer()
            Text(formatBytes(file.size)).font(.caption).foregroundStyle(.secondary)
        }
    }

    /// Where the bottom "New folder" button creates: inside the
    /// selected folder (or the selected file's folder), else at root.
    private func newFolderTargetParent() -> String {
        guard let sel = vault.selectedFileID else { return "" }
        if vault.folders.contains(sel) { return sel }            // a folder is selected
        return (sel as NSString).deletingLastPathComponent       // a file → its folder ("" if root)
    }

    private var newFolderButtonTitle: String {
        let p = newFolderTargetParent()
        return p.isEmpty ? "New folder" : "New folder in “\((p as NSString).lastPathComponent)”"
    }

    var body: some View {
        VStack(spacing: 0) {
            // Search bar — only when the vault holds something to search.
            if !(vault.files.isEmpty && vault.folders.isEmpty) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Search files…", text: $searchText)
                        .textFieldStyle(.plain)
                    if !searchText.isEmpty {
                        Button { searchText = "" } label: {
                            Image(systemName: "xmark.circle.fill")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.secondary)
                        .help("Clear search")
                    }
                }
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor),
                            in: RoundedRectangle(cornerRadius: 6))
                .padding(.horizontal, 8)
                .padding(.top, 8)
            }

            Group {
                if vault.files.isEmpty && vault.folders.isEmpty {
                    EmptyVaultView()
                        // A SwiftUI List consumes drag events over its own
                        // area, so the Finder-file import drop must live on
                        // the content itself (here and on the List below),
                        // not on an ancestor container.
                        .onDrop(of: [UTType.fileURL], isTargeted: $isDropTargeted,
                                perform: handleFileDrop)
                } else if !searchText.isEmpty {
                    // Search active → flat list of matching files (no folders,
                    // no drop target — importing belongs to the normal view).
                    List(selection: $vault.selectedFileID) {
                        if matchingFiles.isEmpty {
                            Text("No file matches “\(searchText)”.")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(matchingFiles, id: \.name) { file in
                                fileRow(file).tag(file.name)
                            }
                        }
                    }
                } else {
                    List(selection: $vault.selectedFileID) {
                        OutlineGroup(roots, children: \.children) { node in
                            row(node)
                        }
                    }
                    .onDrop(of: [UTType.fileURL], isTargeted: $isDropTargeted,
                            perform: handleFileDrop)
                }
            }
            .overlay {
                if isDropTargeted {
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(Color.accentColor, lineWidth: 3)
                        .background(Color.accentColor.opacity(0.08))
                        .overlay {
                            Label("Drop to import into the vault", systemImage: "square.and.arrow.down")
                                .font(.headline)
                                .foregroundStyle(Color.accentColor)
                        }
                        .padding(4)
                        .allowsHitTesting(false)
                }
            }

            Divider()
            HStack {
                Button {
                    newFolderName = ""
                    newFolderParent = newFolderTargetParent()
                } label: {
                    Label(newFolderButtonTitle, systemImage: "folder.badge.plus")
                }
                Spacer()
            }
            .padding(.horizontal, 10)
            .padding(.top, 6)
            ImportBar()
        }
        .sheet(isPresented: Binding(
            get: { renameTarget != nil },
            set: { if !$0 { renameTarget = nil } }
        )) {
            RenameSheet(
                originalName: (renameTarget.map { ($0 as NSString).lastPathComponent }) ?? "",
                text: $renameText,
                onConfirm: {
                    if let old = renameTarget {
                        // Keep the file in its folder: rebuild the full
                        // path from the old parent + the new leaf.
                        let parent = (old as NSString).deletingLastPathComponent
                        let leaf = renameText.trimmingCharacters(in: .whitespacesAndNewlines)
                        let target = parent.isEmpty ? leaf : "\(parent)/\(leaf)"
                        vault.renameFile(old, to: target)
                    }
                    renameTarget = nil
                },
                onCancel: { renameTarget = nil }
            )
        }
        .sheet(isPresented: Binding(
            get: { newFolderParent != nil },
            set: { if !$0 { newFolderParent = nil } }
        )) {
            NewFolderSheet(
                parent: newFolderParent ?? "",
                name: $newFolderName,
                onConfirm: {
                    let parent = newFolderParent ?? ""
                    let leaf = newFolderName.trimmingCharacters(in: .whitespacesAndNewlines)
                    let path = parent.isEmpty ? leaf : "\(parent)/\(leaf)"
                    vault.createFolder(path)
                    newFolderParent = nil
                },
                onCancel: { newFolderParent = nil }
            )
        }
        .sheet(isPresented: Binding(
            get: { folderRenameTarget != nil },
            set: { if !$0 { folderRenameTarget = nil } }
        )) {
            RenameSheet(
                originalName: (folderRenameTarget.map { ($0 as NSString).lastPathComponent }) ?? "",
                text: $folderRenameText,
                onConfirm: {
                    if let old = folderRenameTarget {
                        let parent = (old as NSString).deletingLastPathComponent
                        let leaf = folderRenameText.trimmingCharacters(in: .whitespacesAndNewlines)
                        let target = parent.isEmpty ? leaf : "\(parent)/\(leaf)"
                        vault.renameFolder(old, to: target)
                    }
                    folderRenameTarget = nil
                },
                onCancel: { folderRenameTarget = nil }
            )
        }
        .alert(
            "Delete this file?",
            isPresented: Binding(
                get: { deleteTarget != nil },
                set: { if !$0 { deleteTarget = nil } }
            ),
            presenting: deleteTarget
        ) { name in
            Button("Delete", role: .destructive) {
                vault.deleteFile(name); deleteTarget = nil
            }
            Button("Cancel", role: .cancel) { deleteTarget = nil }
        } message: { name in
            Text("“\((name as NSString).lastPathComponent)” will be permanently removed and its encrypted chunks securely shredded. This cannot be undone — there is no recovery, by design.")
        }
        .alert(
            "Delete this folder?",
            isPresented: Binding(
                get: { deleteFolderTarget != nil },
                set: { if !$0 { deleteFolderTarget = nil } }
            ),
            presenting: deleteFolderTarget
        ) { path in
            Button("Delete", role: .destructive) {
                vault.deleteFolder(path); deleteFolderTarget = nil
            }
            Button("Cancel", role: .cancel) { deleteFolderTarget = nil }
        } message: { path in
            Text("“\((path as NSString).lastPathComponent)” and ALL its contents will be permanently removed and securely shredded. This cannot be undone.")
        }
    }

    /// Import files dropped from Finder. Resolves each provider's file URL
    /// (completions fire on arbitrary threads → collect via URLBox), then
    /// imports on the main thread.
    private func handleFileDrop(_ providers: [NSItemProvider]) -> Bool {
        let box = URLBox()
        let group = DispatchGroup()
        for p in providers where p.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            group.enter()
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                if let url, url.isFileURL { box.add(url) }
                group.leave()
            }
        }
        group.notify(queue: .main) {
            let urls = box.take()
            if !urls.isEmpty { vault.importFiles(urls) }
        }
        return true
    }

    // -- Row rendering --------------------------------------------------

    @ViewBuilder
    private func row(_ node: TreeNode) -> some View {
        if node.isFolder {
            HStack(spacing: 8) {
                Image(systemName: "folder.fill").foregroundStyle(.secondary)
                Text(node.title)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
            }
            .padding(.vertical, 5)
            .help(node.title)
            .draggable(node.id)   // a folder can be dragged into another
            .contextMenu {
                Button {
                    newFolderName = ""
                    newFolderParent = node.id
                } label: { Label("New subfolder…", systemImage: "folder.badge.plus") }
                Button {
                    folderRenameText = node.title
                    folderRenameTarget = node.id
                } label: { Label("Rename folder…", systemImage: "pencil") }
                if node.id.contains("/") {
                    Button {
                        vault.moveItem(node.id, intoFolder: "")
                    } label: { Label("Move to top level", systemImage: "arrow.up.to.line") }
                }
                Divider()
                Button(role: .destructive) {
                    deleteFolderTarget = node.id
                } label: { Label("Delete folder", systemImage: "trash") }
            }
            // Accept a file OR a folder dragged onto this folder.
            .dropDestination(for: String.self) { ids, _ in
                for item in ids { vault.moveItem(item, intoFolder: node.id) }
                return !ids.isEmpty
            }
        } else {
            HStack(spacing: 8) {
                Image(systemName: iconName(for: node.title)).foregroundStyle(.secondary)
                Text(node.title)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 8)
                Text(formatBytes(node.size))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 5)
            .help(node.title)
            .draggable(node.id)   // drag a file onto a folder to move it
            .contextMenu {
                Button {
                    renameText = node.title
                    renameTarget = node.id
                } label: { Label("Rename…", systemImage: "pencil") }
                if node.id.contains("/") {
                    Button {
                        vault.moveFile(node.id, toFolder: "")
                    } label: { Label("Move to top level", systemImage: "arrow.up.to.line") }
                }
                Divider()
                Button(role: .destructive) {
                    deleteTarget = node.id
                } label: { Label("Delete", systemImage: "trash") }
            }
        }
    }
}

/// Sheet to name a new folder.
struct NewFolderSheet: View {
    let parent: String
    @Binding var name: String
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(parent.isEmpty ? "New folder" : "New folder in “\((parent as NSString).lastPathComponent)”")
                .font(.title3.weight(.semibold))
            TextField("Folder name", text: $name)
                .textFieldStyle(.roundedBorder)
                .onSubmit(onConfirm)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Button("Create", action: onConfirm)
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 380)
    }
}

/// Modal sheet for renaming a vault file. A plain text field plus
/// Cancel / Rename. Confirms on Return.
struct RenameSheet: View {
    let originalName: String
    @Binding var text: String
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Rename file")
                .font(.title3.weight(.semibold))
            Text("Renaming “\(originalName)”. The encrypted content is unchanged; only the name in the manifest is updated.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("New name", text: $text)
                .textFieldStyle(.roundedBorder)
                .onSubmit(onConfirm)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Button("Rename", action: onConfirm)
                    .keyboardShortcut(.defaultAction)
                    .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 420)
    }
}

/// Footer below the file list: Import button, secure-shred toggle,
/// and a transient status line after an import.
struct ImportBar: View {
    @EnvironmentObject var vault: VaultModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Button {
                    pickAndImport()
                } label: {
                    Label("Import…", systemImage: "square.and.arrow.down")
                }
                Button {
                    vault.newNote()
                } label: {
                    Label("New note", systemImage: "square.and.pencil")
                }
                .help("Create a new empty note and open it in the editor. It lives only inside the encrypted vault.")
                Spacer()
                if vault.shredOriginalsAfterImport {
                    Picker("Passes", selection: $vault.shredPasses) {
                        Text("1 pass").tag(1)
                        Text("3 passes").tag(3)
                        Text("7 passes").tag(7)
                    }
                    .labelsHidden()
                    .frame(width: 110)
                    .help("Overwrite passes. 1 is enough on any modern drive; 3/7 exist only for standards that mandate them and add nothing on an SSD.")
                }
                Toggle(isOn: $vault.shredOriginalsAfterImport) {
                    Text("Shred originals")
                }
                .toggleStyle(.checkbox)
                .help("After importing, securely overwrite and delete the source file. On a hard disk this physically erases it; on an SSD wear-leveling means it's best-effort only (no guarantee) — the real protection is the encrypted vault.")
            }
            if let status = vault.importStatus {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            } else {
                Text("Drag files here, or click Import. Files are encrypted into the vault; nothing is written elsewhere.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .lineLimit(2)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        // A guaranteed drop zone: this bar is a plain VStack (not a List),
        // so onDrop always fires here even if the list above swallows it.
        .onDrop(of: [UTType.fileURL], isTargeted: nil) { providers in
            let box = URLBox()
            let group = DispatchGroup()
            for p in providers where p.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
                group.enter()
                _ = p.loadObject(ofClass: URL.self) { url, _ in
                    if let url, url.isFileURL { box.add(url) }
                    group.leave()
                }
            }
            group.notify(queue: .main) {
                let urls = box.take()
                if !urls.isEmpty { vault.importFiles(urls) }
            }
            return true
        }
    }

    func pickAndImport() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        if panel.runModal() == .OK {
            vault.importFiles(panel.urls)
        }
    }
}

struct EmptyVaultView: View {
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: "tray")
                .font(.system(size: 40))
                .foregroundStyle(.tertiary)
            Text("This vault contains no files.")
                .foregroundStyle(.secondary)
            Text("Drag files here, or use Import below.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// =============================================================================
// Audio playback (in-app, streamed from RAM)
// =============================================================================

/// Streams PCM from the Rust (Symphonia) decoder into `AVAudioEngine`.
///
/// All engine/decoder state is touched only on a private serial queue;
/// `@Published` UI state is marshalled to the main thread. The compressed
/// bytes live in RAM for the player's lifetime and the decode is in-process
/// — nothing is ever written to disk.
final class AudioPlayer: ObservableObject, @unchecked Sendable {
    @Published var isPlaying = false
    @Published var positionSeconds: Double = 0
    @Published var durationSeconds: Double = 0   // 0 = unknown (no slider)
    @Published var failed: String?
    /// Per-bucket peak amplitudes (0…1) for the waveform; empty until computed.
    @Published var waveform: [Float] = []

    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private let q = DispatchQueue(label: "app.farewell.audio")

    private var decoder: OpaquePointer?
    private var format: AVAudioFormat?
    private var sampleRate: Double = 44_100
    private var channels: Int = 2
    private var totalFrames: Int64 = 0
    private var attached = false

    /// Bumped on stop/seek so stale scheduleBuffer completions are ignored.
    private var generation = 0
    private var atEnd = false
    /// Buffers scheduled but not yet consumed (current generation).
    private var inFlight = 0
    /// Frames before the current play segment (for position after a seek).
    private var seekBaseFrame: Int64 = 0
    private var posTimer: Timer?

    private let framesPerBuffer = 8192

    // -- Public API (call from the UI) --------------------------------

    func load(_ data: Data) { q.async { [weak self] in self?.doLoad(data) } }
    func togglePlay() { q.async { [weak self] in self?.doToggle() } }
    func stop() { q.async { [weak self] in self?.teardown() } }

    func seek(toFraction f: Double) {
        q.async { [weak self] in
            guard let self, self.totalFrames > 0 else { return }
            let frame = Int64(Double(self.totalFrames) * min(max(f, 0), 1))
            self.seekTo(frame)
        }
    }

    deinit { if let d = decoder { farewell_audio_close(d) } }

    // -- Implementation (serial queue) --------------------------------

    private func doLoad(_ data: Data) {
        teardown()
        var info = FarewellAudioInfo()
        let dec = data.withUnsafeBytes { raw -> OpaquePointer? in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return farewell_audio_open(base, UInt64(data.count), &info)
        }
        guard let dec else {
            publish { $0.failed = "This audio format can't be played in the app." }
            return
        }
        decoder = dec
        sampleRate = Double(info.sample_rate)
        channels = Int(max(1, info.channels))
        totalFrames = Int64(info.total_frames)
        guard let fmt = AVAudioFormat(
            commonFormat: .pcmFormatFloat32,
            sampleRate: sampleRate,
            channels: AVAudioChannelCount(channels),
            interleaved: false
        ) else {
            publish { $0.failed = "Unsupported audio layout." }
            return
        }
        format = fmt
        if !attached {
            engine.attach(player)
            attached = true
        }
        engine.connect(player, to: engine.mainMixerNode, format: fmt)
        do { try engine.start() } catch {
            publish { $0.failed = "Could not start audio." }
            return
        }

        seekBaseFrame = 0
        atEnd = false
        inFlight = 0
        let dur = totalFrames > 0 ? Double(totalFrames) / sampleRate : 0
        publish { $0.failed = nil; $0.durationSeconds = dur; $0.positionSeconds = 0 }

        // Prime buffers so the first ▶︎ is instant, but DON'T autoplay:
        // unexpected sound is an operational hazard for this audience, and
        // people select files to inspect, not necessarily to listen. The
        // user starts playback explicitly.
        let gen = generation
        for _ in 0..<3 { scheduleNext(gen) }
        publish { $0.isPlaying = false }

        // Compute the waveform off this serial queue (a full decode pass) and
        // publish it when ready, so playback setup isn't blocked.
        let wfData = data
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let buckets = 700
            var peaks = [Float](repeating: 0, count: buckets)
            let ok = wfData.withUnsafeBytes { raw -> Bool in
                guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return false }
                return farewell_audio_waveform(
                    base, UInt64(wfData.count), UInt64(buckets), &peaks) == .ffi_ok
            }
            if ok {
                let result = peaks
                self?.publish { $0.waveform = result }
            }
        }
    }

    private func doToggle() {
        guard decoder != nil else { return }
        if player.isPlaying {
            player.pause()
            publish { $0.isPlaying = false }
            stopPosTimer()
        } else {
            if atEnd { seekTo(0) }
            player.play()
            publish { $0.isPlaying = true }
            startPosTimer()
        }
    }

    private func seekTo(_ frame: Int64) {
        guard let dec = decoder else { return }
        let wasPlaying = player.isPlaying
        generation += 1
        player.stop()                       // clears the schedule, resets sampleTime
        _ = farewell_audio_seek(dec, UInt64(max(0, frame)))
        seekBaseFrame = frame
        atEnd = false
        inFlight = 0
        let gen = generation
        for _ in 0..<3 { scheduleNext(gen) }
        if wasPlaying {
            player.play()
            publish { $0.isPlaying = true }
            startPosTimer()
        }
        let secs = Double(frame) / sampleRate
        publish { $0.positionSeconds = secs }
    }

    /// Pull one buffer from the decoder and schedule it; its completion
    /// schedules the next. `gen` guards against post-seek/stop staleness.
    private func scheduleNext(_ gen: Int) {
        guard gen == generation else { return }
        if atEnd {
            if inFlight == 0 { finishPlayback() }
            return
        }
        guard let dec = decoder, let fmt = format else { return }
        let cap = framesPerBuffer * channels
        var inter = [Float](repeating: 0, count: cap)
        let got = inter.withUnsafeMutableBufferPointer {
            farewell_audio_read(dec, $0.baseAddress, UInt64(cap))
        }
        if got <= 0 {
            atEnd = true
            if inFlight == 0 { finishPlayback() }
            return
        }
        let frames = AVAudioFrameCount(Int(got) / channels)
        guard frames > 0, let buf = AVAudioPCMBuffer(pcmFormat: fmt, frameCapacity: frames) else {
            atEnd = true
            if inFlight == 0 { finishPlayback() }
            return
        }
        buf.frameLength = frames
        if let chans = buf.floatChannelData {
            for c in 0..<channels {
                let dst = chans[c]
                for i in 0..<Int(frames) { dst[i] = inter[i * channels + c] }
            }
        }
        inFlight += 1
        player.scheduleBuffer(buf, completionCallbackType: .dataConsumed) { [weak self] _ in
            self?.q.async { [weak self] in
                guard let self, gen == self.generation else { return }
                self.inFlight -= 1
                self.scheduleNext(gen)
            }
        }
    }

    /// End-of-stream: stop the clock, pin the position to the end, and
    /// leave `atEnd` set so the next play() restarts from 0.
    private func finishPlayback() {
        player.stop()
        stopPosTimer()
        publish { p in
            p.isPlaying = false
            if p.durationSeconds > 0 { p.positionSeconds = p.durationSeconds }
        }
    }

    private func teardown() {
        generation += 1
        if engine.isRunning {
            player.stop()
            engine.stop()
        }
        if let d = decoder { farewell_audio_close(d); decoder = nil }
        atEnd = false
        inFlight = 0
        seekBaseFrame = 0
        stopPosTimer()
        publish { $0.isPlaying = false }
    }

    // -- Position timer (main thread) ---------------------------------

    private func startPosTimer() {
        DispatchQueue.main.async {
            self.posTimer?.invalidate()
            let t = Timer(timeInterval: 0.1, repeats: true) { [weak self] _ in
                self?.q.async { [weak self] in self?.sampleCurrentPosition() }
            }
            RunLoop.main.add(t, forMode: .common)
            self.posTimer = t
        }
    }
    private func stopPosTimer() {
        DispatchQueue.main.async { self.posTimer?.invalidate(); self.posTimer = nil }
    }
    private func sampleCurrentPosition() {
        guard let nodeTime = player.lastRenderTime,
              let playerTime = player.playerTime(forNodeTime: nodeTime) else { return }
        var s = Double(seekBaseFrame + playerTime.sampleTime) / sampleRate
        if totalFrames > 0 { s = min(s, Double(totalFrames) / sampleRate) }
        let secs = max(0, s)
        publish { $0.positionSeconds = secs }
    }

    /// Apply a mutation to the published state on the main thread.
    private func publish(_ mutate: @escaping @Sendable (AudioPlayer) -> Void) {
        DispatchQueue.main.async { mutate(self) }
    }
}

/// The audio transport shown in the viewer: play/pause, an optional
/// scrubber, and elapsed / total time. Owns one `AudioPlayer`.
/// The real waveform: per-bucket amplitude bars (played portion in the accent
/// colour, the rest dimmed), a playhead line, and click/drag-to-seek.
struct WaveformView: View {
    let peaks: [Float]
    let progress: Double                 // 0…1 playhead position
    let onScrub: (Double) -> Void        // live preview while dragging
    let onCommit: (Double) -> Void       // final seek on release / click

    var body: some View {
        GeometryReader { geo in
            let w = max(geo.size.width, 1)
            Canvas { ctx, size in
                let midY = size.height / 2
                guard !peaks.isEmpty else {
                    var line = Path()
                    line.move(to: CGPoint(x: 0, y: midY))
                    line.addLine(to: CGPoint(x: size.width, y: midY))
                    ctx.stroke(line, with: .color(.secondary.opacity(0.25)), lineWidth: 1)
                    return
                }
                let n = peaks.count
                let step = size.width / CGFloat(n)
                let barW = max(1, step * 0.7)
                let playX = size.width * CGFloat(min(max(progress, 0), 1))
                for i in 0..<n {
                    let x = CGFloat(i) * step + step / 2
                    let barH = max(1.5, CGFloat(peaks[i]) * size.height * 0.9)
                    let rect = CGRect(x: x - barW / 2, y: midY - barH / 2,
                                      width: barW, height: barH)
                    let color: Color = x <= playX ? .accentColor : .secondary.opacity(0.35)
                    ctx.fill(Path(roundedRect: rect, cornerRadius: barW / 2), with: .color(color))
                }
                var ph = Path()
                ph.move(to: CGPoint(x: playX, y: 0))
                ph.addLine(to: CGPoint(x: playX, y: size.height))
                ctx.stroke(ph, with: .color(.primary.opacity(0.7)), lineWidth: 1.5)
            }
            .contentShape(Rectangle())
            .gesture(
                DragGesture(minimumDistance: 0)
                    .onChanged { v in onScrub(Double(min(max(v.location.x / w, 0), 1))) }
                    .onEnded { v in onCommit(Double(min(max(v.location.x / w, 0), 1))) }
            )
        }
    }
}

struct AudioPlayerView: View {
    let data: Data
    @StateObject private var player = AudioPlayer()
    @State private var scrubbing = false
    @State private var scrubFraction = 0.0

    /// Playhead fraction: the live scrub while dragging, else play position.
    private var fraction: Double {
        if scrubbing { return scrubFraction }
        guard player.durationSeconds > 0 else { return 0 }
        return min(max(player.positionSeconds / player.durationSeconds, 0), 1)
    }
    private var displaySeconds: Double {
        scrubbing ? scrubFraction * player.durationSeconds : player.positionSeconds
    }

    var body: some View {
        VStack(spacing: 16) {
            Spacer()
            if let err = player.failed {
                Image(systemName: "waveform")
                    .font(.system(size: 40))
                    .foregroundStyle(.secondary)
                Text(err)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            } else {
                WaveformView(
                    peaks: player.waveform,
                    progress: fraction,
                    onScrub: { f in scrubbing = true; scrubFraction = f },
                    onCommit: { f in
                        if player.durationSeconds > 0 {
                            // Update the published position synchronously so the
                            // playhead doesn't flash back to the old spot while
                            // the async seek runs (the seek republishes the same
                            // value). Avoids the visible "sweep" on release.
                            player.positionSeconds = f * player.durationSeconds
                            player.seek(toFraction: f)
                        }
                        scrubbing = false
                    }
                )
                .frame(height: 96)
                .padding(.horizontal, 24)

                HStack(spacing: 16) {
                    Button {
                        player.togglePlay()
                    } label: {
                        Image(systemName: player.isPlaying ? "pause.circle.fill" : "play.circle.fill")
                            .font(.system(size: 40))
                    }
                    .buttonStyle(.plain)
                    Text(timeString(displaySeconds))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(timeString(player.durationSeconds))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 24)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { player.load(data) }
        .onDisappear { player.stop() }
    }

    private func timeString(_ s: Double) -> String {
        guard s.isFinite, s >= 0 else { return "0:00" }
        let total = Int(s.rounded(.down))
        return String(format: "%d:%02d", total / 60, total % 60)
    }
}

// =============================================================================
// Video playback (in-app, fed from RAM, our own fullscreen — no QuickTime)
// =============================================================================

/// Serves in-memory video bytes to AVPlayer via a custom URL scheme so
/// playback needs no file path and writes nothing to disk. VideoToolbox
/// decodes in-process; we render in our own layer (never AVKit/QuickTime).
final class InMemoryAssetLoader: NSObject, AVAssetResourceLoaderDelegate {
    static let scheme = "farewellmem"
    private let data: Data
    private let contentType: String

    init(data: Data, contentType: String) {
        self.data = data
        self.contentType = contentType
        super.init()
    }

    func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource req: AVAssetResourceLoadingRequest
    ) -> Bool {
        if let info = req.contentInformationRequest {
            info.contentType = contentType
            info.contentLength = Int64(data.count)
            info.isByteRangeAccessSupported = true
        }
        if let dr = req.dataRequest {
            let start = Int(dr.currentOffset)
            if start < data.count {
                let len = min(Int(dr.requestedLength), data.count - start)
                if len > 0 { dr.respond(with: data.subdata(in: start ..< start + len)) }
            }
        }
        req.finishLoading()
        return true
    }
}

/// The NSView that hosts the AVPlayerLayer AND the controls (as a hosting
/// subview). Putting the controls inside this view means they follow it
/// into `enterFullScreenMode` — fullscreen WITH controls, no extra window.
final class PlayerNSView: NSView {
    let playerLayer = AVPlayerLayer()
    weak var controller: VideoPlayerController?
    private var fsWindow: NSWindow?

    func configure(player: AVPlayer, controls: AnyView) {
        wantsLayer = true
        layer = CALayer()
        layer?.backgroundColor = NSColor.black.cgColor
        playerLayer.player = player
        playerLayer.videoGravity = .resizeAspect
        layer?.addSublayer(playerLayer)

        let host = NSHostingView(rootView: controls)
        host.translatesAutoresizingMaskIntoConstraints = false
        addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: leadingAnchor),
            host.trailingAnchor.constraint(equalTo: trailingAnchor),
            host.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
    }

    override func layout() {
        super.layout()
        playerLayer.frame = bounds
    }

    var isFullScreen: Bool { fsWindow != nil }

    // Rather than `enterFullScreenMode` (which fights SwiftUI's Auto Layout and
    // leaves the view at its original size), present a dedicated borderless
    // window covering the whole screen. The same AVPlayer renders into a fresh
    // layer there; transport state stays in sync because both layers share the
    // one controller/player. On exit we re-attach the player to our inline layer.
    func toggleFullScreen() {
        if fsWindow != nil { exitFullScreen(); return }
        guard let screen = window?.screen ?? NSScreen.main,
              let controller else { return }

        let container = FSPlayerView()
        container.onExit = { [weak self] in self?.exitFullScreen() }
        container.wantsLayer = true
        container.layer = CALayer()
        container.layer?.backgroundColor = NSColor.black.cgColor
        let pl = AVPlayerLayer()
        pl.videoGravity = .resizeAspect
        pl.player = controller.player
        container.layer?.addSublayer(pl)
        container.playerLayer = pl

        let controls = AnyView(
            VideoControls(controller: controller) { [weak self] in self?.exitFullScreen() }
        )
        let host = NSHostingView(rootView: controls)
        host.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            host.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            host.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])

        let win = FullscreenWindow(contentRect: screen.frame, styleMask: [.borderless],
                                   backing: .buffered, defer: false)
        win.isReleasedWhenClosed = false
        win.backgroundColor = .black
        win.isOpaque = true
        // Above the menu bar / Dock so it truly covers the screen.
        win.level = NSWindow.Level(rawValue: Int(CGShieldingWindowLevel()))
        win.collectionBehavior = [.fullScreenAuxiliary, .stationary]
        win.contentView = container
        win.setFrame(screen.frame, display: true)

        // Hand rendering to the fullscreen layer (one player → one active layer).
        playerLayer.player = nil
        fsWindow = win
        win.makeKeyAndOrderFront(nil)
        win.makeFirstResponder(container)
    }

    func exitFullScreen() {
        guard let win = fsWindow else { return }
        fsWindow = nil
        playerLayer.player = controller?.player   // resume rendering inline
        win.orderOut(nil)
        window?.makeKeyAndOrderFront(nil)
    }
}

/// A borderless window that can still become key — required so the fullscreen
/// video view receives keyboard events (a plain borderless NSWindow returns
/// `canBecomeKey == false`, which is why Esc never reached `keyDown`).
final class FullscreenWindow: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}

/// The content view of the dedicated fullscreen window: keeps the player layer
/// sized to the whole window and exits on Esc.
final class FSPlayerView: NSView {
    weak var playerLayer: AVPlayerLayer?
    var onExit: (() -> Void)?

    override func layout() {
        super.layout()
        playerLayer?.frame = bounds
    }

    override var acceptsFirstResponder: Bool { true }

    // Esc → exit. `cancelOperation` is delivered up the responder chain when
    // Esc is pressed, so it fires even if the controls overlay holds focus;
    // keyDown is the belt-and-suspenders path when this view is first responder.
    override func cancelOperation(_ sender: Any?) {
        onExit?()
    }

    override func keyDown(with event: NSEvent) {
        if event.keyCode == 53 {   // 53 = Esc
            onExit?()
        } else {
            super.keyDown(with: event)
        }
    }
}

struct PlayerLayerView: NSViewRepresentable {
    @ObservedObject var controller: VideoPlayerController

    func makeNSView(context: Context) -> PlayerNSView {
        let v = PlayerNSView()
        let controls = AnyView(
            VideoControls(controller: controller) { [weak v] in v?.toggleFullScreen() }
        )
        v.controller = controller
        v.configure(player: controller.player, controls: controls)
        controller.layerView = v
        return v
    }

    func updateNSView(_ nsView: PlayerNSView, context: Context) {}
}

/// Drives AVPlayer fed from RAM. No autoplay; the user presses play.
@MainActor
final class VideoPlayerController: ObservableObject {
    @Published var isPlaying = false
    @Published var positionSeconds = 0.0
    @Published var durationSeconds = 0.0
    @Published var failed: String?

    let player = AVPlayer()
    weak var layerView: PlayerNSView?

    private var loader: InMemoryAssetLoader?
    private let loaderQueue = DispatchQueue(label: "app.farewell.video.loader")
    private var timeObserver: Any?
    private var statusObs: NSKeyValueObservation?
    private var endObs: NSObjectProtocol?

    func load(_ data: Data, ext: String) {
        guard let ut = UTType(filenameExtension: ext) else {
            failed = "This video format can't be played in the app."
            return
        }
        let loader = InMemoryAssetLoader(data: data, contentType: ut.identifier)
        self.loader = loader
        guard let url = URL(string: "\(InMemoryAssetLoader.scheme)://video") else { return }
        let asset = AVURLAsset(url: url)
        asset.resourceLoader.setDelegate(loader, queue: loaderQueue)
        let item = AVPlayerItem(asset: asset)

        statusObs = item.observe(\.status, options: [.new]) { [weak self] it, _ in
            let status = it.status
            let dur = CMTimeGetSeconds(it.duration)
            Task { @MainActor [weak self] in
                guard let self else { return }
                if status == .failed {
                    self.failed = "This video format can't be played in the app."
                } else if status == .readyToPlay, dur.isFinite, dur > 0 {
                    self.durationSeconds = dur
                }
            }
        }
        endObs = NotificationCenter.default.addObserver(
            forName: .AVPlayerItemDidPlayToEndTime, object: item, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.isPlaying = false }
        }
        player.replaceCurrentItem(with: item)
        timeObserver = player.addPeriodicTimeObserver(
            forInterval: CMTime(seconds: 0.1, preferredTimescale: 600), queue: .main
        ) { [weak self] t in
            MainActor.assumeIsolated { self?.positionSeconds = CMTimeGetSeconds(t) }
        }
        // No autoplay.
    }

    func togglePlay() {
        if player.timeControlStatus == .playing {
            player.pause()
            isPlaying = false
        } else {
            if durationSeconds > 0,
               CMTimeGetSeconds(player.currentTime()) >= durationSeconds - 0.05 {
                player.seek(to: .zero)
            }
            player.play()
            isPlaying = true
        }
    }

    func seek(toFraction f: Double) {
        guard durationSeconds > 0 else { return }
        let secs = durationSeconds * min(max(f, 0), 1)
        player.seek(to: CMTime(seconds: secs, preferredTimescale: 600),
                    toleranceBefore: .zero, toleranceAfter: .zero)
    }

    func stop() {
        player.pause()
        if let o = timeObserver { player.removeTimeObserver(o); timeObserver = nil }
        statusObs = nil
        if let e = endObs { NotificationCenter.default.removeObserver(e); endObs = nil }
        if layerView?.isFullScreen == true { layerView?.exitFullScreen() }
        player.replaceCurrentItem(with: nil)
        loader = nil
        isPlaying = false
    }
}

/// Our own transport bar (no AVKit chrome): play/pause, scrubber,
/// elapsed/total, and a fullscreen toggle. Lives inside PlayerNSView so it
/// stays on screen in fullscreen too.
struct VideoControls: View {
    @ObservedObject var controller: VideoPlayerController
    let onFullscreen: () -> Void
    @State private var scrubbing = false
    @State private var scrubValue = 0.0

    var body: some View {
        HStack(spacing: 14) {
            Button { controller.togglePlay() } label: {
                Image(systemName: controller.isPlaying ? "pause.fill" : "play.fill")
                    .font(.title3)
                    .frame(width: 22)
            }
            .buttonStyle(.plain)

            Text(timeStr(scrubbing ? scrubValue : controller.positionSeconds))
                .font(.caption.monospacedDigit())

            Slider(
                value: Binding(
                    get: { scrubbing ? scrubValue : controller.positionSeconds },
                    set: { scrubValue = $0 }
                ),
                in: 0...max(controller.durationSeconds, 0.1),
                onEditingChanged: { editing in
                    scrubbing = editing
                    if !editing, controller.durationSeconds > 0 {
                        controller.seek(toFraction: scrubValue / controller.durationSeconds)
                    }
                }
            )

            Text(timeStr(controller.durationSeconds))
                .font(.caption.monospacedDigit())

            Button(action: onFullscreen) {
                Image(systemName: "arrow.up.left.and.arrow.down.right")
            }
            .buttonStyle(.plain)
            .help("Fullscreen (Esc to exit)")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(.ultraThinMaterial)
        .foregroundStyle(.primary)
    }

    private func timeStr(_ s: Double) -> String {
        guard s.isFinite, s >= 0 else { return "0:00" }
        let t = Int(s.rounded(.down))
        return String(format: "%d:%02d", t / 60, t % 60)
    }
}

struct VideoPlayerView: View {
    let data: Data
    let ext: String
    @StateObject private var controller = VideoPlayerController()

    var body: some View {
        Group {
            if let err = controller.failed {
                VStack(spacing: 8) {
                    Image(systemName: "film.stack")
                        .font(.system(size: 40))
                        .foregroundStyle(.tertiary)
                    Text(err)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
            } else {
                PlayerLayerView(controller: controller)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { controller.load(data, ext: ext) }
        .onDisappear { controller.stop() }
    }
}

struct ViewerPanel: View {
    @EnvironmentObject var vault: VaultModel
    @State private var showExportWarning = false
    // The name of the file currently being edited (nil = not editing). Edit
    // mode is *derived* (editingFile == shown file), so switching files simply
    // hides the editor — no reset races — and switching back restores the
    // in-progress draft.
    @State private var editingFile: String?
    @State private var draft = ""
    @State private var saveError: String?

    var body: some View {
        if let file = vault.selectedFile {
            let editing = (editingFile == file.name)
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Image(systemName: iconName(for: file.name))
                        .foregroundStyle(.secondary)
                    Text(file.name)
                        .font(.headline)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(file.name)
                    Spacer(minLength: 8)
                    if editing {
                        Button("Cancel") {
                            editingFile = nil
                            saveError = nil
                        }
                        Button {
                            if let err = vault.saveText(name: file.name, content: draft) {
                                saveError = err
                            } else {
                                editingFile = nil
                                saveError = nil
                            }
                        } label: {
                            Label("Save", systemImage: "checkmark")
                        }
                        .keyboardShortcut("s", modifiers: .command)
                        .help("Save the changes back into the encrypted vault. Nothing is written to disk.")
                    } else {
                        Text(formatBytes(file.size))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if editableString(vault.selectedContent) != nil {
                            Button {
                                draft = editableString(vault.selectedContent) ?? ""
                                saveError = nil
                                editingFile = file.name
                            } label: {
                                Label("Edit", systemImage: "pencil")
                            }
                            .help("Edit this text file in the app and save it back into the vault. Nothing is written to disk.")
                        }
                        Button {
                            showExportWarning = true
                        } label: {
                            Label("Export…", systemImage: "square.and.arrow.up")
                        }
                        .help("Write a decrypted copy of this file to disk, outside the vault. Shows a warning first.")
                    }
                }
                .padding(12)
                Divider()
                if editing {
                    VStack(spacing: 0) {
                        if let err = saveError {
                            Text(err)
                                .font(.caption)
                                .foregroundStyle(.red)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                            Divider()
                        }
                        EditableTextView(text: $draft)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                } else {
                    content(for: vault.selectedContent)
                        // Tie the content to the selected file so switching
                        // files gives a FRESH subtree: a player's @StateObject
                        // is reset, .onDisappear/.onAppear fire, and the new
                        // audio/video loads instead of the view being silently
                        // reused with stale state.
                        .id(file.name)
                }
            }
            // A just-created note (or anything VaultModel flags) opens straight
            // into the editor. These triggers all converge on the same
            // idempotent consume, so their firing order doesn't matter.
            .onAppear { consumePendingEdit(file.name) }
            .onChange(of: file.name) { _, n in consumePendingEdit(n) }
            .onChange(of: vault.pendingEditFile) { _, _ in consumePendingEdit(file.name) }
            .sheet(isPresented: $showExportWarning) {
                ExportWarningSheet(fileName: file.name) {
                    runExport(for: file.name)
                }
            }
        } else {
            VStack(spacing: 8) {
                Image(systemName: "sidebar.right")
                    .font(.system(size: 40))
                    .foregroundStyle(.tertiary)
                Text("Select a file to view it.")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// If `name` is the file VaultModel asked to open in the editor, start
    /// editing it (empty draft) and clear the request. Idempotent.
    func consumePendingEdit(_ name: String) {
        if vault.pendingEditFile == name {
            draft = ""
            saveError = nil
            editingFile = name
            vault.pendingEditFile = nil
        }
    }

    /// The editable source string for a content kind, or nil if this kind
    /// isn't text-editable (PDF, image, audio, video, errors).
    func editableString(_ content: VaultModel.ViewerContent?) -> String? {
        switch content {
        case .text(let s)?: return s
        case .markdown(let s)?: return s
        default: return nil
        }
    }

    @ViewBuilder
    func content(for content: VaultModel.ViewerContent?) -> some View {
        switch content {
        case .text(let s)?:
            // Native NSTextView: stable monospaced layout + native
            // selection. SwiftUI's Text + .textSelection re-lays out on
            // click, visibly shifting line spacing — this avoids that.
            CodeTextView(text: s)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .markdown(let s)?:
            ScrollView {
                renderedMarkdown(s)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
        case .pdf(let data)?:
            if PDFDocument(data: data) != nil {
                PDFKitView(data: data)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                viewerMessage(
                    icon: "doc.questionmark",
                    title: "Not a valid PDF",
                    detail: "The file has a .pdf extension but PDFKit could not parse it."
                )
            }
        case .image(let data)?:
            if let img = NSImage(data: data) {
                // Fit the whole image to the panel, preserving aspect
                // ratio, resizing live with the window. No ScrollView:
                // scaledToFit already bounds it to the available frame.
                Image(nsImage: img)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding()
            } else {
                viewerMessage(
                    icon: "photo.badge.exclamationmark",
                    title: "Cannot decode image",
                    detail: "The bytes could not be decoded as a known image format."
                )
            }
        case .audio(let data)?:
            AudioPlayerView(data: data)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .video(let data, let ext)?:
            VideoPlayerView(data: data, ext: ext)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .unsupported(let reason)?:
            VStack(spacing: 8) {
                Image(systemName: "doc.questionmark")
                    .font(.system(size: 40))
                    .foregroundStyle(.tertiary)
                Text("Cannot preview")
                    .foregroundStyle(.secondary)
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .loadFailed(let reason)?:
            VStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: 40))
                    .foregroundStyle(.orange)
                Text("Failed to load")
                    .foregroundStyle(.secondary)
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .none:
            ProgressView().controlSize(.small)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// Centered icon + title + detail, used for the empty/error states.
    @ViewBuilder
    func viewerMessage(icon: String, title: String, detail: String) -> some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 40))
                .foregroundStyle(.tertiary)
            Text(title)
                .foregroundStyle(.secondary)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    func renderedMarkdown(_ source: String) -> Text {
        // Render block-level markdown. `.full` interprets headings,
        // lists, links, code spans, etc.; `inlineOnly` would only
        // do bold/italic/links inline.
        let options = AttributedString.MarkdownParsingOptions(
            interpretedSyntax: .full
        )
        if let attributed = try? AttributedString(markdown: source, options: options) {
            return Text(attributed)
        }
        return Text(source)
    }

    /// Invoked after the user confirms the export warning. Shows a
    /// save panel, then streams the decrypted bytes to the chosen
    /// location via the model.
    func runExport(for name: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.canCreateDirectories = true
        panel.title = "Export decrypted copy"
        panel.message = String(localized: "This file will be written UNENCRYPTED outside the vault.")
        if panel.runModal() == .OK, let url = panel.url {
            vault.exportFile(name, to: url)
        }
    }
}

/// Warning shown before any export. Lists the OS-cache leak vectors
/// the user accepts by writing a decrypted copy to disk. Cancel is
/// the default action; "Export anyway" is styled as destructive.
struct ExportWarningSheet: View {
    let fileName: String
    let onConfirm: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(.orange)
                Text("Export a decrypted copy?")
                    .font(.title3.weight(.semibold))
            }

            Text("You are about to write the decrypted contents of “\(fileName)” to a regular file on disk. Once written, that file leaves Farewell's protection:")
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 6) {
                leakRow("magnifyingglass", "Spotlight will index its contents")
                leakRow("eye", "QuickLook will cache a thumbnail")
                leakRow("clock.arrow.circlepath", "Time Machine will back it up (if enabled)")
                leakRow("doc.on.doc", "Apps that open it keep it in Recent Items")
                leakRow("xmark.bin", "Farewell can no longer track or recall it")
            }
            .font(.callout)

            Text("Use the in-app viewer instead unless you genuinely need an external copy. For device-to-device transfer, Farewell-to-Farewell P2P (coming later) never writes cleartext to disk.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Export anyway", role: .destructive) {
                    dismiss()
                    onConfirm()
                }
            }
        }
        .padding(24)
        .frame(width: 460)
    }

    @ViewBuilder
    private func leakRow(_ icon: String, _ text: LocalizedStringKey) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(.orange)
                .frame(width: 20)
            Text(text)
        }
    }
}

// =============================================================================
// App entry
// =============================================================================

/// AppDelegate that flips this bare executable into a regular,
/// window-bearing macOS app. Without this, a SwiftUI `@main App`
/// invoked outside a proper `.app` bundle launches with activation
/// policy `.prohibited` (no Dock icon, no focusable window). Pre-1.0
/// builds run directly from `swift build`; the production app will
/// be bundled and signed and won't need this dance.
final class FarewellAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        // Bring the (first) window forward if SwiftUI already created one,
        // and make sure it's tall enough for the full create form. macOS
        // window-state restoration can reopen the window shorter than
        // `.defaultSize`, which clipped the "Create and open" button; grow
        // it back to a comfortable height (the user can still shrink it —
        // the content then scrolls).
        if let window = NSApp.windows.first {
            let minContentHeight: CGFloat = 860
            if window.contentLayoutRect.height < minContentHeight {
                let w = max(window.frame.width, 820)
                window.setContentSize(NSSize(width: w, height: minContentHeight))
                window.center()
            }
            window.makeKeyAndOrderFront(nil)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

@main
struct FarewellAppMain: App {
    @NSApplicationDelegateAdaptor(FarewellAppDelegate.self) private var appDelegate
    @StateObject private var vault = VaultModel()
    @StateObject private var license = LicenseModel()

    var body: some Scene {
        WindowGroup("Farewell") {
            ContentView()
                .environmentObject(vault)
                .environmentObject(license)
                .frame(minWidth: 720, minHeight: 480)
                .task { license.refresh() }
        }
        // Freely resizable, opening at a roomy default. (Previously
        // `.contentSize`, which clipped the create form at the bottom.)
        .windowResizability(.contentMinSize)
        .defaultSize(width: 820, height: 900)
        .commands {
            // Custom "About Farewell" with the copyright + version.
            CommandGroup(replacing: .appInfo) {
                Button("About Farewell") { FarewellAppMain.showAboutPanel() }
            }
        }

        // Preferences window (⌘,) — auto-lock timeout for now.
        Settings {
            SettingsView()
        }
    }

    /// Version string for the About panel — the bundle's, with a fallback.
    static var appVersion: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "0.22"
    }

    static func showAboutPanel() {
        // The copyright line is supplied automatically from Info.plist's
        // NSHumanReadableCopyright. Don't ALSO pass it via `.credits`, or the
        // About panel shows the same line twice.
        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: "Farewell",
            .applicationVersion: appVersion,
        ])
    }
}

/// Preferences window. Auto-lock is the only setting for now: lock the open
/// vault after this much inactivity (and always on sleep / screen lock).
struct SettingsView: View {
    @AppStorage("autoLockMinutes") private var autoLockMinutes: Int = 5

    var body: some View {
        Form {
            Picker("Auto-lock after inactivity:", selection: $autoLockMinutes) {
                Text("1 minute").tag(1)
                Text("5 minutes").tag(5)
                Text("15 minutes").tag(15)
                Text("30 minutes").tag(30)
                Text("Never").tag(0)
            }
            Text("The vault always locks on system sleep and screen lock. Inactivity is measured system-wide.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(width: 380)
    }
}
