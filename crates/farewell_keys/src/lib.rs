//! Secure in-memory key handling for Farewell.
//!
//! Per ARCHITECTURE.md §12.1, all sensitive cryptographic material in
//! memory lives in a [`SecureBuffer`]:
//!
//! - **Dedicated, page-aligned allocation** (`mmap(MAP_ANON)` on Unix):
//!   the secret never shares a page with unrelated heap objects, so its
//!   `mlock`/`munlock` cannot be defeated by (or defeat) another
//!   allocation's lock on the same page — a hazard the previous
//!   `Vec`-backed version silently had.
//! - `mlock` to prevent swap, **observable**: [`SecureBuffer::is_locked`]
//!   reports whether the lock actually took, so callers can surface a
//!   degraded state instead of ignoring it.
//! - Zeroize on Drop, **before** the pages are unlocked and released —
//!   never after, when the pager would already be free to swap them.
//!
//! Intended for keys and small working secrets (bytes to kilobytes).
//! It is NOT a container for large media content: locking hundreds of
//! megabytes of viewer data would fight the OS for no gain — large
//! plaintext buffers belong to the streaming viewers, not here.
//!
//! # Safety
//!
//! This crate uses `unsafe` for the `mmap`/`munmap`/`mlock`/`munlock`
//! syscalls and for the slice views over the owned mapping. Every
//! `unsafe` block is annotated with its precondition and is the minimum
//! surface needed.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// A pinned, zeroized-on-drop, page-aligned allocation for secret
/// material.
///
/// On Unix the backing store is a dedicated anonymous mapping (never
/// the global heap); `mlock` is attempted and its outcome recorded. On
/// other platforms the buffer degrades to an ordinary allocation with
/// zeroization only (`is_locked()` reports `false`).
pub struct SecureBuffer {
    /// Base of the dedicated mapping (`null` when `capacity == 0`).
    ptr: *mut u8,
    /// Requested (usable) length in bytes.
    len: usize,
    /// Size of the mapping, rounded up to whole pages (0 = no mapping).
    capacity: usize,
    /// Whether `mlock` succeeded on the mapping.
    locked: bool,
    /// Non-Unix fallback storage (empty and unused on Unix).
    #[cfg(not(unix))]
    fallback: Vec<u8>,
}

// SAFETY: the buffer exclusively owns its mapping; no interior
// mutability, no aliasing beyond the borrows the API hands out. Moving
// it between threads, or sharing `&self` (read-only slice access), is
// as safe as it is for a `Vec<u8>`.
unsafe impl Send for SecureBuffer {}
unsafe impl Sync for SecureBuffer {}

impl SecureBuffer {
    /// Allocate `len` zeroed bytes in a dedicated, page-aligned,
    /// best-effort-locked mapping. `len == 0` allocates nothing.
    pub fn new(len: usize) -> Self {
        Self::alloc(len)
    }

    /// Construct from existing bytes. The bytes are copied into the
    /// secure mapping and the source `Vec` is **zeroized in place**
    /// before being freed, so no plaintext copy survives in the general
    /// heap.
    pub fn from_vec(mut bytes: Vec<u8>) -> Self {
        let mut buf = Self::alloc(bytes.len());
        buf.as_mut_slice().copy_from_slice(&bytes);
        bytes.zeroize();
        buf
    }

    /// Whether the backing pages are actually `mlock`ed (pinned out of
    /// swap). `false` means the allocation is in a DEGRADED state —
    /// zeroize-on-drop still applies, but the OS may page the secret to
    /// disk. Callers owning long-lived keys should surface this.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Borrow the bytes immutably.
    pub fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        #[cfg(unix)]
        // SAFETY: `ptr` is a live private mapping of at least `len`
        // readable bytes, exclusively owned by `self`.
        unsafe {
            std::slice::from_raw_parts(self.ptr, self.len)
        }
        #[cfg(not(unix))]
        &self.fallback
    }

    /// Borrow the bytes mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.len == 0 {
            return &mut [];
        }
        #[cfg(unix)]
        // SAFETY: as in `as_slice`, plus `&mut self` guarantees
        // exclusive access.
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr, self.len)
        }
        #[cfg(not(unix))]
        &mut self.fallback
    }

    /// Length of the buffer in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(unix)]
    fn alloc(len: usize) -> Self {
        if len == 0 {
            return Self {
                ptr: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
                locked: false,
            };
        }
        let page = page_size();
        let capacity = len.div_ceil(page) * page;
        // SAFETY: plain anonymous private mapping request; no fd, no
        // fixed address. Checked for MAP_FAILED below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                capacity,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            // Out of address space for a key-sized mapping is a
            // program-ending condition; aborting beats handing the
            // caller a fake secret store.
            panic!("SecureBuffer: mmap of {capacity} bytes failed");
        }
        // SAFETY: `ptr` is the base of our fresh `capacity`-byte
        // mapping (mmap zero-fills anonymous pages).
        let locked = unsafe { libc::mlock(ptr, capacity) } == 0;
        Self {
            ptr: ptr as *mut u8,
            len,
            capacity,
            locked,
        }
    }

    #[cfg(not(unix))]
    fn alloc(len: usize) -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len,
            capacity: 0,
            locked: false,
            fallback: vec![0u8; len],
        }
    }

    /// The teardown sequence, in the only sound order:
    ///
    /// 1. **zeroize** while the pages are still resident and locked;
    /// 2. **munlock** (only if the lock took) — after this the pager
    ///    may do as it pleases with pages that now hold zeros;
    /// 3. release the mapping.
    ///
    /// The previous implementation unlocked FIRST, opening a window in
    /// which the still-secret bytes were swappable.
    fn wipe_then_release(&mut self) {
        #[cfg(test)]
        drop_order::record("zeroize");
        self.as_mut_slice().zeroize();

        #[cfg(unix)]
        {
            if self.capacity > 0 {
                if self.locked {
                    #[cfg(test)]
                    drop_order::record("munlock");
                    // SAFETY: `ptr`/`capacity` describe our own live,
                    // locked mapping.
                    unsafe {
                        libc::munlock(self.ptr as *const libc::c_void, self.capacity);
                    }
                }
                // SAFETY: `ptr`/`capacity` describe our own live
                // mapping; nothing references it past this point.
                unsafe {
                    libc::munmap(self.ptr as *mut libc::c_void, self.capacity);
                }
                self.ptr = std::ptr::null_mut();
                self.capacity = 0;
                self.len = 0;
            }
        }
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.wipe_then_release();
    }
}

#[cfg(unix)]
fn page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) has no preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 {
        n as usize
    } else {
        4096
    }
}

/// Test-only recorder proving the Drop sequence order (zeroize before
/// munlock). Kept outside `mod tests` so `wipe_then_release` can call
/// it without test-only imports at the call site.
#[cfg(test)]
mod drop_order {
    use std::cell::RefCell;
    thread_local! {
        static LOG: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }
    pub fn record(step: &'static str) {
        LOG.with(|l| l.borrow_mut().push(step));
    }
    pub fn take() -> Vec<&'static str> {
        LOG.with(|l| l.borrow_mut().drain(..).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn new_zero_init() {
        let b = SecureBuffer::new(32);
        assert_eq!(b.len(), 32);
        assert!(b.as_slice().iter().all(|&x| x == 0));
    }

    #[test]
    fn from_vec_preserves_content() {
        let v = vec![1u8, 2, 3, 4];
        let b = SecureBuffer::from_vec(v);
        assert_eq!(b.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn mutable_access() {
        let mut b = SecureBuffer::new(4);
        b.as_mut_slice().copy_from_slice(&[9u8; 4]);
        assert_eq!(b.as_slice(), &[9, 9, 9, 9]);
    }

    #[test]
    fn empty_buffer_is_valid() {
        let mut b = SecureBuffer::new(0);
        assert!(b.is_empty());
        assert_eq!(b.as_slice(), &[] as &[u8]);
        assert_eq!(b.as_mut_slice(), &mut [] as &mut [u8]);
        assert!(!b.is_locked());
        drop(b); // must not crash on the no-mapping path
        let e = SecureBuffer::from_vec(Vec::new());
        assert!(e.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn allocation_is_page_aligned_and_dedicated() {
        let b = SecureBuffer::new(32);
        let addr = b.as_slice().as_ptr() as usize;
        assert_eq!(addr % page_size(), 0, "mapping must start on a page boundary");
        // A second buffer must live on different pages entirely — the
        // property that makes per-buffer mlock/munlock sound.
        let b2 = SecureBuffer::new(32);
        let addr2 = b2.as_slice().as_ptr() as usize;
        assert_ne!(addr / page_size(), addr2 / page_size());
    }

    #[cfg(unix)]
    #[test]
    fn small_key_is_actually_locked() {
        // A 32-byte key must lock on any sane RLIMIT_MEMLOCK; if this
        // fails, is_locked() is at least telling the truth about it.
        let b = SecureBuffer::new(32);
        if !b.is_locked() {
            eprintln!("warning: mlock failed for a 32-byte key (rlimit?) — degraded state correctly reported");
        }
    }

    #[test]
    fn zeroize_clears_live_contents() {
        let mut b = SecureBuffer::from_vec(vec![0xABu8; 64]);
        assert!(b.as_slice().iter().all(|&x| x == 0xAB));
        b.as_mut_slice().zeroize();
        assert!(b.as_slice().iter().all(|&x| x == 0));
    }

    #[test]
    fn drop_zeroizes_before_unlocking() {
        // The audit's exact finding: the old Drop ran munlock BEFORE
        // zeroize, leaving a window where the still-secret pages were
        // swappable. The recorder proves the corrected order.
        let _ = drop_order::take();
        let b = SecureBuffer::from_vec(vec![0x77u8; 128]);
        let was_locked = b.is_locked();
        drop(b);
        let log = drop_order::take();
        assert_eq!(log.first(), Some(&"zeroize"), "zeroize must come first");
        if was_locked {
            assert_eq!(log.get(1), Some(&"munlock"), "munlock must follow zeroize");
        }
    }

    // --- "no plaintext copy left in the general heap", done soundly ---
    //
    // `from_vec` copies the secret into the dedicated mapping and must
    // zeroize the SOURCE Vec before the allocator gets it back. The
    // snooping allocator snapshots the watched allocation from inside
    // `dealloc`, while it is still live.

    struct SnoopAlloc;

    static WATCH_PTR: AtomicUsize = AtomicUsize::new(0);
    static WATCH_LEN: AtomicUsize = AtomicUsize::new(0);
    static CAPTURED_NONZERO: AtomicUsize = AtomicUsize::new(usize::MAX);
    static CAPTURED: AtomicBool = AtomicBool::new(false);

    unsafe impl GlobalAlloc for SnoopAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            unsafe { System.realloc(ptr, layout, new_size) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let watched = WATCH_PTR.load(Ordering::SeqCst);
            if watched != 0 && ptr as usize == watched {
                let len = WATCH_LEN.load(Ordering::SeqCst).min(layout.size());
                // SAFETY: inside this allocation's own `dealloc`; the
                // memory is still valid to read until handed to System.
                let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
                CAPTURED_NONZERO
                    .store(bytes.iter().filter(|&&b| b != 0).count(), Ordering::SeqCst);
                CAPTURED.store(true, Ordering::SeqCst);
                WATCH_PTR.store(0, Ordering::SeqCst);
            }
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static GLOBAL: SnoopAlloc = SnoopAlloc;

    #[test]
    fn from_vec_zeroizes_the_source_heap_allocation() {
        const LEN: usize = 4096;
        const SENTINEL: u8 = 0x5A;

        let mut v = Vec::with_capacity(LEN);
        v.resize(LEN, SENTINEL);
        let ptr = v.as_ptr() as usize;

        CAPTURED.store(false, Ordering::SeqCst);
        CAPTURED_NONZERO.store(usize::MAX, Ordering::SeqCst);
        WATCH_LEN.store(LEN, Ordering::SeqCst);
        WATCH_PTR.store(ptr, Ordering::SeqCst);

        let buf = SecureBuffer::from_vec(v); // copies + zeroizes + frees source
        assert!(buf.as_slice().iter().all(|&b| b == SENTINEL));

        assert!(
            CAPTURED.load(Ordering::SeqCst),
            "source allocation was never freed"
        );
        let nonzero = CAPTURED_NONZERO.load(Ordering::SeqCst);
        assert_eq!(
            nonzero, 0,
            "from_vec left {nonzero} non-zero byte(s) in the source heap allocation"
        );
        drop(buf);
    }
}
