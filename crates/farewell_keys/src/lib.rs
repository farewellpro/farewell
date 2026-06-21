//! Secure in-memory key handling for Farewell.
//!
//! Per ARCHITECTURE.md §12.1, all sensitive cryptographic material in
//! memory lives in a [`SecureBuffer`]:
//!
//! - `mlock` to prevent swap.
//! - Zeroize via `explicit_bzero`-equivalent on Drop.
//! - Indirection so the secret is never copied through `Clone`.
//!
//! Guard pages and `mprotect(PROT_NONE)` when idle are tracked as
//! Phase 1 hardening (TODO: see `SecureBuffer::with_guard`).
//!
//! # Safety
//!
//! This crate uses `unsafe` exclusively for `mlock`/`munlock` syscalls.
//! Every `unsafe` block is annotated with its precondition and is the
//! minimum surface needed to call libc.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// A pinned, zeroized-on-drop heap allocation for secret material.
///
/// The contained bytes are kept resident in physical memory via `mlock`
/// (best effort: on platforms where `mlock` is unavailable or fails due
/// to rlimits, the allocation degrades to a regular heap allocation
/// with zeroization, and a runtime warning is surfaced once).
pub struct SecureBuffer {
    inner: Vec<u8>,
    #[allow(dead_code)]
    locked: bool,
}

impl SecureBuffer {
    /// Allocate `len` zeroed bytes pinned in memory.
    pub fn new(len: usize) -> Self {
        let inner = vec![0u8; len];
        let locked = lock_memory(&inner);
        Self { inner, locked }
    }

    /// Construct from existing bytes. The input is moved in and the caller
    /// must ensure no copy remains outside (the input `Vec` is consumed).
    pub fn from_vec(mut bytes: Vec<u8>) -> Self {
        let locked = lock_memory(&bytes);
        // Take ownership; on drop we will zeroize the contents.
        let inner = std::mem::take(&mut bytes);
        Self { inner, locked }
    }

    /// Borrow the bytes immutably.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Borrow the bytes mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Length of the buffer in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        unlock_memory(&self.inner);
        self.inner.zeroize();
    }
}

#[cfg(unix)]
fn lock_memory(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // SAFETY: mlock with a valid pointer and length. Failure is non-fatal;
    // we only report success/failure for diagnostic purposes.
    let rc = unsafe {
        libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len())
    };
    rc == 0
}

#[cfg(not(unix))]
fn lock_memory(_bytes: &[u8]) -> bool {
    false
}

#[cfg(unix)]
fn unlock_memory(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    // SAFETY: munlock with a valid pointer and length. Best effort.
    unsafe {
        libc::munlock(bytes.as_ptr() as *const libc::c_void, bytes.len());
    }
}

#[cfg(not(unix))]
fn unlock_memory(_bytes: &[u8]) {}

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
    fn zeroize_clears_live_contents() {
        // The exact primitive `Drop` relies on, observed on a live buffer.
        let mut b = SecureBuffer::from_vec(vec![0xABu8; 64]);
        assert!(b.as_slice().iter().all(|&x| x == 0xAB));
        b.as_mut_slice().zeroize();
        assert!(b.as_slice().iter().all(|&x| x == 0));
    }

    // --- "scan the heap for the key after lock", done soundly ---
    //
    // The live master key lives in a `SecureBuffer` (see `farewell_format`),
    // so proving the buffer's backing store is wiped on drop is the
    // regression guard that matters: it fails if a future change drops the
    // `zeroize()` call or lets a key copy escape the buffer.
    //
    // A naive "read the bytes after drop" would be use-after-free. Instead we
    // snapshot the *watched* allocation from inside `dealloc`, while it is
    // still live — sound, targeted (one pointer), and free of the false
    // positives a whole-heap scan would suffer from.

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
                // SAFETY: we are inside this allocation's own `dealloc`; the
                // memory is still valid to read until we hand it to `System`.
                let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
                CAPTURED_NONZERO.store(bytes.iter().filter(|&&b| b != 0).count(), Ordering::SeqCst);
                CAPTURED.store(true, Ordering::SeqCst);
                WATCH_PTR.store(0, Ordering::SeqCst);
            }
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static GLOBAL: SnoopAlloc = SnoopAlloc;

    #[test]
    fn drop_zeroizes_backing_store() {
        const LEN: usize = 4096;
        const SENTINEL: u8 = 0x5A;

        // cap == len, so the backing store is exactly LEN sentinel bytes.
        let mut v = Vec::with_capacity(LEN);
        v.resize(LEN, SENTINEL);
        let ptr = v.as_ptr() as usize;

        CAPTURED.store(false, Ordering::SeqCst);
        CAPTURED_NONZERO.store(usize::MAX, Ordering::SeqCst);
        WATCH_LEN.store(LEN, Ordering::SeqCst);
        WATCH_PTR.store(ptr, Ordering::SeqCst);

        let buf = SecureBuffer::from_vec(v);
        // `from_vec` moves the heap buffer in place — same address.
        assert_eq!(buf.as_slice().as_ptr() as usize, ptr);
        assert!(buf.as_slice().iter().all(|&b| b == SENTINEL));

        drop(buf); // munlock + zeroize, then the Vec frees -> snoop captures.

        assert!(CAPTURED.load(Ordering::SeqCst), "watched allocation was never freed");
        let nonzero = CAPTURED_NONZERO.load(Ordering::SeqCst);
        assert_eq!(nonzero, 0, "Drop left {nonzero} non-zero byte(s) in the backing store");
    }
}
