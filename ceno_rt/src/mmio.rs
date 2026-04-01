//! Memory-mapped I/O (MMIO) functions.

use ceno_serde::from_slice;
use ceno_syscall::syscall_pub_io_commit;
use core::{cell::UnsafeCell, ptr, slice::from_raw_parts};
use serde::de::DeserializeOwned;
use std::vec::Vec;
use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 digest of the empty string (""), encoded as 8 little-endian `u32` words.
pub const KECCAK_EMPTY_WORDS: [u32; 8] = [
    0x0146d2c5, 0x3c23f786, 0xb27d7e92, 0xc003c7dc, 0x53b600e5, 0x3b2782ca, 0x04d8fa7b, 0x70a4855d,
];

struct RegionState {
    next_len_at: *const usize,
    next_data_at: *const u8,
    alignment: usize,
    initialized: bool,
}

impl RegionState {
    const fn new() -> Self {
        Self {
            next_len_at: ptr::null(),
            next_data_at: ptr::null(),
            alignment: 1,
            initialized: false,
        }
    }

    unsafe fn ensure_initialized(&mut self, len_start: *const usize, data_start: *const u8) {
        if self.initialized {
            return;
        }
        let mut cursor = len_start;
        let data_offset = unsafe { ptr::read(cursor) };
        cursor = unsafe { cursor.add(1) };
        self.alignment = unsafe { ptr::read(cursor) };
        cursor = unsafe { cursor.add(1) };
        self.next_len_at = cursor;
        self.next_data_at = unsafe { data_start.add(data_offset) };
        self.initialized = true;
    }

    unsafe fn take_len(&mut self, len_start: *const usize, data_start: *const u8) -> usize {
        unsafe { self.ensure_initialized(len_start, data_start) };
        let len = unsafe { ptr::read(self.next_len_at) };
        self.next_len_at = unsafe { self.next_len_at.add(1) };
        len
    }

    unsafe fn take_slice<'a>(
        &mut self,
        len_start: *const usize,
        data_start: *const u8,
    ) -> &'a [u8] {
        let len = unsafe { self.take_len(len_start, data_start) };
        let ptr = self.next_data_at;
        let padded = len.next_multiple_of(self.alignment);
        self.next_data_at = unsafe { self.next_data_at.add(padded) };
        unsafe { from_raw_parts(ptr, len) }
    }
}

unsafe extern "C" {
    static _hints_start: u8;
    static _lengths_of_hints_start: usize;
}

struct RegionStateCell(UnsafeCell<RegionState>);

impl RegionStateCell {
    const fn new() -> Self {
        Self(UnsafeCell::new(RegionState::new()))
    }

    unsafe fn with_mut<R>(&self, f: impl FnOnce(&mut RegionState) -> R) -> R {
        f(unsafe { &mut *self.0.get() })
    }
}

unsafe impl Sync for RegionStateCell {}

static HINT_STATE: RegionStateCell = RegionStateCell::new();

pub fn read_slice<'a>() -> &'a [u8] {
    unsafe {
        HINT_STATE
            .with_mut(|state| state.take_slice(&raw const _lengths_of_hints_start, &_hints_start))
    }
}

pub fn read_owned<T>() -> T
where
    T: DeserializeOwned,
{
    from_slice(read_slice()).expect("Deserialised value failed.")
}

pub fn read<T>() -> T
where
    T: DeserializeOwned,
{
    read_owned()
}

fn digest_to_words(digest: [u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| {
        u32::from_le_bytes([
            digest[i * 4],
            digest[i * 4 + 1],
            digest[i * 4 + 2],
            digest[i * 4 + 3],
        ])
    })
}

fn keccak_words(bytes: &[u8]) -> [u32; 8] {
    if bytes.is_empty() {
        return KECCAK_EMPTY_WORDS;
    }

    let mut keccak = Keccak::v256();
    keccak.update(bytes);
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);
    digest_to_words(digest)
}

/// Commit a precomputed public-io digest.
///
/// The input must already be an 8-word Keccak-256 digest encoded in little-endian words.
pub fn commit_digest(digest_words: [u32; 8]) {
    syscall_pub_io_commit(&digest_words);
}

/// Accumulates committed bytes and emits one digest when finalized.
#[derive(Clone, Debug, Default)]
pub struct CommitCtx {
    bytes: Vec<u8>,
}

impl CommitCtx {
    pub fn new() -> Self {
        Self::default()
    }

    fn digest_words(&self) -> [u32; 8] {
        keccak_words(&self.bytes)
    }

    /// Append arbitrary bytes to this context.
    pub fn commit(&mut self, data: &[u8]) {
        self.bytes.extend_from_slice(data);
    }

    /// Compute a final digest by hashing the accumulated bytes once.
    pub fn finalized(self) {
        commit_digest(self.digest_words())
    }
}

/// Commit arbitrary public bytes by hashing with Keccak-256 and emitting digest limbs.
pub fn commit(data: &[u8]) {
    commit_digest(keccak_words(data));
}

#[cfg(test)]
mod tests {
    use super::{CommitCtx, digest_to_words, keccak_words};
    use tiny_keccak::{Hasher, Keccak};

    #[test]
    fn keccak_words_matches_manual_conversion() {
        let words = keccak_words(b"hello world");

        let mut manual = Keccak::v256();
        manual.update(b"hello world");
        let mut digest = [0u8; 32];
        manual.finalize(&mut digest);

        assert_eq!(words, digest_to_words(digest));
    }

    #[test]
    fn commit_ctx_digest_words_hashes_all_appended_bytes() {
        let mut ctx = CommitCtx::new();
        ctx.commit(b"abc");
        ctx.commit(b"123");

        let got = ctx.digest_words();
        let expected = keccak_words(b"abc123");

        assert_eq!(got, expected);
    }

    #[test]
    fn commit_ctx_commit_appends_raw_bytes_before_finalize() {
        let mut ctx = CommitCtx::new();
        ctx.commit(b"hello");
        ctx.commit(b" ");
        ctx.commit(b"world");

        let got = ctx.digest_words();
        let expected = keccak_words(b"hello world");

        assert_eq!(got, expected);
    }

    #[test]
    #[should_panic(expected = "syscall_pub_io_commit should only run inside zkvm")]
    fn commit_ctx_finalized_is_callable() {
        let mut ctx = CommitCtx::new();
        ctx.commit(b"payload");
        ctx.finalized();
    }
}
