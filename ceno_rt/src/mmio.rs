//! Memory-mapped I/O (MMIO) functions.

use ceno_serde::from_slice;
use core::{cell::UnsafeCell, ptr, slice::from_raw_parts};
use serde::de::DeserializeOwned;
use tiny_keccak::{Hasher, Keccak};

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

#[cfg(target_arch = "riscv32")]
#[inline(always)]
fn syscall_pub_io_commit(digest_u16_limbs: &[u32; 16]) {
    // a0 carries a pointer to the digest limbs, a1 carries the limb count.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") digest_u16_limbs.as_ptr(),
            in("a1") digest_u16_limbs.len(),
            in("t0") 1_u32,
        );
    }
}

#[cfg(not(target_arch = "riscv32"))]
#[inline(always)]
fn syscall_pub_io_commit(_digest_u16_limbs: &[u32; 16]) {}

fn digest_to_u16_limbs(digest: [u8; 32]) -> [u32; 16] {
    core::array::from_fn(|i| u16::from_le_bytes([digest[i * 2], digest[i * 2 + 1]]) as u32)
}

/// Commit arbitrary public bytes by hashing with Keccak-256 and emitting digest limbs.
pub fn commit(data: &[u8]) {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);

    let digest_u16_limbs = digest_to_u16_limbs(digest);
    syscall_pub_io_commit(&digest_u16_limbs);
}
