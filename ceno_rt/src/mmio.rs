//! Memory-mapped I/O (MMIO) functions.

use ceno_serde::from_slice;
use core::{cell::UnsafeCell, ptr, slice::from_raw_parts};
use serde::de::DeserializeOwned;

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
    static _pubio_start: u8;
    static _lengths_of_pubio_start: usize;
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
static PUBIO_STATE: RegionStateCell = RegionStateCell::new();

pub fn read_slice<'a>() -> &'a [u8] {
    unsafe {
        HINT_STATE.with_mut(|state| state.take_slice(&raw const _lengths_of_hints_start, &_hints_start))
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

pub fn pubio_read_slice<'a>() -> &'a [u8] {
    unsafe {
        PUBIO_STATE.with_mut(|state| state.take_slice(&raw const _lengths_of_pubio_start, &_pubio_start))
    }
}

/// Read a value from public io, deserialize it, and assert that it matches the given value.
pub fn commit<T>(v: &T)
where
    T: DeserializeOwned + core::fmt::Debug + PartialEq,
{
    let expected: T = from_slice(pubio_read_slice()).expect("Deserialised value failed.");
    assert_eq!(*v, expected);
}
