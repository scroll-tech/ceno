use revm_primitives::{B256, U256};

use crate::alloc::vec::Vec;
use core::{
    cmp::min,
    fmt, iter,
    ops::{BitAnd, Not},
};

/// A sequential memory shared between calls, which uses
/// a `Vec` for internal representation.
/// A [SharedMemory] instance should always be obtained using
/// the `new` static method to ensure memory safety.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SharedMemory {
    /// The underlying buffer.
    buffer: Vec<u8>,
    /// The timestamps of the last modification of each memory slot.
    timestamps: Vec<u64>,
    /// Memory checkpoints for each depth.
    /// Invariant: these are always in bounds of `data`.
    checkpoints: Vec<usize>,
    /// Invariant: equals `self.checkpoints.last()`
    last_checkpoint: usize,
    /// Memory limit. See [`CfgEnv`](revm_primitives::CfgEnv).
    #[cfg(feature = "memory_limit")]
    memory_limit: u64,
}

/// Empty shared memory.
///
/// Used as placeholder inside Interpreter when it is not running.
pub const EMPTY_SHARED_MEMORY: SharedMemory = SharedMemory {
    buffer: Vec::new(),
    timestamps: Vec::new(),
    checkpoints: Vec::new(),
    last_checkpoint: 0,
    #[cfg(feature = "memory_limit")]
    memory_limit: u64::MAX,
};

impl fmt::Debug for SharedMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedMemory")
            .field("current_len", &self.len())
            .field(
                "context_memory",
                &crate::primitives::hex::encode(self.context_memory()),
            )
            .finish_non_exhaustive()
    }
}

impl Default for SharedMemory {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SharedMemory {
    /// Creates a new memory instance that can be shared between calls.
    ///
    /// The default initial capacity is 4KiB.
    #[inline]
    pub fn new() -> Self {
        Self::with_capacity(4 * 1024) // from evmone
    }

    /// Creates a new memory instance that can be shared between calls with the given `capacity`.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            timestamps: Vec::with_capacity(capacity),
            checkpoints: Vec::with_capacity(32),
            last_checkpoint: 0,
            #[cfg(feature = "memory_limit")]
            memory_limit: u64::MAX,
        }
    }

    /// Creates a new memory instance that can be shared between calls,
    /// with `memory_limit` as upper bound for allocation size.
    ///
    /// The default initial capacity is 4KiB.
    #[cfg(feature = "memory_limit")]
    #[inline]
    pub fn new_with_memory_limit(memory_limit: u64) -> Self {
        Self {
            memory_limit,
            ..Self::new()
        }
    }

    /// Returns `true` if the `new_size` for the current context memory will
    /// make the shared buffer length exceed the `memory_limit`.
    #[cfg(feature = "memory_limit")]
    #[inline]
    pub fn limit_reached(&self, new_size: usize) -> bool {
        (self.last_checkpoint + new_size) as u64 > self.memory_limit
    }

    /// Prepares the shared memory for a new context.
    #[inline]
    pub fn new_context(&mut self) {
        self.timestamps.resize(self.buffer.len(), 0);
        let new_checkpoint = self.buffer.len();
        self.checkpoints.push(new_checkpoint);
        self.last_checkpoint = new_checkpoint;
    }

    /// Prepares the shared memory for returning to the previous context.
    #[inline]
    pub fn free_context(&mut self) {
        if let Some(old_checkpoint) = self.checkpoints.pop() {
            self.last_checkpoint = self.checkpoints.last().cloned().unwrap_or_default();
            // SAFETY: buffer length is less than or equal `old_checkpoint`
            unsafe {
                self.buffer.set_len(old_checkpoint);
                self.timestamps.set_len(old_checkpoint);
            }
        }
    }

    /// Returns the length of the current memory range.
    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len() - self.last_checkpoint
    }

    /// Returns `true` if the current memory range is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Resizes the memory in-place so that `len` is equal to `new_len`.
    #[inline]
    pub fn resize(&mut self, new_size: usize) {
        self.buffer.resize(self.last_checkpoint + new_size, 0);
        self.timestamps.resize(self.last_checkpoint + new_size, 0);
    }

    /// Returns a byte slice of the memory region at the given offset.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn slice(&mut self, offset: usize, size: usize, ts: u64) -> (&[u8], Vec<u64>) {
        let end = offset + size;
        let last_checkpoint = self.last_checkpoint;

        let data = self
            .buffer
            .get(last_checkpoint + offset..last_checkpoint + offset + size)
            .unwrap_or_else(|| {
                debug_unreachable!("slice OOB: {offset}..{end}; len: {}", self.len())
            });
        let timestamps = self
            .timestamps
            .splice(
                last_checkpoint + offset..last_checkpoint + offset + size,
                iter::repeat(ts).take(size),
            )
            .collect();
        (data, timestamps)
    }

    /// Returns a byte slice of the memory region at the given offset.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn slice_mut(&mut self, offset: usize, size: usize, ts: u64) -> (&mut [u8], Vec<u64>) {
        let len = self.len();
        let end = offset + size;
        let last_checkpoint = self.last_checkpoint;

        let data = self
            .buffer
            .get_mut(last_checkpoint + offset..last_checkpoint + offset + size)
            .unwrap_or_else(|| debug_unreachable!("slice OOB: {offset}..{end}; len: {}", len));
        let timestamps = self
            .timestamps
            .splice(
                last_checkpoint + offset..last_checkpoint + offset + size,
                iter::repeat(ts).take(size),
            )
            .collect();
        (data, timestamps)
    }

    /// Returns the byte at the given offset.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    pub fn get_byte(&self, offset: usize, ts: u64) -> (u8, u64) {
        let ret = self.slice(offset, 1, ts);
        (ret.0[0], ret.1[0])
    }

    /// Returns a 32-byte slice of the memory region at the given offset.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    pub fn get_word(&self, offset: usize, ts: u64) -> (B256, Vec<u64>) {
        let ret = self.slice(offset, 32, ts);
        (ret.0.try_into().unwrap(), ret.1)
    }

    /// Returns a U256 of the memory region at the given offset.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    pub fn get_u256(&self, offset: usize, ts: u64) -> (U256, Vec<u64>) {
        let ret = self.get_word(offset, ts);
        (ret.0.into(), ret.1)
    }

    /// Sets the `byte` at the given `index`.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn set_byte(&mut self, offset: usize, byte: u8, ts: u64) -> (u8, u64) {
        let ret = self.set(offset, &[byte], ts);
        (ret.0[0], ret.1[0])
    }

    /// Sets the given 32-byte `value` to the memory region at the given `offset`.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn set_word(&mut self, offset: usize, value: &B256, ts: u64) -> (B256, Vec<u64>) {
        let ret = self.set(offset, &value[..], ts);
        (ret.0.as_slice().try_into().unwrap(), ret.1)
    }

    /// Sets the given U256 `value` to the memory region at the given `offset`.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn set_u256(&mut self, offset: usize, value: U256, ts: u64) -> (U256, Vec<u64>) {
        let ret = self.set(offset, &value.to_be_bytes::<32>(), ts);
        let value: B256 = ret.0.as_slice().try_into().unwrap();
        (value.into(), ret.1)
    }

    /// Set memory region at given `offset`.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn set(&mut self, offset: usize, value: &[u8], ts: u64) -> (Vec<u8>, Vec<u64>) {
        if !value.is_empty() {
            let (slice, old_ts) = self.slice_mut(offset, value.len(), ts);
            let old_slice = slice.to_vec();
            slice.copy_from_slice(value);
            (old_slice, old_ts)
        } else {
            (Vec::new(), Vec::new())
        }
    }

    /// Set memory from data. Our memory offset+len is expected to be correct but we
    /// are doing bound checks on data/data_offeset/len and zeroing parts that is not copied.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn set_data(
        &mut self,
        memory_offset: usize,
        data_offset: usize,
        len: usize,
        data: &[u8],
        ts: u64,
    ) -> (Vec<u8>, Vec<u64>) {
        if data_offset >= data.len() {
            // nullify all memory slots
            let (slice, old_ts) = self.slice_mut(memory_offset, len, ts);
            let old_slice = slice.to_vec();
            slice.fill(0);

            return (old_slice, old_ts);
        }

        let data_end = min(data_offset + len, data.len());
        let data_len = data_end - data_offset;
        debug_assert!(data_offset < data.len() && data_end <= data.len());
        let data = unsafe { data.get_unchecked(data_offset..data_end) };
        let (slice_0, old_ts_0) = self.slice_mut(memory_offset, data_len, ts);
        let old_slice_0 = slice_0.to_vec();
        slice_0.copy_from_slice(data);

        // nullify rest of memory slots
        // SAFETY: Memory is assumed to be valid, and it is commented where this assumption is made.
        let (slice_1, old_ts_1) = self.slice_mut(memory_offset + data_len, len - data_len, ts);
        let old_slice_1 = slice_1.to_vec();
        slice_1.fill(0);
        (
            old_slice_0.into_iter().chain(old_slice_1).collect(),
            old_ts_0.into_iter().chain(old_ts_1).collect(),
        )
    }

    /// Copies elements from one part of the memory to another part of itself.
    ///
    /// # Panics
    ///
    /// Panics on out of bounds.
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn copy(&mut self, dst: usize, src: usize, len: usize, ts: u64) -> (Vec<u8>, Vec<u64>) {
        let (slice, timestamps) = self.context_memory_mut(ts);
        let old_slice = slice[src..src + len].to_vec();
        let old_ts = timestamps[src..src + len].to_vec();
        timestamps[dst..dst + len].fill(ts);
        slice.copy_within(src..src + len, dst);
        (old_slice, old_ts)
    }

    /// Returns a reference to the memory of the current context, the active memory.
    #[inline]
    pub fn context_memory(&self) -> &[u8] {
        // SAFETY: access bounded by buffer length
        unsafe {
            self.buffer
                .get_unchecked(self.last_checkpoint..self.buffer.len())
        }
    }

    /// Returns a mutable reference to the memory of the current context.
    #[inline]
    fn context_memory_mut(&mut self, ts: u64) -> (&mut [u8], &mut [u64]) {
        let buf_len = self.buffer.len();
        // SAFETY: access bounded by buffer length
        unsafe {
            let slice = self.buffer.get_unchecked_mut(self.last_checkpoint..buf_len);
            let timestamps = self
                .timestamps
                .get_unchecked_mut(self.last_checkpoint..buf_len);
            (slice, timestamps)
        }
    }
}

/// Rounds up `x` to the closest multiple of 32. If `x % 32 == 0` then `x` is returned.
#[inline]
pub fn next_multiple_of_32(x: usize) -> usize {
    let r = x.bitand(31).not().wrapping_add(1).bitand(31);
    x.saturating_add(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_multiple_of_32() {
        // next_multiple_of_32 returns x when it is a multiple of 32
        for i in 0..32 {
            let x = i * 32;
            assert_eq!(x, next_multiple_of_32(x));
        }

        // next_multiple_of_32 rounds up to the nearest multiple of 32 when `x % 32 != 0`
        for x in 0..1024 {
            if x % 32 == 0 {
                continue;
            }
            let next_multiple = x + 32 - (x % 32);
            assert_eq!(next_multiple, next_multiple_of_32(x));
        }
    }

    #[test]
    fn new_free_context() {
        let mut shared_memory = SharedMemory::new();
        shared_memory.new_context();

        assert_eq!(shared_memory.buffer.len(), 0);
        assert_eq!(shared_memory.timestamps.len(), 0);
        assert_eq!(shared_memory.checkpoints.len(), 1);
        assert_eq!(shared_memory.last_checkpoint, 0);

        unsafe { shared_memory.buffer.set_len(32) };
        assert_eq!(shared_memory.len(), 32);
        shared_memory.new_context();

        assert_eq!(shared_memory.buffer.len(), 32);
        assert_eq!(shared_memory.timestamps, vec![0; 32]);
        assert_eq!(shared_memory.checkpoints.len(), 2);
        assert_eq!(shared_memory.last_checkpoint, 32);
        assert_eq!(shared_memory.len(), 0);

        unsafe { shared_memory.buffer.set_len(96) };
        assert_eq!(shared_memory.len(), 64);
        shared_memory.new_context();

        assert_eq!(shared_memory.buffer.len(), 96);
        assert_eq!(shared_memory.timestamps, vec![0; 96]);
        assert_eq!(shared_memory.checkpoints.len(), 3);
        assert_eq!(shared_memory.last_checkpoint, 96);
        assert_eq!(shared_memory.len(), 0);

        // free contexts
        shared_memory.free_context();
        assert_eq!(shared_memory.buffer.len(), 96);
        assert_eq!(shared_memory.timestamps, vec![0; 96]);
        assert_eq!(shared_memory.checkpoints.len(), 2);
        assert_eq!(shared_memory.last_checkpoint, 32);
        assert_eq!(shared_memory.len(), 64);

        shared_memory.free_context();
        assert_eq!(shared_memory.buffer.len(), 32);
        assert_eq!(shared_memory.timestamps, vec![0; 32]);
        assert_eq!(shared_memory.checkpoints.len(), 1);
        assert_eq!(shared_memory.last_checkpoint, 0);
        assert_eq!(shared_memory.len(), 32);

        shared_memory.free_context();
        assert_eq!(shared_memory.buffer.len(), 0);
        assert_eq!(shared_memory.timestamps.len(), 0);
        assert_eq!(shared_memory.checkpoints.len(), 0);
        assert_eq!(shared_memory.last_checkpoint, 0);
        assert_eq!(shared_memory.len(), 0);
    }

    #[test]
    fn resize() {
        let mut shared_memory = SharedMemory::new();
        shared_memory.new_context();

        shared_memory.resize(32);
        assert_eq!(shared_memory.buffer.len(), 32);
        assert_eq!(shared_memory.timestamps, vec![0; 32]);
        assert_eq!(shared_memory.len(), 32);
        assert_eq!(shared_memory.buffer.get(0..32), Some(&[0_u8; 32] as &[u8]));

        shared_memory.new_context();
        shared_memory.resize(96);
        assert_eq!(shared_memory.buffer.len(), 128);
        assert_eq!(shared_memory.timestamps, vec![0; 128]);
        assert_eq!(shared_memory.len(), 96);
        assert_eq!(
            shared_memory.buffer.get(32..128),
            Some(&[0_u8; 96] as &[u8])
        );

        shared_memory.free_context();
        shared_memory.resize(64);
        assert_eq!(shared_memory.buffer.len(), 64);
        assert_eq!(shared_memory.timestamps, vec![0; 64]);
        assert_eq!(shared_memory.len(), 64);
        assert_eq!(shared_memory.buffer.get(0..64), Some(&[0_u8; 64] as &[u8]));
    }
}
