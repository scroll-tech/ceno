use itertools::Itertools;

use crate::{EmuContext, VMState, WORD_SIZE, Word, WordAddr};

/// Utilities for reading/manipulating a memory segment of fixed length
pub struct MemoryView<'a, const LENGTH: usize> {
    vm: &'a VMState,
    start: WordAddr,
}

impl<'a, const LENGTH: usize> MemoryView<'a, LENGTH> {
    /// Creates a new memory segment view
    /// Asserts that `start` is a multiple of `WORD_SIZE`
    pub fn new(vm: &'a VMState, start: u32) -> Self {
        assert!(start % WORD_SIZE as u32 == 0);
        // TODO: do we need stricter alignment requirements for keccak (u64 array)
        MemoryView {
            vm,
            start: WordAddr::from(start),
        }
    }

    pub fn iter_addrs(&self) -> impl Iterator<Item = WordAddr> {
        (self.start..).take(LENGTH)
    }

    pub fn addrs(&self) -> [WordAddr; LENGTH] {
        self.iter_addrs().collect_vec().try_into().unwrap()
    }

    pub fn iter_words(&self) -> impl Iterator<Item = Word> + '_ {
        self.iter_addrs().map(|addr| self.vm.peek_memory(addr))
    }

    pub fn words(&self) -> [Word; LENGTH] {
        self.iter_words().collect_vec().try_into().unwrap()
    }

    pub fn iter_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.iter_words().map(|word| word.to_le_bytes()).flatten()
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.iter_bytes().collect_vec()
    }

    pub fn debug(&self) {
        dbg!(self.start, LENGTH);
        dbg!(self.addrs());
        dbg!(self.words());
        dbg!(self.bytes());
    }
}
