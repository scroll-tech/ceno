use std::marker::PhantomData;

use itertools::Itertools;

use crate::{EmuContext, VMState, Word, WordAddr};

/// Utilities for interpreting the address segment `[start..start + length]` of `vm`
/// as an array of type T
pub struct MemoryView<'a, T> {
    vm: &'a VMState,
    start: WordAddr,
    length: usize,
    marker: PhantomData<T>,
}

pub trait HasByteRepr
where
    Self: Sized,
{
    fn vec_from_bytes(bytes: &[u8]) -> Vec<Self>;
    fn vec_into_bytes(vec: Vec<Self>) -> Vec<u8>;
}

impl HasByteRepr for u8 {
    fn vec_from_bytes(bytes: &[u8]) -> Vec<Self> {
        bytes.to_vec()
    }
    fn vec_into_bytes(vec: Vec<Self>) -> Vec<u8> {
        vec
    }
}

macro_rules! impl_has_byte_repr {
    ($t:ty, $size:expr) => {
        impl HasByteRepr for $t {
            fn vec_from_bytes(bytes: &[u8]) -> Vec<Self> {
                bytes
                    .chunks($size)
                    .map(|chunk| <$t>::from_le_bytes(chunk.try_into().unwrap()))
                    .collect_vec()
            }
            fn vec_into_bytes(vec: Vec<Self>) -> Vec<u8> {
                vec.iter()
                    .map(|word| word.to_le_bytes())
                    .flatten()
                    .collect_vec()
            }
        }
    };
}

impl_has_byte_repr!(u32, 4);
impl_has_byte_repr!(u64, 8);

impl<'a, T: Sized + HasByteRepr> MemoryView<'a, T> {
    /// `strict_align = true` enforces that the address segment is aligned with
    /// the size of T
    pub fn new(vm: &'a VMState, start: u32, length: usize, strict_align: bool) -> Self {
        if strict_align {
            // enforce start alignment
            assert!(start as usize % size_of::<T>() == 0);
            // enforce end alignment
            assert!(length * size_of::<T>() % size_of::<WordAddr>() == 0)
        }
        MemoryView {
            vm,
            start: WordAddr::from(start),
            length,
            marker: Default::default(),
        }
    }

    /// Interpret `T`s as words, usually for writing into memory
    pub fn into_words(vec: Vec<T>) -> Vec<Word> {
        Word::vec_from_bytes(&T::vec_into_bytes(vec))
    }

    /// Number of words covered by the `length` instances of `T`
    pub fn words_count(&self) -> usize {
        self.length * size_of::<T>() / size_of::<WordAddr>()
    }

    /// Addresses covered by the `length` instances of `T`
    pub fn iter_addrs(&self) -> impl Iterator<Item = WordAddr> {
        (self.start..).take(self.words_count())
    }

    /// Addresses covered by the `length` instances of `T`
    pub fn addrs(&self) -> Vec<WordAddr> {
        self.iter_addrs().collect_vec()
    }

    /// Words covered by the `length` instances of `T`
    pub fn iter_words(&self) -> impl Iterator<Item = Word> + '_ {
        self.iter_addrs().map(|addr| self.vm.peek_memory(addr))
    }

    /// Words covered by the `length` instances of `T`
    pub fn words(&self) -> Vec<Word> {
        self.iter_words().collect_vec()
    }

    // Bytes covered by the `length` instances of `T`
    pub fn iter_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.iter_words().map(|word| word.to_le_bytes()).flatten()
    }

    // Bytes covered by the `length` instances of `T`
    pub fn bytes(&self) -> Vec<u8> {
        self.iter_bytes().collect_vec()
    }

    // Interpret target segment as consecutive `T`s
    pub fn interpret(&self) -> Vec<T> {
        T::vec_from_bytes(&self.iter_bytes().collect_vec())
    }
}
