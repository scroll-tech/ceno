#![no_std]

//! Word-addressed serialization utilities extracted from OpenVM.

extern crate alloc;

mod deserializer;
mod err;
mod serializer;

pub use deserializer::{from_slice, Deserializer, WordRead};
pub use err::{Error, Result};
pub use serializer::{to_vec, to_vec_with_capacity, Serializer, WordWrite};

pub(crate) const WORD_SIZE: usize = 4;

#[inline]
pub(crate) const fn align_up(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        value
    } else {
        let mask = alignment - 1;
        (value + mask) & !mask
    }
}
