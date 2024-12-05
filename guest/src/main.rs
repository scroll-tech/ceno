#![no_main]
#![no_std]

use rkyv::{
    Portable, Serialize,
    api::high::{HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    rancor::Error,
    ser::allocator::ArenaHandle,
    to_bytes,
    util::AlignedVec,
};

use core::ops::Range;
// Use volatile functions to prevent compiler optimizations.
use core::ptr::{read_volatile, write_volatile};

const HINTS: Range<usize> = 0x4000_0000..0x5000_0000;

ceno_rt::entry!(main);
fn main() {
    let x: u32 = unsafe { read_volatile(HINTS.start as *mut u32) };
    assert_eq!(x, 0xdead_beef);
}
