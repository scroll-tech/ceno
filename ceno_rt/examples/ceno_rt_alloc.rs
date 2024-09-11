#![no_main]
#![no_std]
use core::ptr::{addr_of, read_volatile};

#[allow(unused_imports)]
use ceno_rt;

extern crate alloc;
use alloc::{vec, vec::Vec};

static mut OUTPUT: u32 = 0;

#[no_mangle]
fn main() {
    // Test writing to a global variable.
    unsafe {
        OUTPUT = 0xf00d;
        black_box(addr_of!(OUTPUT));
    }

    // Test writing to the heap.
    let mut v: Vec<u32> = vec![];
    v.push(0xbeef);
    black_box(&v[0]);
}

/// Prevent compiler optimizations.
fn black_box<T>(x: *const T) -> T {
    unsafe { read_volatile(x) }
}
