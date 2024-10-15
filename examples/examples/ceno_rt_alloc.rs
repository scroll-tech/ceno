#![no_main]
#![no_std]
use core::ptr::{addr_of, read_volatile};

extern crate ceno_rt;

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
    let v: Vec<u32> = vec![0xbeef];
    black_box(&v[0]);

    // Test writing to a larger vector on the heap
    let mut v: Vec<u32> = vec![0; 128 * 1024];
    v[999] = 0xdead_beef;
    black_box(&v[0]);
}

/// Prevent compiler optimizations.
fn black_box<T>(x: *const T) -> T {
    unsafe { read_volatile(x) }
}
