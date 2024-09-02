#![no_main]
#![no_std]
use core::ptr::addr_of_mut;

#[allow(unused_imports)]
use ceno_rt;

#[no_mangle]
fn main() {
    let y = my_recurse(3, 0);
    output(y);
}

// A sufficiently complicated function to test the stack.
#[inline(never)]
#[no_mangle]
fn my_recurse(x: u32, y: u32) -> u32 {
    if x == 0 {
        y
    } else {
        my_recurse(x - 1, y * 3 + 5)
    }
}

// A global variable to test writing to memory.
static mut OUTPUT: u32 = 0;

#[inline(never)]
fn output(out: u32) {
    unsafe {
        // Volatile write to prevent the compiler from optimizing this away.
        core::ptr::write_volatile(addr_of_mut!(OUTPUT), out);
    }
}
