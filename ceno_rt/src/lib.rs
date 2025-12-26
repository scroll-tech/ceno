#![deny(clippy::cargo)]
#![feature(linkage)]
use getrandom::{Error, register_custom_getrandom};

#[cfg(target_arch = "riscv32")]
use core::arch::{asm, global_asm};
use std::{
    alloc::{Layout, alloc_zeroed},
    ptr,
};

#[cfg(target_arch = "riscv32")]
mod allocator;

mod mmio;
pub use mmio::{commit, read, read_owned, read_slice};

mod io;
#[cfg(debug_assertions)]
pub use io::info_out;

mod params;
pub use params::*;

#[unsafe(no_mangle)]
#[linkage = "weak"]
pub extern "C" fn sys_write(_fd: i32, _buf: *const u8, _count: usize) -> isize {
    0
}

#[unsafe(no_mangle)]
#[linkage = "weak"]
pub extern "C" fn sys_alloc_words(nwords: usize) -> *mut u32 {
    unsafe { alloc_zeroed(Layout::from_size_align(4 * nwords, 4).unwrap()) as *mut u32 }
}

#[unsafe(no_mangle)]
#[linkage = "weak"]
pub extern "C" fn sys_getenv(_name: *const u8) -> *const u8 {
    ptr::null()
}

/// Generates random bytes.
///
/// # Safety
///
/// Make sure that `buf` has at least `nwords` words.
/// This generator is terrible. :)
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub unsafe extern "C" fn sys_rand(recv_buf: *mut u8, words: usize) {
    fn step() -> u32 {
        static mut X: u32 = 0xae569764;
        // We are stealing Borland Delphi's random number generator.
        // The random numbers here are only good enough to make eg
        // HashMap work.
        //
        // SAFETY: Used for hashing purposes so it is more or less OK to have conflicting reads
        // and writes.
        unsafe {
            X = X.wrapping_mul(134775813) + 1;
            X
        }
    }
    let mut idx = 0;
    let steps = words / 4;
    let rest = words % 4;
    for _ in 0..steps {
        let bytes = step().to_le_bytes();
        // SAFETY: Up to the caller
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), recv_buf.add(idx), 4);
        }
        idx = idx.wrapping_add(4);
    }
    let [a, b, c, _] = step().to_le_bytes();
    for (_, el) in (0..rest).zip([a, b, c]) {
        // SAFETY: Up to the caller
        unsafe {
            *recv_buf.add(idx) = el;
        }
        idx = idx.wrapping_add(1);
    }
}

/// Custom random number generator for getrandom
///
/// One of sproll's dependencies uses the getrandom crate,
/// and it will only build, if we provide a custom random number generator.
///
/// Otherwise, it'll complain about an unsupported target.
pub fn my_get_random(buf: &mut [u8]) -> Result<(), Error> {
    unsafe { sys_rand(buf.as_mut_ptr(), buf.len()) };
    Ok(())
}
register_custom_getrandom!(my_get_random);

/// Custom getrandom implementation for getrandom v0.3
///
/// see also: <https://docs.rs/getrandom/0.3.3/getrandom/#custom-backend>
///
/// # Safety
/// - `dest` must be valid for writes of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom_v3::Error> {
    unsafe {
        sys_rand(dest, len);
    }
    Ok(())
}

pub fn halt(exit_code: u32) -> ! {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        asm!(
            "ecall",
            in ("a0") exit_code,
            in ("t0") 0,
        );
        unreachable!();
    }
    #[cfg(not(target_arch = "riscv32"))]
    unimplemented!(
        "Halt is only implemented for RiscV, not for this target, exit_code: {}",
        exit_code
    );
}

#[cfg(target_arch = "riscv32")]
global_asm!(
    "
// The entry point for the program.
.section .init
.global _start
_start:

    // Set the global pointer somewhere towards the start of RAM.
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // Set the stack pointer and frame pointer to the top of the stack.
    la sp, _stack_start
    mv fp, sp

    // Call Rust's main function.
    call main

    // If we return from main, we halt with success:

    // Set the ecall code HALT.
    li t0, 0
    // Set successful exit code, ie 0:
    li a0, 0
    ecall
    ",
);

unsafe extern "C" {
    // The address of this variable is the start of the stack (growing downwards).
    static _stack_start: u8;
}

#[cfg(test)]
mod tests {
    use crate::sys_rand;

    #[test]
    fn fills_with_random_bytes() {
        let mut buf = [0u8; 65];
        unsafe {
            sys_rand(buf.as_mut_ptr(), buf.len());
        }
        assert_ne!(buf, [0u8; 65]);
    }
}
