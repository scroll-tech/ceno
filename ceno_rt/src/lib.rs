#![deny(clippy::cargo)]
#![feature(strict_overflow_ops)]
#![feature(linkage)]

#[cfg(target_arch = "riscv32")]
use core::arch::{asm, global_asm};

mod allocator;

mod mmio;
pub use mmio::{read, read_slice};

mod io;
pub use io::info_out;

mod params;
pub use params::*;

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn sys_write(_fd: i32, _buf: *const u8, _count: usize) -> isize {
    unimplemented!();
}

/// Generates random bytes.
///
/// # Safety
///
/// Make sure that `buf` has at least `nwords` words.
/// This generator is terrible. :)
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn sys_rand(recv_buf: *mut u8, words: usize) {
    // SYS_RAND_WARNING.call_once(|| {
    //     println!("WARNING: Using insecure random number generator.");
    // });
    // Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs"
    // Just for testing.
    unsafe fn step() -> u32 {
        static mut X: u32 = 0xae569764;
        // We are stealing Borland Delphi's random number generator.
        // The random numbers here are only good enough to make eg
        // HashMap works.
        X = X.wrapping_mul(134775813) + 1;
        X
    }
    // TODO(Matthias): this is a bit inefficient,
    // we could fill whole u32 words at a time.
    // But it's just for testing.
    for i in 0..words {
        let element = recv_buf.add(i);
        // The lower bits ain't really random, so might as well take
        // the higher order ones, if we are only using 8 bits.
        *element = step().to_le_bytes()[3];
    }
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn syscall_hint_len() -> usize {
    unimplemented!();
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn syscall_hint_read(_ptr: *mut u8, _len: usize) {
    unimplemented!();
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
    unimplemented!("Halt is not implemented for this target: {}", exit_code);
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

    // Call the Rust start function.
    // jal zero, _start_rust
    call main

    // If we return from main, we halt with success:

    // Set the ecall code HALT.
    li t0, 0
    // Set successful exit code, ie 0:
    li a0, 0
    ecall
    ",
);
