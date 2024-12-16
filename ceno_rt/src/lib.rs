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
    unimplemented!("Halt is not implemented for this target, exit_code: {}", exit_code); 
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

extern "C" {
    // The address of this variable is the start of the stack (growing downwards).
    static _stack_start: u8;
}
