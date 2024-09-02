#![no_std]

mod io;
pub use io::info_out;

use core::arch::{asm, global_asm};

mod params;
pub use params::*;

#[cfg(not(test))]
mod panic_handler {
    use core::panic::PanicInfo;

    #[panic_handler]
    #[inline(never)]
    fn panic_handler(_panic: &PanicInfo<'_>) -> ! {
        super::halt(1)
    }
}

pub fn halt(exit_code: u32) -> ! {
    unsafe {
        asm!(
            // Set the first argument.
            "mv a0, {}",
            // Set the ecall code HALT.
            "li t0, 0x0",
            in(reg) exit_code,
        );
        riscv::asm::ecall();
    }
    #[allow(clippy::empty_loop)]
    loop {}
}

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
    jal zero, _start_rust
    ",
);

/// _start_rust is called by the assembly entry point and it calls the Rust main().
#[no_mangle]
unsafe extern "C" fn _start_rust() -> ! {
    main();
    halt(0)
}

extern "C" {
    fn main();
}

extern "C" {
    // The address of this variable is the start of the stack (growing downwards).
    static _stack_start: u8;
    // The address of this variable is the start of the heap (growing upwards).
    static _sheap: u8;
}
