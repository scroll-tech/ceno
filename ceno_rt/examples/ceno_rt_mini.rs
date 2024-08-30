#![no_main]
#![no_std]
use core::{arch::asm, panic::PanicInfo};

#[panic_handler]
#[inline(never)]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    halt(1)
}

fn halt(exit_code: u32) -> ! {
    unsafe {
        asm!(
            "mv a0, {}",
            "li t0, 0x0",
            in(reg) exit_code,
        );
        riscv::asm::ecall();
    }
    unreachable!()
}

#[no_mangle]
pub fn _start() -> ! {
    halt(0)
}
