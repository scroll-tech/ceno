#![no_main]
#![no_std]
use core::{arch::asm, panic::PanicInfo};

#[panic_handler]
#[inline(never)]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

fn halt(exit_code: u32) -> ! {
    unsafe {
        asm!("mv a0, {}", in(reg) exit_code);
        asm!("li t0, 0x0");
        riscv::asm::ecall();
    }
    unreachable!();
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    halt(0)
}
