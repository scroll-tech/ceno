#![no_main]
#![no_std]

use core::panic::PanicInfo;
use riscv::asm;

#[panic_handler]
#[inline(never)]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        asm::ecall();
    }
    unreachable!();
}
