#![no_main]
#![no_std]
use core::{arch::asm, panic::PanicInfo, ptr::addr_of_mut};

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

#[link_section = ".init"]
#[no_mangle]
pub fn _start() -> ! {
    main();
    halt(0)
}

fn main() {
    let y = my_recurse(3, 0);
    output(y);
}

static mut OUTPUT: u32 = 0;

#[inline(never)]
fn output(out: u32) {
    // Volatile write to prevent the compiler from optimizing this away.
    unsafe { core::ptr::write_volatile(addr_of_mut!(OUTPUT), out) };
}

#[inline(never)]
#[no_mangle]
fn my_recurse(x: u32, y: u32) -> u32 {
    if x == 0 {
        y
    } else {
        my_recurse(x - 1, y * 3 + 5)
    }
}
