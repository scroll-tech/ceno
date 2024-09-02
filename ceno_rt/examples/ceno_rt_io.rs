#![no_main]
#![no_std]

#[allow(unused_imports)]
use ceno_rt;
use ceno_rt::write_info;

#[no_mangle]
#[inline(never)]
fn main() {
    write_info("📜📜📜 Hello, World!\n".as_bytes());
    write_info("🌏🌍🌎\n".as_bytes());
}
