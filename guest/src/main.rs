#![no_main]
#![no_std]

extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;
use core::ops::Range;

const HINTS: Range<usize> = 0x4000_0000..0x5000_0000;

ceno_rt::entry!(main);
fn main() {
    println!("📜📜📜 Hello, World!");
    println!("🌏🌍🌎");
}
