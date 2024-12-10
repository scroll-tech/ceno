#![no_main]
#![no_std]

extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;

ceno_rt::entry!(main);
fn main() {
    println!("📜📜📜 Hello, World!");
    println!("🌏🌍🌎");
}
