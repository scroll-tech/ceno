#![no_main]
#![no_std]

extern crate ceno_rt;

ceno_rt::entry!(main);
fn main() {
    panic!("This is a panic message!");
}
