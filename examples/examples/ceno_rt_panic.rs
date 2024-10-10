#![no_main]
#![no_std]

extern crate ceno_rt;

#[no_mangle]
fn main() {
    panic!("This is a panic message!");
}
