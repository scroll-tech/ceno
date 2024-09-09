#![no_main]
#![no_std]

#[allow(unused_imports)]
use ceno_rt;

#[no_mangle]
fn main() {
    panic!("This is a panic message!");
}
