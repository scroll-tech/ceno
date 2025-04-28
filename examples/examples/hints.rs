extern crate ceno_rt;
use ceno_rt::debug_println;
use core::fmt::Write;
use rkyv::{Archived, string::ArchivedString};

fn main() {
    let condition: &bool = ceno_rt::read();
    assert!(*condition);
    let msg: &ArchivedString = ceno_rt::read();

    let a: &Archived<u32> = ceno_rt::read();
    let b: &Archived<u32> = ceno_rt::read();
    let product: u32 = a * b;

    assert_eq!(product, 3992003);
    debug_println!("{product}");
    debug_println!("This message is a hint: {msg}");
}
