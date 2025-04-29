extern crate ceno_rt;
use ceno_rt::debug_println;
#[cfg(debug_assertions)]
use core::fmt::Write;
use rkyv::Archived;
#[cfg(debug_assertions)]
use rkyv::string::ArchivedString;
fn main() {
    let condition: &bool = ceno_rt::read();
    assert!(*condition);
    #[cfg(debug_assertions)]
    {
        let msg: &ArchivedString = ceno_rt::read();
        debug_println!("This message is a hint: {msg}");
    }

    let a: &Archived<u32> = ceno_rt::read();
    let b: &Archived<u32> = ceno_rt::read();
    let product: u32 = a * b;

    assert_eq!(product, 3992003);
    debug_println!("{product}");
}
