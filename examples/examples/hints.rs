extern crate alloc;
extern crate ceno_rt;
use ceno_rt::debug_println;
#[cfg(debug_assertions)]
use core::fmt::Write;

fn main() {
    let condition: bool = ceno_rt::read();
    assert!(condition);
    #[cfg(debug_assertions)]
    {
        use alloc::string::String;
        let msg: String = ceno_rt::read();
        debug_println!("This message is a hint: {msg}");
    }

    let a: u32 = ceno_rt::read();
    let b: u32 = ceno_rt::read();
    let product: u32 = a * b;

    assert_eq!(product, 3992003);
    debug_println!("{product}");
}
