#![no_main]
// #![no_std]

extern crate ceno_rt;
use ceno_rt::println;
use core::fmt::Write;
use rkyv::{Archived, string::ArchivedString};
use std::collections::BTreeMap;

ceno_rt::entry!(main);
fn main() {
    let _foo: BTreeMap<&str, &str> = Default::default();
    let msg: &ArchivedString = ceno_rt::read();

    let a: &Archived<u32> = ceno_rt::read();
    let b: &Archived<u32> = ceno_rt::read();
    let product = a * b;

    println!("📜📜📜 Hello, World!");
    println!("🌏🌍🌎");
    println!("🚀🚀🚀");
    println!("This message is a hint: {msg}");
    println!("I know the factors for {product}.");
    if *ceno_rt::read() {
        panic!();
    }
}
