//! Memory-mapped I/O (MMIO) functions.

use rkyv::{Portable, api::high::HighValidator, bytecheck::CheckBytes, rancor::Failure};

use core::slice::from_raw_parts;

use crate::_hints_start;

static mut NEXT_HINT_LEN_AT: usize = 0x4000_0000;

pub unsafe fn init_hints() {
    NEXT_HINT_LEN_AT = core::ptr::from_ref::<u8>(&_hints_start).cast::<u8>() as usize;
}

pub fn read_slice<'a>() -> &'a [u8] {
    unsafe {
        let len: u32 = core::ptr::read(NEXT_HINT_LEN_AT as *const u32);
        NEXT_HINT_LEN_AT += 4;

        let start: *const u8 = core::ptr::from_ref::<u8>(&crate::_hints_start).cast::<u8>();
        &from_raw_parts(start, 1 << 30)[..len as usize]
    }
}

pub fn read<'a, T>() -> &'a T
where
    T: Portable + for<'c> CheckBytes<HighValidator<'c, Failure>>,
{
    rkyv::access::<T, Failure>(read_slice()).expect("Deserialised access failed.")
}
