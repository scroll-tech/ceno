//! Memory-mapped I/O (MMIO) functions.

use rkyv::{Portable, api::high::HighValidator, bytecheck::CheckBytes, rancor::Failure};

use core::slice::from_raw_parts;

extern "C" {
    /// The address of this variable is the start of the hints ROM.
    ///
    /// It is defined in the linker script.
    static _hints_start: u8;
    static _hints_end: u8;
}

static mut NEXT_HINT_LEN_AT: *const u8 = &raw const _hints_start;

pub fn read_slice<'a>() -> &'a [u8] {
    unsafe {
        let len: u32 = core::ptr::read(NEXT_HINT_LEN_AT as *const u32);
        NEXT_HINT_LEN_AT = NEXT_HINT_LEN_AT.add(4);

        let hints_region = {
            let total_length = (&raw const _hints_end).offset_from(&_hints_start) as usize;
            from_raw_parts(&_hints_start, total_length)
        };

        &hints_region[..len as usize]
    }
}

pub fn read<'a, T>() -> &'a T
where
    T: Portable + for<'c> CheckBytes<HighValidator<'c, Failure>>,
{
    rkyv::access::<T, Failure>(read_slice()).expect("Deserialised access failed.")
}
