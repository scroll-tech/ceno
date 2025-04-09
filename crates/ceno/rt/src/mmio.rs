//! Memory-mapped I/O (MMIO) functions.

use rkyv::{Portable, api::high::HighValidator, bytecheck::CheckBytes, rancor::Failure};

use core::slice::from_raw_parts;

/// The memory region with our hints.
///
/// Logically, this is a static constant, but the type system doesn't see it that way.
/// (We hope that the optimiser is smart enough to see that it is a constant.)
fn hints_region<'a>() -> &'a [u8] {
    extern "C" {
        /// The address of this variable is the start of the hints ROM.
        ///
        /// It is defined in the linker script.  The value of this variable is undefined.
        static _hints_start: u8;
        /// The _address_ of this variable is the length of the hints ROM
        ///
        /// It is defined in the linker script.  The value of this variable is undefined.
        static _hints_length: usize;
    }
    unsafe {
        let hints_length = &_hints_length as *const usize as usize;
        from_raw_parts(&_hints_start, hints_length)
    }
}

/// Get the length of the next hint
fn hint_len() -> usize {
    extern "C" {
        /// The address of this variable is the start of the slice that holds the length of the hints.
        ///
        /// It is defined in the linker script.  The value of this variable is undefined.
        static _lengths_of_hints_start: usize;
    }
    static mut NEXT_HINT_LEN_AT: *const usize = &raw const _lengths_of_hints_start;
    unsafe {
        let len: usize = core::ptr::read(NEXT_HINT_LEN_AT);
        NEXT_HINT_LEN_AT = NEXT_HINT_LEN_AT.add(1);
        len
    }
}

pub fn read_slice<'a>() -> &'a [u8] {
    &hints_region()[..hint_len()]
}

pub fn read<'a, T>() -> &'a T
where
    T: Portable + for<'c> CheckBytes<HighValidator<'c, Failure>>,
{
    rkyv::access::<T, Failure>(read_slice()).expect("Deserialised access failed.")
}

/// The memory region with public io.
fn pubio_region<'a>() -> &'a [u8] {
    extern "C" {
        /// The address of this variable is the start of the hints ROM.
        ///
        /// It is defined in the linker script.  The value of this variable is undefined.
        static _pubio_start: u8;
        /// The _address_ of this variable is the length of the hints ROM
        ///
        /// It is defined in the linker script.  The value of this variable is undefined.
        static _pubio_length: usize;
    }
    unsafe {
        let pubio_length = &_pubio_length as *const usize as usize;
        from_raw_parts(&_pubio_start, pubio_length)
    }
}

/// Get the length of the next pubio
fn pubio_len() -> usize {
    extern "C" {
        /// The address of this variable is the start of the slice that holds the length of the hints.
        ///
        /// It is defined in the linker script.  The value of this variable is undefined.
        static _lengths_of_pubio_start: usize;
    }
    static mut NEXT_PUBIO_LEN_AT: *const usize = &raw const _lengths_of_pubio_start;
    unsafe {
        let len: usize = core::ptr::read(NEXT_PUBIO_LEN_AT);
        NEXT_PUBIO_LEN_AT = NEXT_PUBIO_LEN_AT.add(1);
        len
    }
}

pub fn pubio_read_slice<'a>() -> &'a [u8] {
    &pubio_region()[..pubio_len()]
}

pub fn commit<'a, T, F: From<&'a T> + core::fmt::Debug + PartialEq>(v: &F)
where
    T: Portable + for<'c> CheckBytes<HighValidator<'c, Failure>> + 'a,
{
    let expected: F = rkyv::access::<T, Failure>(pubio_read_slice())
        .expect("Deserialised access failed.")
        .into();
    assert_eq!(*v, expected);
}
