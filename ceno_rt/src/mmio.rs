//! Memory-mapped I/O (MMIO) functions.

use rkyv::{
    Archived, Deserialize, Portable, api::high::{HighValidator, HighDeserializer}, bytecheck::CheckBytes,
    rancor::Failure,
};

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

/// Read a value from public io, deserialize it, and assert that it matches the given value.
pub fn commit<T>(v: &T)
where
    T: rkyv::Archive + core::fmt::Debug + PartialEq,
    T::Archived:
        for<'c> CheckBytes<HighValidator<'c, Failure>> + Deserialize<T, HighDeserializer<Failure>>,
{
    let expected = rkyv::access::<Archived<T>, Failure>(pubio_read_slice())
        .expect("Deserialised access failed.");
    let expected_deserialized: T =
        rkyv::deserialize::<T, Failure>(expected).expect("Deserialised value failed.");
    assert_eq!(*v, expected_deserialized);
}
