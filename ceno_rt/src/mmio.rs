//! Memory-mapped I/O (MMIO) functions.

use rkyv::{Portable, api::high::HighValidator, bytecheck::CheckBytes, rancor::Error};

use core::slice::from_raw_parts;

use crate::_hints_start;

static mut NEXT_HINT_LEN_AT: usize = 0x4000_0000;

pub unsafe fn init_hints() {
    NEXT_HINT_LEN_AT = core::ptr::from_ref::<u8>(&_hints_start).cast::<u8>() as usize;
}

// pub const HINTS_START: usize = 0x4000_0000;

// static mut STDIN: SerialisedCenoStdin = SerialisedCenoStdin(&[]);
// static mut STDIN_ITER: SerialisedCenoStdinIter = unsafe { SerialisedCenoStdinIter {
//     next: 0,
//     buf: &raw const STDIN,
// }};

// // This should only be called once at the start.
// // Similar to how we init the allocator.
// pub fn set_hints_slice() {
//     unsafe {
//         STDIN = SerialisedCenoStdin(from_raw_parts(
//             HINTS.start as *const u8,
//             HINTS.end - HINTS.start,
//         ))
//     };
// }

// // static HINTS_SLICE: &[u8] = unsafe {
// //     slice::from_raw_parts(HINTS.start as *const u8, HINTS.end - HINTS.start)
// // };

// // const HINTS: Range<usize> = 0x4000_0000..0x5000_0000;

// // static HINTS_SLICE: &'static [u8] =
// //     unsafe { core::slice::from_raw_parts(HINTS.start as *const u8, HINTS.end - HINTS.start) };

// // #[derive(Default)]
// // pub struct CenoStdin {
// //     pub items: Vec<AlignedVec>,
// // }

// pub struct SerialisedCenoStdin<'a>(&'a [u8]);

// pub struct SerialisedCenoStdinIter<'a> {
//     buf: &'a SerialisedCenoStdin<'a>,
//     next: usize,
// }

// // pub fn read() {

// // }

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
    T: Portable + for<'c> CheckBytes<HighValidator<'c, Error>>,
{
    rkyv::access::<T, Error>(read_slice()).unwrap()
}

// impl<'b> SerialisedCenoStdinIter<'b> {
//     pub fn read<'a, T>(&'a mut self) -> &'b T
//     where
//         T: Portable + for<'c> CheckBytes<HighValidator<'c, Error>>,
//     {
//         rkyv::access::<T, Error>(self.read_slice()).unwrap()
//     }

//     pub fn read_slice<'a>(&'a mut self) -> &'b [u8] {
//         self.next().unwrap()
//     }
// }

// impl<'a> Iterator for SerialisedCenoStdinIter<'a> {
//     type Item = &'a [u8];
//     fn next(&mut self) -> Option<Self::Item> {
//         let len = u32::from_le_bytes(
//             self.buf.0[self.next..][..size_of::<u32>()]
//                 .try_into()
//                 .unwrap(),
//         ) as usize;
//         self.next += size_of::<u32>();
//         Some(&self.buf.0[..len])
//     }
// }

// impl<'a> IntoIterator for &'a SerialisedCenoStdin<'a> {
//     type Item = &'a [u8];
//     type IntoIter = SerialisedCenoStdinIter<'a>;

//     fn into_iter(self) -> Self::IntoIter {
//         SerialisedCenoStdinIter { next: 0, buf: self }
//     }
// }
