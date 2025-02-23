use std::{
    iter::{repeat, zip},
    sync::Arc,
};

use anyhow::Result;
use ceno_emul::{IterAddresses, Platform, Program, VMState, host_utils::read_all_messages};
use itertools::{Itertools, chain};
use rkyv::{
    Serialize, api::high::HighSerializer, rancor::Error, ser::allocator::ArenaHandle, to_bytes,
    util::AlignedVec,
};

// We want to get access to the default value of `AlignedVec::ALIGNMENT`, and using it directly like this
//   pub const RKVY_ALIGNMENT: usize = rkyv::util::AlignedVec::ALIGNMENT;
// doesn't work:
pub const RKYV_ALIGNMENT: usize = {
    type AlignedVec = rkyv::util::AlignedVec;
    AlignedVec::ALIGNMENT
};

/// A structure for building the hints input to the Ceno emulator.
///
/// Use the `write` method to add a hint to the input.
/// When you are done, call `into` to convert to a `Vec<u32>` to pass to the emulator.
///
/// Our guest programs have two requirements on the format:
/// 1. The start of the hints buffer consists of a sequence of `usize` values, each representing the
///    length of the next hint (from the start of the whole buffer).
/// 2. hints[..current_hint_len] can deserialise into the expected type via rkyv.
///
/// Note how we overlap the two areas, and don't specify starts for our hints.  That's a simplification
/// and performance improvement we can make because of how rkyv works: you can add arbitrary padding to
/// the left of a serialised buffer, and it will still work.
#[derive(Default)]
pub struct CenoStdin {
    pub items: Vec<AlignedVec>,
}

#[derive(Debug, Default, Clone)]
pub struct Item {
    pub data: Vec<u8>,
    pub end_of_data: usize,
}

impl From<&AlignedVec> for Item {
    fn from(data: &AlignedVec) -> Self {
        let mut data = data.to_vec();
        let end_of_data = data.len();
        data.resize(data.len().next_multiple_of(RKYV_ALIGNMENT), 0);
        Item { data, end_of_data }
    }
}

impl From<Vec<u32>> for Item {
    fn from(data: Vec<u32>) -> Self {
        let data: Vec<u8> = data.into_iter().flat_map(u32::to_le_bytes).collect();
        Item {
            end_of_data: data.len(),
            data,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Items {
    pub data: Vec<u8>,
    pub ends: Vec<usize>,
}

impl Items {
    pub fn total_length(&self) -> usize {
        self.data.len()
    }
    pub fn append(&mut self, item: Item) {
        let end = self.total_length() + item.end_of_data;
        self.data.extend_from_slice(&item.data);
        self.ends.push(end);
    }

    /// Shift all the end cursors by `n`
    pub fn shift(&mut self, n: usize) {
        for end in &mut self.ends {
            *end += n;
        }
    }

    /// Prepend the end cursors to the data buffer
    ///
    /// Taking care to adjust the recorded ends to account
    /// for the space the ends themselves take up.
    pub fn finalise(mut self) -> Vec<u8> {
        let start_of_data = (size_of::<u32>() * self.ends.len()).next_multiple_of(RKYV_ALIGNMENT);
        self.shift(start_of_data);
        let lengths = self.ends.iter().map(|&end| end as u32);
        let padded_lengths =
            chain!(lengths.flat_map(u32::to_le_bytes), repeat(0_u8)).take(start_of_data);
        chain!(padded_lengths, self.data.clone()).collect()
    }
}

impl From<&CenoStdin> for Vec<u8> {
    fn from(stdin: &CenoStdin) -> Vec<u8> {
        let mut items = Items::default();
        for item in &stdin.items {
            items.append(Item::from(item));
        }
        items.finalise()
    }
}

impl From<&CenoStdin> for Vec<u32> {
    fn from(stdin: &CenoStdin) -> Vec<u32> {
        Vec::<u8>::from(stdin)
            .into_iter()
            .tuples()
            .map(|(a, b, c, d)| u32::from_le_bytes([a, b, c, d]))
            .collect()
    }
}

impl CenoStdin {
    pub fn write_slice(&mut self, bytes: AlignedVec) -> &mut Self {
        self.items.push(bytes);
        self
    }

    pub fn write(
        &mut self,
        item: &impl for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, Error>>,
    ) -> Result<&mut Self, Error> {
        to_bytes::<Error>(item).map(|bytes| self.write_slice(bytes))
    }
}

pub fn run(platform: Platform, elf: &[u8], hints: &CenoStdin) -> Vec<Vec<u8>> {
    let program = Program::load_elf(elf, u32::MAX).unwrap();
    let platform = Platform {
        prog_data: program.image.keys().copied().collect(),
        ..platform
    };

    let hints: Vec<u32> = hints.into();
    let hints_range = platform.hints.clone();

    let mut state = VMState::new(platform, Arc::new(program));

    for (addr, value) in zip(hints_range.iter_addresses(), hints) {
        state.init_memory(addr.into(), value);
    }

    let steps = state
        .iter_until_halt()
        .collect::<Result<Vec<_>>>()
        .expect("Failed to run the program");
    eprintln!("Emulator ran for {} steps.", steps.len());
    read_all_messages(&state)
}
