use anyhow::Result;
use ceno_emul::{
    IterAddresses, Platform, Program, VMState, WORD_SIZE, Word, host_utils::read_all_messages,
};
use ceno_serde::to_vec;
use core::mem::size_of;
use itertools::Itertools;
use serde::Serialize;
use std::{fs, io, iter::zip, path::Path, sync::Arc};

pub const WORD_ALIGNMENT: usize = size_of::<u32>();

/// A structure for building the hints input to the Ceno emulator.
///
/// Use the `write` method to add a hint to the input.
/// When you are done, call `into` to convert to a `Vec<u32>` to pass to the emulator.
///
/// Our guest programs have two requirements on the format:
/// 1. The start of the hints buffer consists of a sequence of `usize` values, each representing the
///    metadata describing the layout: first the offset where the serialized bytes begin, then the
///    alignment used for each record, followed by the length of every hint in order.
/// 2. hints[..current_hint_len] can deserialise into the expected type via `ceno_serde`.
///
/// After the metadata we place every serialized blob back-to-back (with alignment padding), so the
/// runtime can walk forward from the lowest address without needing any random access.
#[derive(Default)]
pub struct CenoStdin {
    pub items: Vec<Item>,
}

#[derive(Debug, Default, Clone)]
pub struct Item {
    pub data: Vec<u8>,
    pub end_of_data: usize,
}

impl From<Vec<u32>> for Item {
    fn from(data: Vec<u32>) -> Self {
        let data: Vec<u8> = data.into_iter().flat_map(u32::to_le_bytes).collect();
        let end_of_data = data.len();
        let mut data = data;
        data.resize(data.len().next_multiple_of(WORD_ALIGNMENT), 0);
        Item { data, end_of_data }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Items {
    pub data: Vec<u8>,
    pub lens: Vec<usize>,
}

impl Items {
    pub fn total_length(&self) -> usize {
        self.data.len()
    }
    pub fn append(&mut self, item: &Item) {
        self.data.extend_from_slice(&item.data);
        self.lens.push(item.end_of_data);
    }

    /// Prepend metadata to the data buffer so that the raw
    /// serialized bytes live at the lowest addresses and can be
    /// consumed sequentially at runtime.
    pub fn finalise(self) -> Vec<u8> {
        let Items { data, lens } = self;
        let header_words = lens.len() + 2;
        let data_offset = (size_of::<u32>() * header_words).next_multiple_of(WORD_ALIGNMENT);

        // NOTE: serde format alignment with [`ceno_rt/src/mmio.rs`]
        let mut header = Vec::with_capacity(header_words);
        header.push(data_offset as u32);
        header.push(WORD_ALIGNMENT as u32);
        header.extend(lens.into_iter().map(|len| len as u32));

        let mut bytes = header
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        bytes.resize(data_offset, 0);
        bytes.extend_from_slice(&data);
        bytes
    }
}

impl From<&CenoStdin> for Vec<u8> {
    fn from(stdin: &CenoStdin) -> Vec<u8> {
        let mut items = Items::default();
        for item in &stdin.items {
            items.append(item);
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
    pub fn write(&mut self, value: &impl Serialize) -> Result<&mut Self, ceno_serde::Error> {
        let item = Item::from(to_vec(value)?);
        self.items.push(item);
        Ok(self)
    }
}

pub fn run(
    platform: Platform,
    elf: &[u8],
    hints: &CenoStdin,
    public_io: Option<&CenoStdin>,
) -> Vec<Vec<u8>> {
    let program = Program::load_elf(elf, u32::MAX).unwrap();
    let platform = Platform {
        prog_data: Arc::new(program.image.keys().copied().collect()),
        ..platform
    };

    let hints: Vec<u32> = hints.into();
    let pubio: Vec<u32> = public_io.map(|c| c.into()).unwrap_or_default();
    let hints_range = platform.hints.clone();
    let pubio_range = platform.public_io.clone();

    let mut state = VMState::new(platform, Arc::new(program));

    for (addr, value) in zip(hints_range.iter_addresses(), hints) {
        state.init_memory(addr.into(), value);
    }

    for (addr, value) in zip(pubio_range.iter_addresses(), pubio) {
        state.init_memory(addr.into(), value);
    }

    let steps = state
        .iter_until_halt()
        .collect::<Result<Vec<_>>>()
        .expect("Failed to run the program");
    eprintln!("Emulator ran for {} steps.", steps.len());
    read_all_messages(&state)
}

pub fn memory_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u32>> {
    let mut buf = fs::read(path)?;
    buf.resize(buf.len().next_multiple_of(WORD_SIZE), 0);
    Ok(buf
        .chunks_exact(WORD_SIZE)
        .map(|word| Word::from_le_bytes(word.try_into().unwrap()))
        .collect_vec())
}
