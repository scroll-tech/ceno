use std::iter::zip;

use anyhow::Result;
use ceno_emul::{ByteAddr, EmuContext, IterAddresses, Platform, VMState};
use itertools::izip;
use rkyv::{
    Serialize, api::high::HighSerializer, rancor::Error, ser::allocator::ArenaHandle, to_bytes,
    util::AlignedVec,
};

#[derive(Default)]
pub struct CenoStdin {
    pub items: Vec<AlignedVec>,
}

impl CenoStdin {
    pub fn write_slice(&mut self, bytes: AlignedVec) {
        self.items.push(bytes);
    }

    pub fn write(
        &mut self,
        item: &impl for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, Error>>,
    ) -> Result<(), Error> {
        to_bytes::<Error>(item).map(|bytes| self.write_slice(bytes))
    }

    pub fn finalise(&self) -> Vec<u32> {
        // TODO: perhaps don't hardcode 16 here.
        // It's from rkyv's format, so we can probably take it from there somehow?
        // TODO: clean this up.
        let initial_offset = (size_of::<u32>() * self.items.len()).next_multiple_of(16);
        // println!("offset: {}", initial_offset);
        let offsets: Vec<u32> = self
            .items
            .iter()
            .scan(initial_offset, |acc, bytes| {
                let output = (*acc + bytes.len()) as u32;
                // print!("len: {}\t", bytes.len());
                *acc += bytes.len().next_multiple_of(16);
                // println!("acc: {}", *acc);
                Some(output)
            })
            .collect();
        let offsets_u8: Vec<u8> = offsets.iter().copied().flat_map(u32::to_le_bytes).collect();
        let mut buf: AlignedVec = AlignedVec::new();
        buf.extend_from_slice(&offsets_u8);
        // println!("buf.len() after offsets: {}", buf.len());
        buf.extend_from_slice(&vec![0; buf.len().next_multiple_of(16) - buf.len()]);
        // println!("buf.len() after offset padding: {}", buf.len());
        for (offset, item) in izip!(offsets, &self.items) {
            buf.extend_from_slice(item);
            buf.extend_from_slice(&vec![0; buf.len().next_multiple_of(16) - buf.len()]);
            assert_eq!(buf.len(), offset.next_multiple_of(16) as usize);
        }
        let (prefix, hints, postfix): (_, &[u32], _) = unsafe { buf.align_to() };
        assert_eq!(prefix, &[]);
        assert_eq!(postfix, &[]);
        hints.to_vec()
    }
}

// TODO: clean up, don't copy and paste.
const WORD_SIZE: usize = 4;
const INFO_OUT_ADDR: u32 = 0xC000_0000;

fn read_all_messages(state: &VMState) -> Vec<String> {
    let mut all_messages = Vec::new();
    let mut word_offset = 0;
    loop {
        let out = read_message(state, word_offset);
        if out.is_empty() {
            break;
        }
        word_offset += out.len().div_ceil(WORD_SIZE) as u32 + 1;
        all_messages.push(out);
    }
    all_messages
}

fn read_message(state: &VMState, word_offset: u32) -> String {
    let out_addr = ByteAddr(INFO_OUT_ADDR).waddr() + word_offset;
    let byte_len = state.peek_memory(out_addr);
    let word_len_up = byte_len.div_ceil(4);

    let mut info_out = Vec::with_capacity(WORD_SIZE * word_len_up as usize);
    for i in 1..1 + word_len_up {
        let value = state.peek_memory(out_addr + i);
        info_out.extend_from_slice(&value.to_le_bytes());
    }
    info_out.truncate(byte_len as usize);
    String::from_utf8_lossy(&info_out).to_string()
}

// TODO(Matthias): also return exit code (if any)
pub fn run(platform: Platform, elf: &[u8], hints: &CenoStdin) -> Vec<String> {
    let hints: Vec<u32> = hints.finalise();

    let mut state = VMState::new_from_elf(platform.clone(), elf).expect("Failed to load ELF");

    for (addr, value) in zip(platform.hints.iter_addresses(), hints) {
        state.init_memory(addr.into(), value);
    }

    let steps = state
        .iter_until_halt()
        .collect::<Result<Vec<_>>>()
        .expect("Failed to run the program");
    eprintln!("Emulator ran for {} steps.", steps.len());
    read_all_messages(&state)
}
