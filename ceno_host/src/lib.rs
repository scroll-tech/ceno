use std::{collections::HashSet, iter::zip, sync::Arc};

use anyhow::Result;
use ceno_emul::{IterAddresses, Platform, Program, VMState, host_utils::read_all_messages};
use itertools::izip;
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
        let initial_offset = (size_of::<u32>() * self.items.len()).next_multiple_of(RKYV_ALIGNMENT);
        let offsets: Vec<u32> = self
            .items
            .iter()
            .scan(initial_offset, |acc, bytes| {
                let output = (*acc + bytes.len()) as u32;
                *acc += bytes.len().next_multiple_of(RKYV_ALIGNMENT);
                Some(output)
            })
            .collect();
        let offsets_u8: Vec<u8> = offsets.iter().copied().flat_map(u32::to_le_bytes).collect();
        let mut buf: AlignedVec = AlignedVec::new();
        buf.extend_from_slice(&offsets_u8);
        buf.extend_from_slice(&vec![
            0;
            buf.len().next_multiple_of(RKYV_ALIGNMENT) - buf.len()
        ]);
        for (offset, item) in izip!(offsets, &self.items) {
            buf.extend_from_slice(item);
            buf.resize(buf.len().next_multiple_of(RKYV_ALIGNMENT), 0);
            assert_eq!(
                buf.len(),
                (offset as usize).next_multiple_of(RKYV_ALIGNMENT)
            );
        }
        let (prefix, hints, postfix): (_, &[u32], _) = unsafe { buf.align_to() };
        assert_eq!(prefix, &[]);
        assert_eq!(postfix, &[]);
        hints.to_vec()
    }
}

pub fn run(platform: Platform, elf: &[u8], hints: &CenoStdin) -> Vec<String> {
    let program = Program::load_elf(elf, u32::MAX).unwrap();
    let platform = Platform {
        prog_data: Some(program.image.keys().copied().collect::<HashSet<u32>>()),
        ..platform
    };

    let hints: Vec<u32> = hints.finalise();
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
