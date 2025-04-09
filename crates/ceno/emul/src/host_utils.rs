use std::iter::from_fn;

use ceno_rt::INFO_OUT_ADDR as CENO_RT_INFO_OUT_ADDR;
use itertools::Itertools;

use crate::{ByteAddr, EmuContext, VMState, Word, WordAddr};

const WORD_SIZE: usize = 4;
const INFO_OUT_ADDR: WordAddr = ByteAddr(CENO_RT_INFO_OUT_ADDR).waddr();

pub fn read_all_messages(state: &VMState) -> Vec<Vec<u8>> {
    let mut offset: WordAddr = WordAddr::from(0);
    from_fn(move || match read_message(state, offset) {
        out if out.is_empty() => None,
        out => {
            offset += out.len().div_ceil(WORD_SIZE) as u32 + 1;
            Some(out)
        }
    })
    .collect()
}

pub fn read_all_messages_as_words(state: &VMState) -> Vec<Vec<Word>> {
    read_all_messages(state)
        .iter()
        .map(|message| {
            assert_eq!(message.len() % WORD_SIZE, 0);
            message
                .chunks_exact(WORD_SIZE)
                .map(|chunk| Word::from_le_bytes(chunk.try_into().unwrap()))
                .collect_vec()
        })
        .collect_vec()
}

fn read_message(state: &VMState, offset: WordAddr) -> Vec<u8> {
    let out_addr = INFO_OUT_ADDR + offset;
    let byte_len = state.peek_memory(out_addr) as usize;

    (out_addr + 1_usize..)
        .map(|address| state.peek_memory(address))
        .flat_map(u32::to_le_bytes)
        .take(byte_len)
        .collect::<Vec<_>>()
}
