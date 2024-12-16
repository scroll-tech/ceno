use std::iter::from_fn;

use crate::{ByteAddr, EmuContext, VMState, WordAddr};

const WORD_SIZE: usize = 4;
const INFO_OUT_ADDR: WordAddr = ByteAddr(0xC000_0000).waddr();

pub fn read_all_messages(state: &VMState) -> Vec<String> {
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

fn read_message(state: &VMState, offset: WordAddr) -> String {
    let out_addr = INFO_OUT_ADDR + offset;
    let byte_len = state.peek_memory(out_addr) as usize;

    String::from_utf8_lossy(
        &(out_addr + 1_usize..)
            .map(|address| state.peek_memory(address))
            .flat_map(u32::to_le_bytes)
            .take(byte_len)
            .collect::<Vec<_>>(),
    )
    .to_string()
}
