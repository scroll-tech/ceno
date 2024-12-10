use crate::{ByteAddr, EmuContext, VMState};

const WORD_SIZE: usize = 4;
const INFO_OUT_ADDR: u32 = 0xC000_0000;

pub fn read_all_messages(state: &VMState) -> Vec<String> {
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
    let byte_len = state.peek_memory(out_addr) as usize;
    let word_len_up = byte_len.div_ceil(4);

    String::from_utf8_lossy(
        &(out_addr + 1_usize..)
            .take(word_len_up)
            .map(|memory| state.peek_memory(memory))
            .flat_map(u32::to_le_bytes)
            .take(byte_len)
            .collect::<Vec<_>>(),
    )
    .to_string()
}
