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
