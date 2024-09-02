use core::{ptr::write_volatile, slice};

const WORD_SIZE: usize = 4;

const INFO_OUT_ADDR: u32 = 0xC000_0000;

static mut INFO_OUT_CURSOR: *mut u32 = INFO_OUT_ADDR as *mut u32;

pub fn write_info_u32(msg: &[u32]) {
    let byte_len = msg.len() * WORD_SIZE;
    write_info_u32_and_odd(msg, None, byte_len);
}

pub fn write_info(msg: &[u8]) {
    let byte_len = msg.len();
    let word_len_up = byte_len.div_ceil(WORD_SIZE);
    let bytes_to_erase = word_len_up * WORD_SIZE - byte_len;

    let msg_words = unsafe {
        // SAFETY: We only support aligned u32 reads. We do read beyond the slice, but reading the last odd bytes means reading the full word and masking the high bytes.
        slice::from_raw_parts(msg.as_ptr() as *const u32, word_len_up)
    };

    if bytes_to_erase == 0 {
        write_info_u32_and_odd(msg_words, None, byte_len);
    } else {
        // Truncate the last word to meet the actual length of the message.
        let odd_word = msg_words[word_len_up - 1];
        let odd_word = (odd_word << (bytes_to_erase * 8)) >> (bytes_to_erase * 8);
        write_info_u32_and_odd(&msg_words[..word_len_up - 1], Some(odd_word), byte_len);
    };
}

fn write_info_u32_and_odd(msg: &[u32], odd_word: Option<u32>, byte_len: usize) {
    unsafe {
        let mut cursor = INFO_OUT_CURSOR.add(1);
        for word in msg {
            write_volatile(cursor, *word);
            cursor = cursor.add(1);
        }
        if let Some(word) = odd_word {
            write_volatile(cursor, word);
            cursor = cursor.add(1);
        }
        write_volatile(INFO_OUT_CURSOR, byte_len as u32);
        INFO_OUT_CURSOR = cursor;
    }
}
