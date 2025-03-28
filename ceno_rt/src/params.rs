pub const WORD_SIZE: usize = 4;

// Now it's defined within RAM
// TODO define a specific region for it and avoid mixup with ram to achieve non-uniform design on heap/stack
pub const INFO_OUT_ADDR: u32 = 0xC000_0000;
