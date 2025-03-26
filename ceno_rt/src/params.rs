pub const WORD_SIZE: usize = 4;

// Now it's defined within RAM
// TODO define a specific region for it, as it will make non-uniform design harder
pub const INFO_OUT_ADDR: u32 = 0xC000_0000;
