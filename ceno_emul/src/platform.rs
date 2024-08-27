pub struct Platform {
    pub rom_start: u32,
    pub rom_size: u32,
    pub pc_start: u32,
}

pub const CENO_PLATFORM: Platform = Platform {
    pc_start: 0x20000000,
    rom_start: 0x20000000,
    rom_size: 0x10000000,
};
