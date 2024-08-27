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

pub const REG_ECALL: usize = 5; // T0: Register for ecall number.
pub const REG_A0: usize = 10; // A0: First function argument.
pub const ECALL_HALT: u32 = 0;
pub const HALT_SUCCESS: u32 = 0;
