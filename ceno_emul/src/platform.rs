use std::ops::Range;

/// The Platform struct holds the parameters of the VM.
pub struct Platform;

pub const CENO_PLATFORM: Platform = Platform;

impl Platform {
    pub fn rom_start(&self) -> u32 {
        0x20000000
    }

    pub fn rom_size(&self) -> u32 {
        0x10000000
    }

    pub fn rom_range(&self) -> Range<u32> {
        self.rom_start()..self.rom_start() + self.rom_size()
    }

    pub fn pc_start(&self) -> u32 {
        self.rom_start()
    }

    /// Register containing the ecall function code. (x5, t0)
    pub fn reg_ecall(&self) -> usize {
        5
    }

    /// Register containing the first function argument. (x10, a0)
    pub fn reg_arg0(&self) -> usize {
        10
    }

    /// The code of ecall HALT.
    pub fn ecall_halt(&self) -> u32 {
        0
    }

    /// The code of success.
    pub fn code_success(&self) -> u32 {
        0
    }
}
