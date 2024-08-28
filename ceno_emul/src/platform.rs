/// The Platform struct holds the parameters of the VM.
pub struct Platform;

pub const CENO_PLATFORM: Platform = Platform;

impl Platform {
    // Virtual memory layout.

    pub fn rom_start(&self) -> u32 {
        0x2000_0000
    }

    pub fn rom_end(&self) -> u32 {
        0x3000_0000 - 1
    }

    pub fn is_rom(&self, addr: u32) -> bool {
        (self.rom_start()..=self.rom_end()).contains(&addr)
    }

    pub fn ram_start(&self) -> u32 {
        0x8000_0000
    }

    pub fn ram_end(&self) -> u32 {
        0xFFFF_FFFF
    }

    pub fn is_ram(&self, addr: u32) -> bool {
        (self.ram_start()..=self.ram_end()).contains(&addr)
    }

    // Startup.

    pub fn pc_start(&self) -> u32 {
        self.rom_start()
    }

    // Permissions.

    pub fn can_read(&self, addr: u32) -> bool {
        self.is_rom(addr) || self.is_ram(addr)
    }

    pub fn can_write(&self, addr: u32) -> bool {
        self.is_ram(addr)
    }

    pub fn can_execute(&self, addr: u32) -> bool {
        self.is_rom(addr)
    }

    // Environment calls.

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
