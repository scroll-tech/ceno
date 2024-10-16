use crate::addr::{Addr, RegIdx};

/// The Platform struct holds the parameters of the VM.
/// It defines:
/// - the layout of virtual memory,
/// - special addresses, such as the initial PC,
/// - codes of environment calls.
pub struct Platform;

pub const CENO_PLATFORM: Platform = Platform;

impl Platform {
    // Virtual memory layout.

    #[must_use]
    pub const fn rom_start(&self) -> Addr {
        0x2000_0000
    }

    #[must_use]
    pub const fn rom_end(&self) -> Addr {
        0x3000_0000 - 1
    }

    #[must_use]
    pub fn is_rom(&self, addr: Addr) -> bool {
        (self.rom_start()..=self.rom_end()).contains(&addr)
    }

    #[must_use]
    pub const fn ram_start(&self) -> Addr {
        0x8000_0000
    }

    #[must_use]
    pub const fn ram_end(&self) -> Addr {
        0xFFFF_FFFF
    }

    #[must_use]
    pub fn is_ram(&self, addr: Addr) -> bool {
        (self.ram_start()..=self.ram_end()).contains(&addr)
    }

    /// Virtual address of a register.
    #[must_use]
    pub const fn register_vma(&self, index: RegIdx) -> Addr {
        // Register VMAs are aligned, cannot be confused with indices, and readable in hex.
        (index << 8) as Addr
    }

    /// Register index from a virtual address (unchecked).
    #[must_use]
    pub const fn register_index(&self, vma: Addr) -> RegIdx {
        (vma >> 8) as RegIdx
    }

    /// Virtual address of the program counter.
    #[must_use]
    pub const fn pc_vma(&self) -> Addr {
        self.register_vma(32)
    }

    // Startup.

    #[must_use]
    pub const fn pc_start(&self) -> Addr {
        self.rom_start()
    }

    // Permissions.

    #[must_use]
    pub fn can_read(&self, addr: Addr) -> bool {
        self.is_rom(addr) || self.is_ram(addr)
    }

    #[must_use]
    pub fn can_write(&self, addr: Addr) -> bool {
        self.is_ram(addr)
    }

    #[must_use]
    pub fn can_execute(&self, addr: Addr) -> bool {
        self.is_rom(addr)
    }

    // Environment calls.

    /// Register containing the ecall function code. (x5, t0)
    #[must_use]
    pub const fn reg_ecall(&self) -> RegIdx {
        5
    }

    /// Register containing the first function argument. (x10, a0)
    #[must_use]
    pub const fn reg_arg0(&self) -> RegIdx {
        10
    }

    /// Register containing the 2nd function argument. (x11, a1)
    #[must_use]
    pub const fn reg_arg1(&self) -> RegIdx {
        11
    }

    /// The code of ecall HALT.
    #[must_use]
    pub const fn ecall_halt(&self) -> u32 {
        0
    }

    /// The code of success.
    #[must_use]
    pub const fn code_success(&self) -> u32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_overlap() {
        let p = CENO_PLATFORM;
        assert!(p.can_execute(p.pc_start()));
        // ROM and RAM do not overlap.
        assert!(!p.is_rom(p.ram_start()));
        assert!(!p.is_rom(p.ram_end()));
        assert!(!p.is_ram(p.rom_start()));
        assert!(!p.is_ram(p.rom_end()));
        // Registers do not overlap with ROM or RAM.
        for reg in [p.pc_vma(), p.register_vma(0), p.register_vma(31)] {
            assert!(!p.is_rom(reg));
            assert!(!p.is_ram(reg));
        }
    }
}
