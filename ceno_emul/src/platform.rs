use core::fmt::{self, Formatter};
use std::{collections::BTreeSet, fmt::Display, ops::Range};

use crate::addr::{Addr, RegIdx};

/// The Platform struct holds the parameters of the VM.
/// It defines:
/// - the layout of virtual memory,
/// - special addresses, such as the initial PC,
/// - codes of environment calls.
#[derive(Clone, Debug)]
pub struct Platform {
    pub rom: Range<Addr>,
    pub prog_data: BTreeSet<Addr>,
    pub public_io: Range<Addr>,

    pub stack: Range<Addr>,
    pub heap: Range<Addr>,
    pub hints: Range<Addr>,

    /// If true, ecall instructions are no-op instead of trap. Testing only.
    pub unsafe_ecall_nop: bool,

    pub is_debug: bool,
}

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let prog_data: Option<Range<Addr>> = match (self.prog_data.first(), self.prog_data.last()) {
            (Some(first), Some(last)) => Some(*first..*last),
            _ => None,
        };
        write!(
            f,
            "Platform {{ rom: {:#x}..{:#x}, prog_data: {:#x}..{:#x}, stack: {:#x}..{:#x}, heap: {:#x}..{:#x}, \
            public_io: {:#x}..{:#x}, hints: {:#x}..{:#x}, unsafe_ecall_nop: {} }}",
            self.rom.start,
            self.rom.end,
            prog_data
                .as_ref()
                .map(|prog_data| prog_data.start)
                .unwrap_or_default(),
            prog_data
                .as_ref()
                .map(|prog_data| prog_data.end)
                .unwrap_or_default(),
            self.stack.start,
            self.stack.end,
            self.heap.start,
            self.heap.end,
            self.public_io.start,
            self.public_io.end,
            self.hints.start,
            self.hints.end,
            self.unsafe_ecall_nop
        )
    }
}

// alined with [`memory.x`]
pub const CENO_PLATFORM: Platform = Platform {
    rom: 0x2000_0000..0x2800_0000, // 128 MB
    prog_data: BTreeSet::new(),
    stack: 0xB0000000..0xC0000000, // stack grows downward
    heap: 0x8000_0000..0xFFFF_0000,
    public_io: 0x3000_0000..0x3004_0000,
    hints: 0x4000_0000..0x5000_0000, // 256 MB
    unsafe_ecall_nop: false,
    is_debug: false,
};

impl Platform {
    // Virtual memory layout.

    pub fn is_rom(&self, addr: Addr) -> bool {
        self.rom.contains(&addr)
    }

    pub fn is_prog_data(&self, addr: Addr) -> bool {
        self.prog_data.contains(&(addr & !0x3))
    }

    pub fn is_ram(&self, addr: Addr) -> bool {
        self.stack.contains(&addr) || self.heap.contains(&addr) || self.is_prog_data(addr)
    }

    pub fn is_pub_io(&self, addr: Addr) -> bool {
        self.public_io.contains(&addr)
    }

    pub fn is_hints(&self, addr: Addr) -> bool {
        self.hints.contains(&addr)
    }

    /// Virtual address of a register.
    pub const fn register_vma(index: RegIdx) -> Addr {
        // Register VMAs are aligned, cannot be confused with indices, and readable in hex.
        (index << 8) as Addr
    }

    /// Register index from a virtual address (unchecked).
    pub const fn register_index(vma: Addr) -> RegIdx {
        (vma >> 8) as RegIdx
    }

    // Startup.

    pub const fn pc_base(&self) -> Addr {
        self.rom.start
    }

    // Permissions.

    pub fn can_read(&self, addr: Addr) -> bool {
        self.can_write(addr)
    }

    pub fn can_write(&self, addr: Addr) -> bool {
        self.is_ram(addr) || self.is_pub_io(addr) || self.is_hints(addr)
    }

    // Environment calls.

    /// Register containing the ecall function code. (x5, t0)
    pub const fn reg_ecall() -> RegIdx {
        5
    }

    /// Register containing the first function argument. (x10, a0)
    pub const fn reg_arg0() -> RegIdx {
        10
    }

    /// Register containing the 2nd function argument. (x11, a1)
    pub const fn reg_arg1() -> RegIdx {
        11
    }

    /// The code of ecall HALT.
    pub const fn ecall_halt() -> u32 {
        0
    }

    /// The code of success.
    pub const fn code_success() -> u32 {
        0
    }

    /// Validate the platform configuration, range shall not overlap.
    pub fn validate(&self) -> bool {
        let mut ranges = [
            &self.rom,
            &self.stack,
            &self.heap,
            &self.public_io,
            &self.hints,
        ];
        ranges.sort_by_key(|r| r.start);
        for i in 0..ranges.len() - 1 {
            if ranges[i].end > ranges[i + 1].start {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VMState, WORD_SIZE};

    #[test]
    fn test_no_overlap() {
        let p = CENO_PLATFORM;
        // ROM and RAM do not overlap.
        assert!(!p.is_rom(p.heap.start));
        assert!(!p.is_rom(p.heap.end - WORD_SIZE as Addr));
        assert!(!p.is_ram(p.rom.start));
        assert!(!p.is_ram(p.rom.end - WORD_SIZE as Addr));
        // Registers do not overlap with ROM or RAM.
        for reg in [
            Platform::register_vma(0),
            Platform::register_vma(VMState::REG_COUNT - 1),
        ] {
            assert!(!p.is_rom(reg));
            assert!(!p.is_ram(reg));
        }
    }
}
