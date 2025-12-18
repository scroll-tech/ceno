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

/// alined with [`memory.x`]
// ┌───────────────────────────── 0x4000_0000 (end of _sheap, or heap)
// │
// │   HEAP (128 MB, grows upward)
// │   0x3800_0000 .. 0x4000_0000
// │
// ├───────────────────────────── 0x3800_0000 (_sheap, align 0x800_0000)
// │   RAM (128 MB)
// │   0x3000_0000 .. 0x3800_0000
// ├───────────────────────────── 0x3000_0000 (RAM base / hints end)
// │
// │   HINTS (128 MB)
// │   0x2800_0000 .. 0x3000_0000
// │
// │───────────────────────────── 0x2800_0000 (hint base / gap end)
// │
// │   [Reserved gap: 128 MB for debug I/O]
// │   0x2000_0000 .. 0x2800_0000
// │───────────────────────────── 0x2000_0000 (gap / stack end)
// │
// │   STACK (≈128 MB, grows downward)
// │   0x1800_0000 .. 0x2000_0000
// │
// ├───────────────────────────── 0x1800_0000 (stack base / pubio end)
// │
// │   PUBLIC I/O (128 MB)
// │   0x1000_0000 .. 0x1800_0000
// │
// ├───────────────────────────── 0x1000_0000 (pubio base / rom end)
// │
// │   ROM / TEXT / RODATA (128 MB)
// │   0x0800_0000 .. 0x1000_0000
// │
// └───────────────────────────── 0x8000_0000 (rom base)
pub const CENO_PLATFORM: Platform = Platform {
    rom: 0x0800_0000..0x1000_0000,       // 128 MB
    public_io: 0x1000_0000..0x1800_0000, // 128 MB
    stack: 0x1800_0000..0x2000_4000, // stack grows downward 128MB, 0x4000 reserved for debug io.
    // we make hints start from 0x2800_0000 thus reserve a 128MB gap for debug io
    // at the end of stack
    hints: 0x2800_0000..0x3000_0000, // 128 MB
    // heap grows upward, reserved 128 MB for it
    // the beginning of heap address got bss/sbss data
    // and the real heap start from 0x3800_0000
    heap: 0x3000_0000..0x4000_0000,
    unsafe_ecall_nop: false,
    prog_data: BTreeSet::new(),
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
    use crate::{PreflightTracer, VMState, WORD_SIZE};

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
            Platform::register_vma(VMState::<PreflightTracer>::REG_COUNT - 1),
        ] {
            assert!(!p.is_rom(reg));
            assert!(!p.is_ram(reg));
        }
    }
}
