use crate::{InsnKind, Instruction};

/// Convenience function to create an `Instruction` with the given fields.
///
/// Pass 0 for unused fields.
pub const fn encode_rv32(kind: InsnKind, rs1: u32, rs2: u32, rd: u32, imm: i32) -> Instruction {
    Instruction {
        kind,
        rs1: rs1 as usize,
        rs2: rs2 as usize,
        rd: rd as usize,
        imm,
        raw: 0,
    }
}

/// Convenience function to create an `Instruction` with the given fields.
///
/// Pass 0 for unused fields.
pub const fn encode_rv32u(kind: InsnKind, rs1: u32, rs2: u32, rd: u32, imm: u32) -> Instruction {
    Instruction {
        kind,
        rs1: rs1 as usize,
        rs2: rs2 as usize,
        rd: rd as usize,
        imm: imm as i32,
        raw: 0,
    }
}
