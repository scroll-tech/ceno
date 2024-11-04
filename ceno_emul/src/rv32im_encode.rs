use crate::{InsnKind, rv32im::InsnFormat};

const MASK_4_BITS: u32 = 0xF;
const MASK_5_BITS: u32 = 0x1F;
const MASK_6_BITS: u32 = 0x3F;
const MASK_7_BITS: u32 = 0x7F;
const MASK_8_BITS: u32 = 0xFF;
const MASK_10_BITS: u32 = 0x3FF;
const MASK_12_BITS: u32 = 0xFFF;

/// Generate bit encoding of a RISC-V instruction.
///
/// Values `rs1`, `rs2` and `rd1` are 5-bit register indices, and `imm` is of
/// bit length depending on the requirements of the instruction format type.
///
/// Fields not required by the instruction's format type are ignored, so one can
/// safely pass an arbitrary value for these, say 0.
pub const fn encode_rv32(kind: InsnKind, rs1: u32, rs2: u32, rd: u32, imm: u32) -> u32 {
    match kind.codes().format {
        InsnFormat::R => encode_r(kind, rs1, rs2, rd),
        InsnFormat::I => encode_i(kind, rs1, rd, imm),
        InsnFormat::S => encode_s(kind, rs1, rs2, imm),
        InsnFormat::B => encode_b(kind, rs1, rs2, imm),
        InsnFormat::U => encode_u(kind, rd, imm),
        InsnFormat::J => encode_j(kind, rd, imm),
    }
}

// R-Type
//        25    20    15       12   7       0
// +------+-----+-----+--------+----+-------+
// funct7 | rs2 | rs1 | funct3 | rd | opcode
const fn encode_r(kind: InsnKind, rs1: u32, rs2: u32, rd: u32) -> u32 {
    let rs2 = rs2 & MASK_5_BITS; // 5-bits mask
    let rs1 = rs1 & MASK_5_BITS;
    let rd = rd & MASK_5_BITS;
    let func7 = kind.codes().func7;
    let func3 = kind.codes().func3;
    let opcode = kind.codes().opcode;
    func7 << 25 | rs2 << 20 | rs1 << 15 | func3 << 12 | rd << 7 | opcode
}

// I-Type
//           20    15       12   7       0
// +---------+-----+--------+----+-------+
// imm[0:11] | rs1 | funct3 | rd | opcode
const fn encode_i(kind: InsnKind, rs1: u32, rd: u32, imm: u32) -> u32 {
    let rs1 = rs1 & MASK_5_BITS;
    let rd = rd & MASK_5_BITS;
    let func3 = kind.codes().func3;
    let opcode = kind.codes().opcode;
    let imm = imm & MASK_12_BITS;
    imm << 20 | rs1 << 15 | func3 << 12 | rd << 7 | opcode
}

// S-Type
//           25    20    15       12         7       0
// +---------+-----+-----+--------+----------+-------+
// imm[5:11] | rs2 | rs1 | funct3 | imm[0:4] | opcode
const fn encode_s(kind: InsnKind, rs1: u32, rs2: u32, imm: u32) -> u32 {
    let rs2 = rs2 & MASK_5_BITS;
    let rs1 = rs1 & MASK_5_BITS;
    let func3 = kind.codes().func3;
    let opcode = kind.codes().opcode;
    let imm_lo = imm & MASK_5_BITS;
    let imm_hi = (imm >> 5) & MASK_7_BITS; // 7-bits mask
    imm_hi << 25 | rs2 << 20 | rs1 << 15 | func3 << 12 | imm_lo << 7 | opcode
}

// B-Type
//         31          25    20    15       12         8         7       0
// +-------+-----------+-----+-----+--------+----------+---------+-------+
// imm[12] | imm[5:10] | rs2 | rs1 | funct3 | imm[1:4] | imm[11] | opcode
const fn encode_b(kind: InsnKind, rs1: u32, rs2: u32, imm: u32) -> u32 {
    let rs2 = rs2 & MASK_5_BITS;
    let rs1 = rs1 & MASK_5_BITS;
    let func3 = kind.codes().func3;
    let opcode = kind.codes().opcode;
    let imm_1_4 = (imm >> 1) & MASK_4_BITS; // skip imm[0]
    let imm_5_10 = (imm >> 5) & MASK_6_BITS;
    ((imm >> 12) & 1) << 31
        | imm_5_10 << 25
        | rs2 << 20
        | rs1 << 15
        | func3 << 12
        | imm_1_4 << 8
        | ((imm >> 11) & 1) << 7
        | opcode
}

// J-Type
//         31          21        20           12   7       0
// +-------+-----------+---------+------------+----+-------+
// imm[20] | imm[1:10] | imm[11] | imm[12:19] | rd | opcode
const fn encode_j(kind: InsnKind, rd: u32, imm: u32) -> u32 {
    let rd = rd & MASK_5_BITS;
    let opcode = kind.codes().opcode;
    let imm_1_10 = (imm >> 1) & MASK_10_BITS; // skip imm[0]
    let imm_12_19 = (imm >> 12) & MASK_8_BITS;
    ((imm >> 20) & 1) << 31
        | imm_1_10 << 21
        | ((imm >> 11) & 1) << 20
        | imm_12_19 << 12
        | rd << 7
        | opcode
}

// U-Type
//            12   7        0
// +----------+----+--------+
// imm[12:31] | rd | opcode
const fn encode_u(kind: InsnKind, rd: u32, imm: u32) -> u32 {
    (imm >> 12) << 12 | (rd & MASK_5_BITS) << 7 | kind.codes().opcode
}
