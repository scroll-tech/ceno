use std::fmt;
use strum_macros::EnumIter;

use crate::uint::UInt;
pub use ceno_emul::PC_STEP_SIZE;

/// This struct is used to define the opcode format for RISC-V instructions,
/// containing three main components: the opcode, funct3, and funct7 fields.
/// These fields are crucial for specifying the
/// exact operation and variants in the RISC-V instruction set architecture.
#[derive(Default, Clone, Debug)]
pub struct RvOpcode {
    pub opcode: OPType,
    pub funct3: Option<u8>,
    pub funct7: Option<u8>,
}

impl From<RvOpcode> for u64 {
    fn from(opcode: RvOpcode) -> Self {
        let mut result: u64 = 0;
        result |= (opcode.opcode as u64) & 0xFF;
        result |= ((opcode.funct3.unwrap() as u64) & 0xFF) << 8;
        result |= ((opcode.funct7.unwrap() as u64) & 0xFF) << 16;
        result
    }
}

#[allow(dead_code, non_camel_case_types)]
/// List all RISC-V base instruction formats:
/// R-Type, I-Type, S-Type, B-Type, U-Type, J-Type and special type.
#[derive(Debug, Clone, Copy)]
pub enum OPType {
    UNKNOWN = 0x00,

    R = 0x33,
    I_LOAD = 0x03,
    I_ARITH = 0x13,
    S = 0x63,
    B = 0x23,
    U_LUI = 0x37,
    U_AUIPC = 0x7,
    J = 0x6F,
    JAR = 0x67,
    SYS = 0x73,
}

impl Default for OPType {
    fn default() -> Self {
        OPType::UNKNOWN
    }
}

impl From<OPType> for u8 {
    fn from(opcode: OPType) -> Self {
        opcode as u8
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, EnumIter)]
pub enum RvInstruction {
    // Type R
    ADD = 0,
    SUB,

    // Type M
    MUL,
    DIV,
    DIVU,

    // Type B
    BLT,
}

impl From<RvInstruction> for RvOpcode {
    fn from(ins: RvInstruction) -> Self {
        // Find the instruction format here:
        // https://fraserinnovations.com/risc-v/risc-v-instruction-set-explanation/
        match ins {
            // Type R
            RvInstruction::ADD => RvOpcode {
                opcode: OPType::R,
                funct3: Some(0b000 as u8),
                funct7: Some(0),
            },
            RvInstruction::SUB => RvOpcode {
                opcode: OPType::R,
                funct3: Some(0b000 as u8),
                funct7: Some(0b010_0000),
            },

            // Type M
            RvInstruction::MUL => RvOpcode {
                opcode: OPType::R,
                funct3: Some(0b000 as u8),
                funct7: Some(0b0000_0001),
            },
            RvInstruction::DIV => RvOpcode {
                opcode: OPType::R,
                funct3: Some(0b100 as u8),
                funct7: Some(0b0000_0001),
            },
            RvInstruction::DIVU => RvOpcode {
                opcode: OPType::R,
                funct3: Some(0b101 as u8),
                funct7: Some(0b0000_0001),
            },

            // Type B
            RvInstruction::BLT => RvOpcode {
                opcode: OPType::B,
                funct3: Some(0b100 as u8),
                funct7: None,
            },
        }
    }
}

impl fmt::Display for RvInstruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub const VALUE_BIT_WIDTH: usize = 16;

#[cfg(feature = "riv32")]
pub type RegUInt<E> = UInt<32, VALUE_BIT_WIDTH, E>;
#[cfg(feature = "riv32")]
/// use RegUInt<x> for x bits limb size
pub type RegUInt8<E> = UInt<32, 8, E>;

#[cfg(feature = "riv64")]
pub type RegUInt<E> = UInt<64, VALUE_BIT_WIDTH, E>;
#[cfg(feature = "riv64")]
pub type RegUInt8<E> = UInt<64, 8, E>;
