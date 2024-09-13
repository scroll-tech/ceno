use std::fmt;

use crate::uint::UInt;

pub(crate) const PC_STEP_SIZE: usize = 4;

pub const OPCODE_OP: usize = 0x33;
pub const FUNCT3_ADD_SUB: usize = 0;
pub const FUNCT7_ADD: usize = 0;
pub const FUNCT7_SUB: usize = 0x20;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy)]
pub enum OPType {
    Op,
    Opimm,
    Jal,
    Jalr,
    Branch,
}

#[derive(Debug, Clone, Copy)]
pub enum OpcodeType {
    RType(OPType, usize, usize), // (OP, func3, func7)
    BType(OPType, usize),        // (OP, func3)
}

impl fmt::Display for OpcodeType {
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
