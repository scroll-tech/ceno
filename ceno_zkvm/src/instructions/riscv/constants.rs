use std::fmt;

use crate::uint::UInt;

pub(crate) const PC_STEP_SIZE: usize = 4;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy)]
pub enum OPType {
    OP,
    OPIMM,
    JAL,
    JALR,
}

#[derive(Debug, Clone, Copy)]
pub enum OpcodeType {
    RType(OPType, usize, usize), // (OP, func3, func7)
}

impl fmt::Display for OpcodeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub const VALUE_BIT_WIDTH: usize = 16;

#[cfg(feature = "riv32")]
pub type RegUInt<E> = UInt<32, VALUE_BIT_WIDTH, E>;

#[cfg(feature = "riv64")]
pub type RegUInt<E> = UInt<64, VALUE_BIT_WIDTH, E>;
