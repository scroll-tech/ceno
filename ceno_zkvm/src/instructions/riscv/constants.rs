use std::fmt;

pub(crate) const PC_STEP_SIZE: usize = 4;

#[derive(Debug, Clone, Copy)]
pub enum OPType {
    OP,
    OPIMM,
    JAL,
    JALR,
    BRANCH,
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
