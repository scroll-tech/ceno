pub(crate) const STACK_CELL_BIT_WIDTH: usize = 8;
pub(crate) const EVM_STACK_BIT_WIDTH: usize = 256;

pub(crate) const RANGE_CHIP_BIT_WIDTH: usize = 8;

// opcode bytecode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpcodeType {
    ADD = 0x01,
    GT = 0x11,
    POP = 0x50,
    MSTORE = 0x52,
    JUMP = 0x56,
    JUMPI = 0x57,
    JUMPDEST = 0x5b,
    PUSH1 = 0x60,
    DUP2 = 0x81,
    DUP1 = 0x80,
    SWAP2 = 0x91,
    SWAP4 = 0x93,
}
