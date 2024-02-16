pub(crate) const STACK_TOP_BIT_WIDTH: usize = 10;

pub(crate) const RANGE_CHIP_BIT_WIDTH: usize = 16;
pub(crate) const VALUE_BIT_WIDTH: usize = 32;
pub(crate) const EVM_STACK_BIT_WIDTH: usize = 256;
pub(crate) const EVM_STACK_BYTE_WIDTH: usize = EVM_STACK_BIT_WIDTH / 8;

// opcode bytecode
pub enum OpcodeType {
    ADD = 0x01,
    GT = 0x11,
    CALLDATALOAD = 0x35,
    POP = 0x50,
    MSTORE = 0x52,
    JUMP = 0x56,
    JUMPI = 0x57,
    JUMPDEST = 0x5b,
    PUSH0 = 0x5F,
    PUSH1 = 0x60,
    DUP1 = 0x80,
    DUP2 = 0x81,
    SWAP1 = 0x90,
    SWAP2 = 0x91,
    SWAP4 = 0x93,
    RETURN = 0xf3,
}
