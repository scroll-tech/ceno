use strum_macros::EnumIter;

pub const STACK_TOP_BIT_WIDTH: usize = 10;

pub const RANGE_CHIP_BIT_WIDTH: usize = 16;
pub const VALUE_BIT_WIDTH: usize = 32;
pub const EVM_STACK_BIT_WIDTH: usize = 256;
pub const EVM_STACK_BYTE_WIDTH: usize = EVM_STACK_BIT_WIDTH / 8;

// opcode bytecode
#[derive(Debug, Clone, Copy, EnumIter)]
pub enum OpcodeType {
    UNKNOWN = 0x00,
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

    // risc-v
    RV_ADD = 0x33,
}

// l

// impl RV64Opcode {
//     // Type R
//     pub const ADD: RV64Opcode = RV64Opcode::R;
//     pub const SUB: RV64Opcode = RV64Opcode::R;
//     pub const SLL: RV64Opcode = RV64Opcode::R;
//     pub const SLT: RV64Opcode = RV64Opcode::R;
//     pub const SLTU: RV64Opcode = RV64Opcode::R;
//     pub const XOR: RV64Opcode = RV64Opcode::R;
//     pub const SRL: RV64Opcode = RV64Opcode::R;
//     pub const SRA: RV64Opcode = RV64Opcode::R;
//     pub const OR: RV64Opcode = RV64Opcode::R;
//     pub const AND: RV64Opcode = RV64Opcode::R;
//     // Type I
//     pub const ADDI: RV64Opcode = RV64Opcode::I_ARITH;
// }
