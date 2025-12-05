use crate::uint::UIntLimbs;
pub use ceno_emul::PC_STEP_SIZE;

pub const ECALL_HALT_OPCODE: [usize; 2] = [0x00_00, 0x00_00];
pub const EXIT_PC: usize = 0;
pub const EXIT_CODE_IDX: usize = 0; // exit code u32 occupied 2 limb, each with 16

pub const INIT_PC_IDX: usize = EXIT_CODE_IDX + 2;
pub const INIT_CYCLE_IDX: usize = INIT_PC_IDX + 1;
pub const END_PC_IDX: usize = INIT_CYCLE_IDX + 1;
pub const END_CYCLE_IDX: usize = END_PC_IDX + 1;
pub const SHARD_ID_IDX: usize = END_CYCLE_IDX + 1;
pub const HEAP_START_ADDR_IDX: usize = SHARD_ID_IDX + 1;
pub const PUBLIC_IO_IDX: usize = HEAP_START_ADDR_IDX + 1;
pub const SHARD_RW_SUM_IDX: usize = PUBLIC_IO_IDX + 2;

pub const LIMB_BITS: usize = 16;
pub const LIMB_MASK: u32 = 0xFFFF;

pub const BIT_WIDTH: usize = 32usize;

pub const PC_BITS: usize = 30;
pub const MEM_BITS: usize = 30;

pub type UInt<E> = UIntLimbs<BIT_WIDTH, LIMB_BITS, E>;
pub type UIntMul<E> = UIntLimbs<{ 2 * BIT_WIDTH }, LIMB_BITS, E>;
/// use UInt<x> for x bits limb size
pub type UInt8<E> = UIntLimbs<BIT_WIDTH, 8, E>;
pub const UINT_LIMBS: usize = BIT_WIDTH.div_ceil(LIMB_BITS);
pub const UINT_BYTE_LIMBS: usize = BIT_WIDTH.div_ceil(8);
