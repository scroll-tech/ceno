use crate::uint::UIntLimbs;
pub use ceno_emul::PC_STEP_SIZE;

pub const ECALL_HALT_OPCODE: [usize; 2] = [0x00_00, 0x00_00];
pub const EXIT_PC: usize = 0;
pub const EXIT_CODE_IDX: usize = 0;

pub const INIT_PC_IDX: usize = 2;
pub const INIT_CYCLE_IDX: usize = 3;
pub const END_PC_IDX: usize = 4;
pub const END_CYCLE_IDX: usize = 5;
pub const PUBLIC_IO_IDX: usize = 6;

pub const LIMB_BITS: usize = 16;
pub const LIMB_MASK: u32 = 0xFFFF;

#[cfg(feature = "riv32")]
pub const BIT_WIDTH: usize = 32usize;
#[cfg(feature = "riv64")]
pub const BIT_WIDTH: usize = 64usize;
pub type UInt<E> = UIntLimbs<BIT_WIDTH, LIMB_BITS, E>;
pub type UIntMul<E> = UIntLimbs<{ 2 * BIT_WIDTH }, LIMB_BITS, E>;
/// use UInt<x> for x bits limb size
pub type UInt8<E> = UIntLimbs<BIT_WIDTH, 8, E>;
pub const UINT_LIMBS: usize = BIT_WIDTH.div_ceil(LIMB_BITS);
