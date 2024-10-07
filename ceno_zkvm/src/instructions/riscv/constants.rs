use crate::uint::UIntLimbs;
pub use ceno_emul::PC_STEP_SIZE;

pub const ECALL_HALT_OPCODE: [usize; 2] = [0x00_00, 0x00_00];
pub const EXIT_PC: usize = 0;
pub const EXIT_CODE_IDX: usize = 0;
pub const VALUE_BIT_WIDTH: usize = 16;

#[cfg(feature = "riv32")]
pub const BIT_WIDTH: usize = 32usize;
#[cfg(feature = "riv64")]
pub const BIT_WIDTH: usize = 64usize;
pub type UInt<E> = UIntLimbs<BIT_WIDTH, VALUE_BIT_WIDTH, E>;
/// use UInt<x> for x bits limb size
pub type UInt8<E> = UIntLimbs<BIT_WIDTH, 8, E>;
pub const UINT_LIMBS: usize = BIT_WIDTH.div_ceil(VALUE_BIT_WIDTH);
