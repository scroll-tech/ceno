use crate::uint::UIntLimbs;
pub use ceno_emul::PC_STEP_SIZE;

pub const VALUE_BIT_WIDTH: usize = 16;

#[cfg(feature = "riv32")]
pub type UInt<E> = UIntLimbs<32, VALUE_BIT_WIDTH, E>;
#[cfg(feature = "riv32")]
/// use UInt<x> for x bits limb size
pub type UInt8<E> = UIntLimbs<32, 8, E>;
#[cfg(feature = "riv32")]
pub const UINT_LIMBS: usize = 32 / VALUE_BIT_WIDTH;

#[cfg(feature = "riv64")]
pub type UInt<E> = UIntLimbs<64, VALUE_BIT_WIDTH, E>;
#[cfg(feature = "riv64")]
pub type UInt8<E> = UIntLimbs<64, 8, E>;
#[cfg(feature = "riv64")]
pub const UINT_LIMBS: usize = 64 / VALUE_BIT_WIDTH;
