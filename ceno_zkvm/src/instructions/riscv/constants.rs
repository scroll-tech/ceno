use crate::uint::UInt;
pub use ceno_emul::PC_STEP_SIZE;

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
