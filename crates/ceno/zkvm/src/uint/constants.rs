use crate::utils::const_min;

use super::{UIntLimbs, util::max_carry_word_for_multiplication};

use ff_ext::ExtensionField;

impl<const TOTAL_BITS: usize, const CAPACITY: usize, E: ExtensionField>
    UIntLimbs<TOTAL_BITS, CAPACITY, E>
{
    pub const TOTAL_BITS: usize = TOTAL_BITS;
    pub const LIMB_BITS: usize = CAPACITY;

    /// Determines the maximum number of bits that should be represented in each limb
    /// independent of the limb capacity.
    /// If total bits < limb capacity, the maximum_usable_limb_capacity
    /// is actually 'total bits'.
    /// but if total bits >= limb capacity then maximum_usable_limb_capacity = 'limb capacity'.
    pub const MAX_LIMB_BIT_WIDTH: usize = const_min(TOTAL_BITS, CAPACITY);

    /// `NUM_LIMBS` represent the minimum number of limbs needed
    /// to hold total bits
    pub const NUM_LIMBS: usize = TOTAL_BITS.div_ceil(CAPACITY);

    /// Max carry value during degree 2 limb multiplication
    pub const MAX_DEGREE_2_MUL_CARRY_VALUE: u64 =
        max_carry_word_for_multiplication(2, Self::TOTAL_BITS, Self::LIMB_BITS);

    /// Min bits to cover MAX_DEGREE_2_MUL_CARRY_VALUE
    pub const MAX_DEGREE_2_MUL_CARRY_BITS: usize = {
        let max_bit_of_carry = u64::BITS - Self::MAX_DEGREE_2_MUL_CARRY_VALUE.leading_zeros();
        max_bit_of_carry as usize
    };

    /// Min number of u16 limb to cover max carry value
    pub const MAX_DEGREE_2_MUL_CARRY_U16_LIMB: usize =
        Self::MAX_DEGREE_2_MUL_CARRY_BITS.div_ceil(16);
}
