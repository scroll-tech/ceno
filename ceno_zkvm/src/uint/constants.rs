use crate::utils::const_min;

use super::{UIntLimbs, util::max_carry_word_for_multiplication};

pub const BYTE_BIT_WIDTH: usize = 8;

use ff_ext::ExtensionField;

impl<const TOTAL_BITS: usize, const CAPACITY: usize, E: ExtensionField>
    UIntLimbs<TOTAL_BITS, CAPACITY, E>
{
    pub const TOTAL_BITS: usize = TOTAL_BITS;
    pub const CAPACITY: usize = CAPACITY;

    /// Determines the maximum number of bits that should be represented in each cell
    /// independent of the cell capacity.
    /// If total bits < cell capacity, the maximum_usable_cell_capacity
    /// is actually 'total bits'.
    /// but if total bits >= cell capacity then maximum_usable_cell_capacity = 'cell capacity'.
    pub const MAX_CELL_BIT_WIDTH: usize = const_min(TOTAL_BITS, CAPACITY);

    /// `NUM_CELLS` represent the minimum number of cells needed
    /// to hold total bits
    pub const NUM_CELLS: usize = TOTAL_BITS.div_ceil(CAPACITY);

    /// Max carry value during degree 2 limb multiplication
    pub const MAX_DEGREE_2_MUL_CARRY_VALUE: u64 =
        max_carry_word_for_multiplication(2, Self::TOTAL_BITS, Self::CAPACITY);

    /// Min bits to cover MAX_DEGREE_2_MUL_CARRY_VALUE
    pub const MAX_DEGREE_2_MUL_CARRY_BITS: usize = {
        let max_bit_of_carry = u64::BITS - Self::MAX_DEGREE_2_MUL_CARRY_VALUE.leading_zeros();
        max_bit_of_carry as usize
    };

    /// Min number of u16 limb to cover max carry value
    pub const MAX_DEGREE_2_MUL_CARRY_U16_LIMB: usize =
        Self::MAX_DEGREE_2_MUL_CARRY_BITS.div_ceil(16);
}
