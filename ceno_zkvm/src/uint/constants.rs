use crate::utils::const_min;

use super::{util::max_carry_word_for_multiplication, UIntLimbs};

pub const RANGE_CHIP_BIT_WIDTH: usize = 16;
pub const BYTE_BIT_WIDTH: usize = 8;

use ff_ext::ExtensionField;

impl<const M: usize, const C: usize, E: ExtensionField> UIntLimbs<M, C, E> {
    pub const M: usize = M;
    pub const C: usize = C;

    /// Determines the maximum number of bits that should be represented in each cell
    /// independent of the cell capacity `C`.
    /// If M < C i.e. total bit < cell capacity, the maximum_usable_cell_capacity
    /// is actually M.
    /// but if M >= C then maximum_usable_cell_capacity = C
    pub const MAX_CELL_BIT_WIDTH: usize = const_min(M, C);

    /// `NUM_CELLS` represent the minimum number of cells each of size `C` needed
    /// to hold `M` total bits
    pub const NUM_CELLS: usize = (M + C - 1) / C;

    /// The number of `RANGE_CHIP_BIT_WIDTH` cells needed to represent one cell of size `C`
    const N_RANGE_CELLS_PER_CELL: usize = (C + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;

    /// The number of `RANGE_CHIP_BIT_WIDTH` cells needed to represent the entire `UIntLimbs<M, C>`
    pub const N_RANGE_CELLS: usize = Self::NUM_CELLS * Self::N_RANGE_CELLS_PER_CELL;

    /// Max carry value during degree 2 limb multiplication
    pub const MAX_DEGREE_2_MUL_CARRY_VALUE: u64 =
        max_carry_word_for_multiplication(2, Self::M, Self::C);

    /// Min bits to cover MAX_DEGREE_2_MUL_CARRY_VALUE
    pub const MAX_DEGREE_2_MUL_CARRY_BITS: usize = {
        let max_bit_of_carry = u64::BITS - Self::MAX_DEGREE_2_MUL_CARRY_VALUE.leading_zeros();
        max_bit_of_carry as usize
    };

    /// Min number of u16 limb to cover max carry value
    pub const MAX_DEGREE_2_MUL_CARRY_U16_LIMB: usize =
        (Self::MAX_DEGREE_2_MUL_CARRY_BITS + 15) / 16;
}
