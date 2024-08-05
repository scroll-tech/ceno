use super::uint::UInt;
use crate::{constants::RANGE_CHIP_BIT_WIDTH, uint::util::const_min};
use std::marker::PhantomData;

impl<const M: usize, const C: usize> UInt<M, C> {
    pub const C: usize = C;
    pub const M: usize = M;
    /// Determines the maximum number of bits that should be represented in each cell
    /// independent of the cell capacity `C`.
    /// If M < C i.e. total bit < cell capacity, the maximum_usable_cell_capacity
    /// is actually M.
    /// but if M >= C then maximum_usable_cell_capacity = C
    pub const MAX_CELL_BIT_WIDTH: usize = const_min(M, C);

    /// `N_OPERAND_CELLS` represent the minimum number of cells each of size `C` needed
    /// to hold `M` total bits
    pub const N_OPERAND_CELLS: usize =
        (M + Self::MAX_CELL_BIT_WIDTH - 1) / Self::MAX_CELL_BIT_WIDTH;

    /// The number of `RANGE_CHIP_BIT_WIDTH` cells needed to represent one cell of size `C`
    pub const N_RANGE_CELLS_PER_CELL: usize =
        (Self::MAX_CELL_BIT_WIDTH + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;

    /// The number of `RANGE_CHIP_BIT_WIDTH` cells needed to represent the entire `UInt<M, C>`
    pub const N_RANGE_CELLS: usize = Self::N_OPERAND_CELLS * Self::N_RANGE_CELLS_PER_CELL;
}

/// Holds addition specific constants
pub struct AddSubConstants<UInt> {
    _marker: PhantomData<UInt>,
}

impl<const M: usize, const C: usize> AddSubConstants<UInt<M, C>> {
    /// Number of cells required to track carry information for the addition operation.
    /// operand_0 =     a   b  c
    /// operand_1 =     e   f  g
    ///                ----------
    /// result    =     h   i  j
    /// carry     =  k  l   m  -
    /// |Carry| = |Cells|
    pub const N_CARRY_CELLS: usize = UInt::<M, C>::N_OPERAND_CELLS;

    /// Number of cells required to track carry information if we assume the addition
    /// operation cannot lead to overflow.
    /// operand_0 =     a   b  c
    /// operand_1 =     e   f  g
    ///                ----------
    /// result    =     h   i  j
    /// carry     =     l   m  -
    /// |Carry| = |Cells - 1|
    const N_CARRY_CELLS_NO_OVERFLOW: usize = Self::N_CARRY_CELLS - 1;

    /// The size of the witness
    pub const N_WITNESS_CELLS: usize = UInt::<M, C>::N_RANGE_CELLS + Self::N_CARRY_CELLS;

    /// The size of the witness assuming carry has no overflow
    /// |Range_values| + |Carry - 1|
    pub const N_WITNESS_CELLS_NO_CARRY_OVERFLOW: usize =
        UInt::<M, C>::N_RANGE_CELLS + Self::N_CARRY_CELLS_NO_OVERFLOW;

    pub const N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS: usize = Self::N_CARRY_CELLS_NO_OVERFLOW;

    /// The number of `RANGE_CHIP_BIT_WIDTH` cells needed to represent the carry cells, assuming
    /// no overflow.
    // TODO: if guaranteed no overflow, then we don't need to range check the highest limb
    //  hence this can be (N_OPERANDS - 1) * N_RANGE_CELLS_PER_CELL
    //  update this once, range check logic doesn't assume all limbs
    pub const N_RANGE_CELLS_NO_OVERFLOW: usize = UInt::<M, C>::N_RANGE_CELLS;
}
