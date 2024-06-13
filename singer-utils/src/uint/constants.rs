use super::uint::UInt;
use crate::constants::RANGE_CHIP_BIT_WIDTH;
use crate::uint::util::const_min;

// TODO: arrange this into sensible units
impl<const M: usize, const C: usize> UInt<M, C> {
    /// `N_OPERAND_CELLS` represent the minimum number of cells each of size `C` needed
    /// to hold `M` total bits
    pub const N_OPERAND_CELLS: usize = (M + C - 1) / C;

    // TODO: add documentation
    pub const N_CARRY_CELLS: usize = Self::N_OPERAND_CELLS;

    // TODO: add documentation
    const N_CARRY_CELLS_NO_OVERFLOW: usize = Self::N_CARRY_CELLS - 1;

    /// The number of `RANGE_CHIP_BIT_WIDTH` cells needed to represent one cell of size `C`
    const N_RANGE_CELLS_PER_CELL: usize = (C + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;

    /// The number of `RANGE_CHIP_BIT_WIDTH` cells needed to represent the entire `UInt<M, C>`
    pub const N_RANGE_CELLS: usize = Self::N_OPERAND_CELLS * Self::N_RANGE_CELLS_PER_CELL;

    // TODO: add documentation
    pub const N_RANGE_CELLS_NO_OVERFLOW: usize =
        Self::N_CARRY_CELLS_NO_OVERFLOW * Self::N_RANGE_CELLS_PER_CELL;

    /// Determines the maximum number of bits that should be represented in each cell
    /// independent of the cell capacity `C`.
    /// If M < C i.e. total bit < cell capacity, the maximum_usable_cell_capacity
    /// is actually M.
    /// but if M >= C then maximum_usable_cell_capacity = C
    pub const MAX_CELL_BIT_WIDTH: usize = const_min(M, C);

    // TODO: add documentation
    // TODO: shouldn't the range cells have no overflow also?
    pub const N_NO_OVERFLOW_WITNESS_CELLS: usize =
        Self::N_RANGE_CELLS + Self::N_CARRY_CELLS_NO_OVERFLOW;

    // TODO: add documentation
    // TODO: potential rename with all the cell thing
    pub const N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS: usize = Self::N_CARRY_CELLS_NO_OVERFLOW;

    // TODO: add documentation
    pub const N_WITNESS_CELLS: usize = Self::N_RANGE_CELLS + Self::N_CARRY_CELLS;
}

// TODO: test generated usize constants (test once we get all constants)
