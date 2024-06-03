use super::uint::UInt;
use crate::uint_new::util::const_min;

impl<const M: usize, const C: usize> UInt<M, C> {
    /// `N_OPERAND_CELLS` represent the minimum number of cells each of size `C` needed
    /// to hold `M` total bits
    pub(crate) const N_OPERAND_CELLS: usize = (M + C - 1) / C;

    /// Determines the maximum number of bits that should be represented in each cell
    /// independent of the cell capacity `C`.
    /// If M < C i.e. total bit < cell capacity, the maximum_usable_cell_capacity
    /// is actually M.
    /// but if M >= C then maximum_usable_cell_capacity = C
    pub(crate) const MAX_CELL_BIT_WIDTH: usize = const_min(M, C);
}

// TODO: test generated usize constants (test once we get all constants)
