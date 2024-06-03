use super::uint::UInt;
use crate::uint_new::util::const_min;

impl<const M: usize, const C: usize> UInt<M, C> {
    /// `N_OPERAND_CELLS` represent the minimum number of cells each of size `C` needed
    /// to hold `M` total bits
    pub(crate) const N_OPERAND_CELLS: usize = (M + C - 1) / C;

    // TODO: consider renaming M and C to communicate what they actually mean
    pub(crate) const MAX_CELL_BIT_WIDTH: usize = const_min(M, C);
}

// TODO: test generated usize constants
