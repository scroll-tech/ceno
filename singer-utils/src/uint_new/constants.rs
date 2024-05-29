use super::uint::UInt;

impl<const M: usize, const C: usize> UInt<M, C> {
    /// `N_OPERAND_CELLS` represent the minimum number of cells each of size `C` needed
    /// to hold `M` total bits
    pub(crate) const N_OPERAND_CELLS: usize = (M + C - 1) / C;
}
