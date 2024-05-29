use super::uint::UInt;

// TODO: determine constant access controls

impl<const M: usize, const C: usize> UInt<M, C> {
    // TODO: explain why this and how this
    pub(crate) const N_OPERAND_CELLS: usize = (M + C - 1) / C;
}
