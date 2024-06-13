use crate::uint_new::uint::UInt;
use simple_frontend::structs::CellId;

// TODO: test
impl<const M: usize, const C: usize> UInt<M, C> {
    // witness_structure
    // [...range_values..., ...carry_witness...]

    // TODO: add documentation
    pub fn extract_carry(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS..]
    }

    // TODO: add documentation
    pub fn extract_carry_no_overflow(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS_NO_OVERFLOW..]
    }

    // TODO: add documentation
    pub fn extract_borrow(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS..]
    }

    // TODO: add documentation
    pub fn extract_range_values(witness: &[CellId]) -> &[CellId] {
        &witness[..Self::N_RANGE_CELLS]
    }

    // TODO: add documentation
    pub fn extract_range_values_no_overflow(witness: &[CellId]) -> &[CellId] {
        &witness[..Self::N_RANGE_CELLS_NO_OVERFLOW]
    }
}
