use crate::uint::constants::AddSubConstants;
use crate::uint::uint::UInt;
use simple_frontend::structs::CellId;

impl<const M: usize, const C: usize> UInt<M, C> {
    // witness_structure
    // [...range_values..., ...carry_witness...]

    pub fn extract_carry(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS..]
    }

    pub fn extract_carry_no_overflow(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS..]
    }

    // TODO: why do we need this
    pub fn extract_unsafe_carry(witness: &[CellId]) -> &[CellId] {
        witness
    }

    pub fn extract_borrow(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS..]
    }

    // TODO: why do we need this
    pub fn extract_unsafe_borrow(witness: &[CellId]) -> &[CellId] {
        witness
    }

    pub fn extract_range_values(witness: &[CellId]) -> &[CellId] {
        &witness[..Self::N_RANGE_CELLS]
    }

    pub fn extract_range_values_no_overflow(witness: &[CellId]) -> &[CellId] {
        &witness[..Self::N_RANGE_CELLS]
    }
}
