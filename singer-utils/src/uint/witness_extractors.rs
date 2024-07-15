use crate::uint::constants::AddSubConstants;
use crate::uint::uint::UInt;
use simple_frontend::structs::CellId;

// TODO: split this into different impls, constrained by specific contexts
//  e.g add_sub, mul, ...
impl<const M: usize, const C: usize> UInt<M, C> {
    // witness_structure
    // [...range_values..., ...carry_witness...]

    pub fn extract_carry_add(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS..]
    }

    pub fn extract_carry_no_overflow_add(witness: &[CellId]) -> &[CellId] {
        &witness[AddSubConstants::<Self>::N_RANGE_CELLS_NO_OVERFLOW..]
    }

    pub fn extract_unsafe_carry_add(witness: &[CellId]) -> &[CellId] {
        witness
    }

    pub fn extract_borrow_sub(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS..]
    }

    pub fn extract_unsafe_borrow_sub(witness: &[CellId]) -> &[CellId] {
        witness
    }

    pub fn extract_range_values(witness: &[CellId]) -> &[CellId] {
        &witness[..Self::N_RANGE_CELLS]
    }

    pub fn extract_range_values_no_overflow(witness: &[CellId]) -> &[CellId] {
        &witness[..AddSubConstants::<Self>::N_RANGE_CELLS_NO_OVERFLOW]
    }
}
