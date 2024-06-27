use crate::uint::constants::AddSubConstants;
use crate::uint::uint::UInt;
use simple_frontend::structs::CellId;

// TODO: split this into different impls, constrained by specific contexts
//  e.g add_sub, mul, ...
impl<const M: usize, const C: usize> UInt<M, C> {
    // witness_structure
    // [...range_values..., ...carry_witness...]

    pub fn extract_carry_add_sub(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS..]
    }

    pub fn extract_carry_no_overflow_add_sub(witness: &[CellId]) -> &[CellId] {
        &witness[AddSubConstants::<Self>::N_RANGE_CELLS_IN_CARRY_NO_OVERFLOW..]
    }

    // TODO: why do we need this
    pub fn extract_unsafe_carry_add_sub(witness: &[CellId]) -> &[CellId] {
        witness
    }

    pub fn extract_borrow_add_sub(witness: &[CellId]) -> &[CellId] {
        &witness[Self::N_RANGE_CELLS..]
    }

    // TODO: why do we need this
    pub fn extract_unsafe_borrow_add_sub(witness: &[CellId]) -> &[CellId] {
        witness
    }

    pub fn extract_range_values(witness: &[CellId]) -> &[CellId] {
        &witness[..Self::N_RANGE_CELLS]
    }

    pub fn extract_range_values_no_overflow(witness: &[CellId]) -> &[CellId] {
        &witness[..AddSubConstants::<Self>::N_RANGE_CELLS_IN_CARRY_NO_OVERFLOW]
    }
}
