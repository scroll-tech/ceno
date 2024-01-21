use frontend::structs::{CellId, CircuitBuilder, MixedCell};
use goldilocks::SmallField;

use crate::{
    error::ZKVMError,
    instructions::utils::{ChipHandler, UInt},
};

use super::{UIntAddSub, UIntCmp};

impl<const M: usize, const C: usize> UIntCmp<UInt<M, C>>
where
    [(); (M + C - 1) / C]:,
{
    pub(in crate::instructions) const N_NO_OVERFLOW_WITNESS_CELLS: usize =
        UIntAddSub::<UInt<M, C>>::N_NO_OVERFLOW_WITNESS_CELLS;

    pub(in crate::instructions) const N_WITNESS_CELLS: usize =
        UIntAddSub::<UInt<M, C>>::N_WITNESS_CELLS;

    pub(in crate::instructions) fn extract_range_values(witness: &[CellId]) -> &[CellId] {
        &witness[..UInt::<M, C>::N_RANGE_CHECK_CELLS]
    }

    pub(in crate::instructions) fn extract_borrow(witness: &[CellId]) -> &[CellId] {
        &UIntAddSub::<UInt<M, C>>::extract_carry(witness)
    }

    pub(in crate::instructions) fn extract_unsafe_borrow(witness: &[CellId]) -> &[CellId] {
        &UIntAddSub::<UInt<M, C>>::extract_unsafe_carry(witness)
    }

    /// Greater than implemented by little-endian subtraction.
    pub(in crate::instructions) fn lt<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        range_chip_handler: &mut ChipHandler,
        oprand_0: &UInt<M, C>,
        oprand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(CellId, UInt<M, C>), ZKVMError> {
        let borrow = Self::extract_borrow(witness);
        let range_values = Self::extract_range_values(witness);
        let computed_diff =
            UIntAddSub::<UInt<M, C>>::sub_unsafe(circuit_builder, oprand_0, oprand_1, borrow)?;
        let diff = range_chip_handler.range_check_uint(
            circuit_builder,
            &computed_diff,
            Some(&range_values),
        )?;
        if borrow.len() == UInt::<M, C>::N_CARRY_CELLS {
            Ok((borrow[UInt::<M, C>::N_CARRY_CELLS - 1], diff))
        } else {
            Ok((circuit_builder.create_cell(), diff))
        }
    }

    pub(in crate::instructions) fn assert_lt<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        range_chip_handler: &mut ChipHandler,
        oprand_0: &UInt<M, C>,
        oprand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(), ZKVMError> {
        let (borrow, _) = Self::lt(
            circuit_builder,
            range_chip_handler,
            oprand_0,
            oprand_1,
            witness,
        )?;
        circuit_builder.assert_const(borrow, &F::ONE);
        Ok(())
    }

    /// Greater or equal than implemented by little-endian subtraction.
    pub(in crate::instructions) fn assert_leq<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        range_chip_handler: &mut ChipHandler,
        oprand_0: &UInt<M, C>,
        oprand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(), ZKVMError> {
        let (borrow, diff) = Self::lt(
            circuit_builder,
            range_chip_handler,
            oprand_0,
            oprand_1,
            witness,
        )?;
        let diff_values = diff.values();
        for d in diff_values.iter() {
            let s = circuit_builder.create_cell();
            // assert_zero({borrow ? 0 : diff})
            circuit_builder.sel_mixed(s, (*d).into(), MixedCell::Constant(F::ZERO), borrow);
            circuit_builder.assert_const(s, &F::ZERO);
        }
        Ok(())
    }
}
