use ff::Field;
use goldilocks::SmallField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::{
    error::ZKVMError,
    utils::chip_handler::{ChipHandler, RangeChipOperations},
};

use super::{UInt, UIntAddSub, UIntCmp};

impl<const M: usize, const C: usize> UIntCmp<UInt<M, C>>
where
    [(); (M + C - 1) / C]:,
{
    pub(crate) const N_NO_OVERFLOW_WITNESS_CELLS: usize =
        UIntAddSub::<UInt<M, C>>::N_NO_OVERFLOW_WITNESS_CELLS;

    pub(crate) const N_WITNESS_CELLS: usize = UIntAddSub::<UInt<M, C>>::N_WITNESS_CELLS;

    pub(crate) fn extract_range_values(witness: &[CellId]) -> &[CellId] {
        &witness[..UInt::<M, C>::N_RANGE_CHECK_CELLS]
    }

    pub(crate) fn extract_borrow(witness: &[CellId]) -> &[CellId] {
        &UIntAddSub::<UInt<M, C>>::extract_carry(witness)
    }

    pub(crate) fn extract_unsafe_borrow(witness: &[CellId]) -> &[CellId] {
        &UIntAddSub::<UInt<M, C>>::extract_unsafe_carry(witness)
    }

    /// Greater than implemented by little-endian subtraction.
    pub(crate) fn lt<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        range_chip_handler: &mut ChipHandler<F>,
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

    pub(crate) fn assert_lt<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        range_chip_handler: &mut ChipHandler<F>,
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
        circuit_builder.assert_const(borrow, F::BaseField::ONE);
        Ok(())
    }

    /// Greater or equal than implemented by little-endian subtraction.
    pub(crate) fn assert_leq<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        range_chip_handler: &mut ChipHandler<F>,
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
            circuit_builder.sel_mixed(
                s,
                (*d).into(),
                MixedCell::Constant(F::BaseField::ZERO),
                borrow,
            );
            circuit_builder.assert_const(s, F::BaseField::ZERO);
        }
        Ok(())
    }

    pub fn assert_eq<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        oprand_0: &UInt<M, C>,
        oprand_1: &UInt<M, C>,
    ) -> Result<(), ZKVMError> {
        let diff = circuit_builder.create_cells(oprand_0.values().len());
        let opr_0 = oprand_0.values();
        let opr_1 = oprand_1.values();
        for i in 0..diff.len() {
            circuit_builder.add(diff[i], opr_0[i], F::BaseField::ONE);
            circuit_builder.add(diff[i], opr_1[i], -F::BaseField::ONE);
            circuit_builder.assert_const(diff[i], F::BaseField::ZERO);
        }
        Ok(())
    }
}
