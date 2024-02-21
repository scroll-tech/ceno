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
        circuit_builder.assert_const(borrow, 1);
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
            circuit_builder.assert_const(s, 0);
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
            circuit_builder.assert_const(diff[i], 0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{ChipHandler, UInt, UIntCmp};
    use goldilocks::Goldilocks;
    use simple_frontend::structs::{ChallengeId, CircuitBuilder};

    #[test]
    fn test_lt() {
        // TODO: this test yet cannot pass due to the same reason
        // as happened in add tests
        // this test fails at singer/src/instructions/utils/uint.rs:168:49:
        // attempt to shift left with overflow
        type Uint256_63 = UInt<256, 63>;
        let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
        // create cells for operand_0, operand_1 and witness
        let _operand_0_cells = circuit_builder.create_cells(Uint256_63::N_OPRAND_CELLS);
        let _operand_1_cells = circuit_builder.create_cells(Uint256_63::N_OPRAND_CELLS);
        let _witness_cells = circuit_builder.create_cells(Uint256_63::N_OPRAND_CELLS);
        let operand_0 = Uint256_63::try_from(vec![0, 1, 2, 3, 4]);
        let operand_1 = Uint256_63::try_from(vec![5, 6, 7, 8, 9]);
        let witness: Vec<usize> = (10..35).collect();
        let mut range_chip_handler = ChipHandler::new(100 as ChallengeId);
        let result = UIntCmp::<Uint256_63>::lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &operand_0.unwrap(),
            &operand_1.unwrap(),
            &witness,
        );
        println!("{:?}", result);
    }
}
