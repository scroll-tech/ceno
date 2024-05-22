use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::{chip_handler::RangeChipOperations, error::UtilError, structs::UInt};

use super::{UIntAddSub, UIntCmp};

impl<const M: usize, const C: usize> UIntCmp<UInt<M, C>> {
    pub const N_NO_OVERFLOW_WITNESS_CELLS: usize =
        UIntAddSub::<UInt<M, C>>::N_NO_OVERFLOW_WITNESS_CELLS;

    pub const N_WITNESS_CELLS: usize = UIntAddSub::<UInt<M, C>>::N_WITNESS_CELLS;

    pub fn extract_range_values(witness: &[CellId]) -> &[CellId] {
        &witness[..UInt::<M, C>::N_RANGE_CHECK_CELLS]
    }

    pub fn extract_borrow(witness: &[CellId]) -> &[CellId] {
        &UIntAddSub::<UInt<M, C>>::extract_carry(witness)
    }

    pub fn extract_unsafe_borrow(witness: &[CellId]) -> &[CellId] {
        &UIntAddSub::<UInt<M, C>>::extract_unsafe_carry(witness)
    }

    /// Greater than implemented by little-endian subtraction.
    pub fn lt<Ext: ExtensionField, H: RangeChipOperations<Ext>>(
        circuit_builder: &mut CircuitBuilder<Ext>,
        range_chip_handler: &mut H,
        oprand_0: &UInt<M, C>,
        oprand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(CellId, UInt<M, C>), UtilError> {
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

    pub fn assert_lt<Ext: ExtensionField, H: RangeChipOperations<Ext>>(
        circuit_builder: &mut CircuitBuilder<Ext>,
        range_chip_handler: &mut H,
        oprand_0: &UInt<M, C>,
        oprand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(), UtilError> {
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
    pub fn assert_leq<Ext: ExtensionField, H: RangeChipOperations<Ext>>(
        circuit_builder: &mut CircuitBuilder<Ext>,
        range_chip_handler: &mut H,
        oprand_0: &UInt<M, C>,
        oprand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(), UtilError> {
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
                MixedCell::Constant(Ext::BaseField::ZERO),
                borrow,
            );
            circuit_builder.assert_const(s, 0);
        }
        Ok(())
    }

    pub fn assert_eq<Ext: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<Ext>,
        oprand_0: &UInt<M, C>,
        oprand_1: &UInt<M, C>,
    ) -> Result<(), UtilError> {
        let diff = circuit_builder.create_cells(oprand_0.values().len());
        let opr_0 = oprand_0.values();
        let opr_1 = oprand_1.values();
        for i in 0..diff.len() {
            circuit_builder.add(diff[i], opr_0[i], Ext::BaseField::ONE);
            circuit_builder.add(diff[i], opr_1[i], -Ext::BaseField::ONE);
            circuit_builder.assert_const(diff[i], 0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::structs::{ChipChallenges, ROMHandler};

    use super::{UInt, UIntCmp};
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use simple_frontend::structs::CircuitBuilder;

    use gkr::structs::{Circuit, CircuitWitness};

    #[test]
    fn test_lt() {
        type Uint256_8 = UInt<256, 8>;
        assert_eq!(Uint256_8::N_OPRAND_CELLS, 32);
        // build the circuit for lt
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();
        let (operand_0_wire_in_id, operand_0_wire_in_cells) =
            circuit_builder.create_witness_in(Uint256_8::N_OPRAND_CELLS);
        let (operand_1_wire_in_id, operand_1_wire_in_cells) =
            circuit_builder.create_witness_in(Uint256_8::N_OPRAND_CELLS);
        let (witness_wire_in_id, witness_wire_in_cells) = circuit_builder
            .create_witness_in(Uint256_8::N_RANGE_CHECK_CELLS + Uint256_8::N_CARRY_CELLS);
        let operand_0 = Uint256_8::try_from(operand_0_wire_in_cells);
        let operand_1 = Uint256_8::try_from(operand_1_wire_in_cells);
        let mut range_chip_handler = ROMHandler::<GoldilocksExt2>::new(&ChipChallenges::default());
        let result = UIntCmp::<Uint256_8>::lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &operand_0.unwrap(),
            &operand_1.unwrap(),
            &witness_wire_in_cells,
        );
        assert_eq!(
            result.unwrap().0,
            2 * Uint256_8::N_OPRAND_CELLS
                + Uint256_8::N_RANGE_CHECK_CELLS
                + Uint256_8::N_CARRY_CELLS
                - 1
        );
        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);
        // fill in witnesses
        let n_witness_in = circuit.n_witness_in;
        let mut wires_in = vec![vec![]; n_witness_in];
        wires_in[operand_0_wire_in_id as usize] =
            vec![Goldilocks::from(1u64), Goldilocks::from(1u64)];
        wires_in[operand_0_wire_in_id as usize]
            .extend(vec![Goldilocks::from(0u64); Uint256_8::N_OPRAND_CELLS - 2]);
        wires_in[operand_1_wire_in_id as usize] =
            vec![Goldilocks::from(255u64), Goldilocks::from(254u64)];
        wires_in[operand_1_wire_in_id as usize]
            .extend(vec![Goldilocks::from(0u64); Uint256_8::N_OPRAND_CELLS - 2]);
        wires_in[witness_wire_in_id as usize] =
            vec![Goldilocks::from(2u64), Goldilocks::from(2u64)];
        wires_in[witness_wire_in_id as usize].extend(vec![
            Goldilocks::from(255u64);
            Uint256_8::N_RANGE_CHECK_CELLS - 2
        ]);
        wires_in[witness_wire_in_id as usize]
            .extend(vec![Goldilocks::from(1u64); Uint256_8::N_CARRY_CELLS]);
        let circuit_witness = {
            let challenges = vec![GoldilocksExt2::from(2), GoldilocksExt2::from(2)];
            let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
            circuit_witness.add_instance(&circuit, wires_in);
            circuit_witness
        };
        //println!("{:?}", circuit_witness);
        circuit_witness.check_correctness(&circuit);
    }
}
