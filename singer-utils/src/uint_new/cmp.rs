// TODO: document module
//  mostly holds comparison methods on the uint type

use crate::chip_handler::RangeChipOperations;
use crate::error::UtilError;
use crate::uint_new::uint::UInt;
use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

impl<const M: usize, const C: usize> UInt<M, C> {
    // TODO: what should this do?
    // operand_0 < operand_1
    // this isn't really checking for less than, more like creating the necessary data needed for less than check
    // TODO: change name
    pub fn lt<E: ExtensionField, H: RangeChipOperations<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_chip_handler: &mut H,
        operand_0: &UInt<M, C>,
        operand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(CellId, UInt<M, C>), UtilError> {
        // achieves less than, by subtracting and then verifying that the result is in
        // some range, so it's technically not correct, depends on the range values that are passed
        // in
        // if operand_0 is less then the borrow will be 1 for the MSB
        let borrow = Self::extract_borrow(witness);
        let range_values = Self::extract_range_values(witness);
        let computed_diff = Self::sub_unsafe(circuit_builder, operand_0, operand_1, borrow)?;

        // TODO: uncomment once you change range_check_uint
        // let diff = range_chip_handler.range_check_uint(
        //     circuit_builder,
        //     &computed_diff,
        //     Some(&range_values)
        // )?;
        //
        // if borrow.len() == Self::N_CARRY_CELLS {
        //     Ok((borrow[Self::N_CARRY_CELLS - 1], diff))
        // } else {
        //     // TODO: if we reach here then definitiely not lt
        //     Ok((circuit_builder.create_cell(), diff))
        // }
        //
        todo!()
    }

    // TODO: add documentation
    //  describe logic
    pub fn assert_lt<E: ExtensionField, H: RangeChipOperations<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_chip_handler: &mut H,
        operand_0: &UInt<M, C>,
        operand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(), UtilError> {
        let (borrow, _) = Self::lt(
            circuit_builder,
            range_chip_handler,
            operand_0,
            operand_1,
            witness,
        )?;
        circuit_builder.assert_const(borrow, 1);
        Ok(())
    }

    // TODO: add documentation
    pub fn assert_leq<E: ExtensionField, H: RangeChipOperations<E>>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_chip_handler: &mut H,
        operand_0: &UInt<M, C>,
        operand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(), UtilError> {
        let (borrow, diff) = Self::lt(
            circuit_builder,
            range_chip_handler,
            operand_0,
            operand_1,
            witness,
        )?;

        // what will be the content of borrow and diif is less than?
        // borrow will be 1 and diff will be diff
        // what will be the content if equal
        // borrow will be 0 and diff should be 0
        // how do we ensure that it's only that case that works?

        // if borrow = 0 return diff
        // if borrow = 1 return 0
        // does this hold across all values?

        let diff_values = diff.values();
        for d in diff_values.iter() {
            let s = circuit_builder.create_cell();
            // if borrow == 0 return diff else return 0
            // TODO: explain this
            circuit_builder.sel_mixed(
                s,
                (*d).into(),
                MixedCell::Constant(E::BaseField::ZERO),
                borrow,
            );
            circuit_builder.assert_const(s, 0);
        }

        Ok(())
    }

    // TODO: add documentation (shuffle)
    // TODO: document the steps
    pub fn assert_eq<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        operand_0: &UInt<M, C>,
        operand_1: &UInt<M, C>,
    ) -> Result<(), UtilError> {
        let diff = circuit_builder.create_cells(Self::N_OPERAND_CELLS);
        let operand_0_cells = operand_0.values();
        let operand_1_cells = operand_1.values();
        for i in 0..Self::N_OPERAND_CELLS {
            circuit_builder.add(diff[i], operand_0_cells[i], E::BaseField::ONE);
            circuit_builder.add(diff[i], operand_1_cells[i], -E::BaseField::ONE);
            circuit_builder.assert_const(diff[i], 0);
        }
        Ok(())
    }

    // TODO: add documentation
    pub fn assert_eq_range_values<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        operand_0: &UInt<M, C>,
        operand_1: &[CellId],
    ) -> Result<(), UtilError> {
        // TODO: really need to test this, different from reference implementation
        let range_as_uint = UInt::from_range_values(circuit_builder, operand_1)?;
        Self::assert_eq(circuit_builder, &operand_0, &range_as_uint)
    }
}
