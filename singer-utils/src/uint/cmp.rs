use crate::{
    chip_handler::{ChipHandler, range::RangeChip},
    error::UtilError,
    uint::{constants::AddSubConstants, uint::UInt},
};
use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

impl<const M: usize, const C: usize> UInt<M, C> {
    /// Generates the required information for asserting lt and leq
    pub fn lt<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        chip_handler: &mut ChipHandler<E>,
        operand_0: &UInt<M, C>,
        operand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(CellId, UInt<M, C>), UtilError> {
        let borrow = Self::extract_borrow_sub(witness);
        let range_values = Self::extract_range_values(witness);
        let computed_diff = Self::sub_unsafe(circuit_builder, operand_0, operand_1, borrow)?;

        let diff = RangeChip::range_check_uint(
            chip_handler,
            circuit_builder,
            &computed_diff,
            Some(range_values),
        )?;

        // if operand_0 < operand_1, the last borrow should equal 1
        if borrow.len() == AddSubConstants::<Self>::N_CARRY_CELLS {
            Ok((borrow[AddSubConstants::<Self>::N_CARRY_CELLS - 1], diff))
        } else {
            Ok((circuit_builder.create_cell(), diff))
        }
    }

    /// Asserts that operand_0 < operand_1
    pub fn assert_lt<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        chip_handler: &mut ChipHandler<E>,
        operand_0: &UInt<M, C>,
        operand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(), UtilError> {
        let (borrow, _) = Self::lt(circuit_builder, chip_handler, operand_0, operand_1, witness)?;
        circuit_builder.assert_const(borrow, 1);
        Ok(())
    }

    /// Asserts that operand_0 <= operand_1
    pub fn assert_leq<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        chip_handler: &mut ChipHandler<E>,
        operand_0: &UInt<M, C>,
        operand_1: &UInt<M, C>,
        witness: &[CellId],
    ) -> Result<(), UtilError> {
        let (borrow, diff) =
            Self::lt(circuit_builder, chip_handler, operand_0, operand_1, witness)?;

        // we have two scenarios
        // 1. eq
        //    in this case, borrow = 0 and diff = [0, ..., 0]
        // 2. lt
        //    in this case, borrow = 1 and diff = [..field_elements..]
        // we check for both cases with the following
        // if borrow == 0 return diff else return 0
        // then assert that the returned item = 0

        let diff_values = diff.values();
        for d in diff_values.iter() {
            let s = circuit_builder.create_cell();
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

    /// Asserts that two `UInt<M, C>` instances represent equal value
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

    /// Asserts that a `UInt<M, C>` instance and a set of range cells represent equal value
    pub fn assert_eq_range_values<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        operand_0: &UInt<M, C>,
        operand_1: &[CellId],
    ) -> Result<(), UtilError> {
        let range_as_uint = UInt::from_range_values(circuit_builder, operand_1)?;
        Self::assert_eq(circuit_builder, operand_0, &range_as_uint)
    }
}
