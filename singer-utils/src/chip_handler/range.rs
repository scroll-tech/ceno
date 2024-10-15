use crate::{
    chip_handler::{util::cell_to_mixed, ChipHandler},
    constants::{RANGE_CHIP_BIT_WIDTH, STACK_TOP_BIT_WIDTH},
    error::UtilError,
    structs::{PCUInt, TSUInt},
    uint::UInt,
};
use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

pub struct RangeChip {}

impl RangeChip {
    pub fn small_range_check<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        value: MixedCell<Ext>,
        bit_width: usize,
    ) -> Result<(), UtilError> {
        if bit_width > RANGE_CHIP_BIT_WIDTH {
            return Err(UtilError::ChipHandlerError);
        }

        let items = [value.mul(Ext::BaseField::from(
            1 << (RANGE_CHIP_BIT_WIDTH - bit_width),
        ))];

        chip_handler
            .rom_handler
            .read_mixed(circuit_builder, &[], &items);

        Ok(())
    }

    pub fn range_check_stack_top<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
    ) -> Result<(), UtilError> {
        Self::small_range_check(
            chip_handler,
            circuit_builder,
            stack_top,
            STACK_TOP_BIT_WIDTH,
        )
    }

    pub fn range_check_bytes<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        bytes: &[CellId],
    ) -> Result<(), UtilError> {
        let bytes = cell_to_mixed(bytes);
        for byte in bytes {
            Self::small_range_check(chip_handler, circuit_builder, byte, 8)?
        }
        Ok(())
    }

    pub fn range_check_table_item<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        item: CellId,
    ) {
        chip_handler.rom_handler.read(circuit_builder, &[], &[item])
    }

    /// Ensures that the value represented in a `UInt<M, C>` (as field elements)
    /// matches its definition.
    /// i.e. total_represented_value <= M and each value represented per cell <= max_cell_width
    pub fn range_check_uint<const M: usize, const C: usize, Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        uint: &UInt<M, C>,
        range_value_witness: Option<&[CellId]>,
    ) -> Result<UInt<M, C>, UtilError> {
        let uint_cell_width = UInt::<M, C>::MAX_CELL_BIT_WIDTH;

        if uint_cell_width <= RANGE_CHIP_BIT_WIDTH {
            // the range_table can range check any value up to RANGE_CHIP_BIT_WIDTH
            // since the uint_cell_width is less than or equal to RANGE_CHIP_BIT_WIDTH
            // the uint cell values can be range checked directly (i.e. no need for decomposition witness)
            for (index, cell) in uint.values.iter().enumerate() {
                // compute the maximum_bit_width for each cell (will be used to perform range check)
                let range_check_width = if index == 0 {
                    // index == 0 represents the least significant cell (cells are represented in little endian).
                    // if n represents the total number of cells, n - 1 cells take full width
                    // maximum_value for this cell = total_bits - (n - 1) * full_cell_width
                    M - ((UInt::<M, C>::N_OPERAND_CELLS - 1) * uint_cell_width)
                } else {
                    // the maximum value for every cell other than the least significant cell is
                    // equal to the maximum cell width
                    uint_cell_width
                };

                // perform range check on cell
                Self::small_range_check(
                    chip_handler,
                    circuit_builder,
                    (*cell).into(),
                    range_check_width,
                )?;
            }
            return Ok(uint.clone());
        }

        // max_cell_bit_width is greater than the range_chip_bit_width
        // in-order to avoid decomposition within the circuit, we take the range values as witness
        if let Some(range_values) = range_value_witness {
            // first we ensure the range_value is exactly equal to the witness
            let range_value_as_uint =
                UInt::<M, C>::from_range_values(circuit_builder, range_values)?;
            UInt::<M, C>::assert_eq(circuit_builder, uint, &range_value_as_uint)?;

            let n_range_cells_per_cell = UInt::<M, C>::N_RANGE_CELLS_PER_CELL;

            debug_assert!(range_values.len() % n_range_cells_per_cell == 0);

            for range_cells in range_values.chunks(n_range_cells_per_cell) {
                // the range cells are big endian relative to the uint cell they represent
                // hence the first n - 1 range cells should take full width
                for range_cell in &range_cells[..(n_range_cells_per_cell - 1)] {
                    Self::small_range_check(
                        chip_handler,
                        circuit_builder,
                        (*range_cell).into(),
                        RANGE_CHIP_BIT_WIDTH,
                    )?;
                }

                // the last range cell represents the least significant range cell
                // hence we truncate the max_value accordingly
                Self::small_range_check(
                    chip_handler,
                    circuit_builder,
                    range_cells[n_range_cells_per_cell - 1].into(),
                    uint_cell_width - ((n_range_cells_per_cell - 1) * RANGE_CHIP_BIT_WIDTH),
                )?;
            }

            Ok(range_value_as_uint)
        } else {
            Err(UtilError::ChipHandlerError)
        }
    }

    pub fn non_zero<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        val: CellId,
        wit: CellId,
    ) -> Result<CellId, UtilError> {
        let prod = circuit_builder.create_cell();
        circuit_builder.mul2(prod, val, wit, Ext::BaseField::ONE);
        Self::small_range_check(chip_handler, circuit_builder, prod.into(), 1)?;

        let statement = circuit_builder.create_cell();
        // If val != 0, then prod = 1. => assert!( val (prod - 1) = 0 )
        circuit_builder.mul2(statement, val, prod, Ext::BaseField::ONE);
        circuit_builder.add(statement, val, -Ext::BaseField::ONE);
        circuit_builder.assert_const(statement, 0);
        Ok(prod)
    }

    pub fn add_pc_const<Ext: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &PCUInt,
        constant: i64,
        witness: &[CellId],
    ) -> Result<PCUInt, UtilError> {
        let carry = PCUInt::extract_unsafe_carry_add(witness);
        PCUInt::add_const_unsafe(
            circuit_builder,
            pc,
            i64_to_base_field::<Ext>(constant),
            carry,
        )
    }

    pub fn add_ts_with_const<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        ts: &TSUInt,
        constant: i64,
        witness: &[CellId],
    ) -> Result<TSUInt, UtilError> {
        TSUInt::add_const(
            circuit_builder,
            chip_handler,
            ts,
            i64_to_base_field::<Ext>(constant),
            witness,
        )
    }
}

fn i64_to_base_field<E: ExtensionField>(x: i64) -> E::BaseField {
    if x >= 0 {
        E::BaseField::from(x as u64)
    } else {
        -E::BaseField::from((-x) as u64)
    }
}
