use crate::chip_handler_new::rom_handler::ROMHandler;
use crate::chip_handler_new::util::cell_to_mixed;
use crate::constants::{RANGE_CHIP_BIT_WIDTH, STACK_TOP_BIT_WIDTH};
use crate::error::UtilError;
use crate::uint::UInt;
use ff::Field;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};
use std::cell::RefCell;
use std::io::Read;
use std::rc::Rc;

struct RangeChip<Ext: ExtensionField> {
    rom_handler: Rc<RefCell<ROMHandler<Ext>>>,
}

impl<Ext: ExtensionField> RangeChip<Ext> {
    // TODO: document
    pub fn small_range_check(
        &mut self,
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
        self.rom_handler
            .borrow_mut()
            .read_mixed(circuit_builder, &[], &items);
        Ok(())
    }

    // range check helper functions

    // TODO: document
    pub fn range_check_stack_top(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
    ) -> Result<(), UtilError> {
        self.small_range_check(circuit_builder, stack_top, STACK_TOP_BIT_WIDTH)
    }

    // TODO: document
    pub fn range_check_bytes(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        bytes: &[CellId],
    ) -> Result<(), UtilError> {
        let bytes = cell_to_mixed(bytes);
        for byte in bytes {
            self.small_range_check(circuit_builder, byte, 8)?
        }
        Ok(())
    }

    // TODO: document
    pub fn range_check_table_item(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        item: CellId,
    ) {
        self.rom_handler
            .borrow_mut()
            .read(circuit_builder, &[], &[item])
    }

    /// Ensures that the value represented in a `UInt<M, C>` (as field elements)
    /// matches its definition.
    /// i.e. total_represented_value <= M and each value represented per cell <= max_cell_width
    pub fn range_check_uint<const M: usize, const C: usize>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        uint: &UInt<M, C>,
        range_value_witness: Option<&[CellId]>,
    ) -> Result<UInt<M, C>, UtilError> {
        // TODO: make an explicit type for range_value_witness that explain it's structure
        let uint_cell_width = UInt::<M, C>::MAX_CELL_BIT_WIDTH;

        if uint_cell_width <= RANGE_CHIP_BIT_WIDTH {
            // the range_table can range check any value up to RANGE_CHIP_BIT_WIDTH
            // since the uint_cell_width is less than or equal to RANGE_CHIP_BIT_WIDTH
            // the uint cell values can be range checked directly (i.e no need for decomposition witness)
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
                self.small_range_check(circuit_builder, (*cell).into(), range_check_width)?;
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

            // TODO: rid this part (once resolve potential logical bug in constant definition across the project)
            let n_range_cells_per_cell =
                (uint_cell_width + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;

            debug_assert!(range_values.len() % n_range_cells_per_cell == 0);

            for range_cells in range_values.chunks(n_range_cells_per_cell) {
                // the range cells are big endian relative to the uint cell they represent
                // hence the first n - 1 range cells should take full width
                for i in 0..(n_range_cells_per_cell - 1) {
                    self.small_range_check(
                        circuit_builder,
                        range_cells[i].into(),
                        RANGE_CHIP_BIT_WIDTH,
                    )?;
                }

                // the last range cell represents the least significant range cell
                // hence we truncate the max_value accordingly
                self.small_range_check(
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

    // TODO: document
    pub fn non_zero(
        &mut self,
        rom_handler: &mut ROMHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        val: CellId,
        wit: CellId,
    ) -> Result<CellId, UtilError> {
        let prod = circuit_builder.create_cell();
        circuit_builder.mul2(prod, val, wit, Ext::BaseField::ONE);
        self.small_range_check(circuit_builder, prod.into(), 1)?;

        let statement = circuit_builder.create_cell();
        // If val != 0, then prod = 1. => assert!( val (prod - 1) = 0 )
        circuit_builder.mul2(statement, val, prod, Ext::BaseField::ONE);
        circuit_builder.add(statement, val, -Ext::BaseField::ONE);
        circuit_builder.assert_const(statement, 0);
        Ok(prod)
    }
}
