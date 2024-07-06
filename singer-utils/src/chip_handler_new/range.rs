use std::io::Read;
use crate::chip_handler_new::rom_handler::ROMHandler;
use crate::chip_handler_new::util::cell_to_mixed;
use crate::constants::STACK_TOP_BIT_WIDTH;
use crate::error::UtilError;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};
use crate::uint::UInt;

struct RangeChip {
    // TODO: we probably don't need this (can lead to consistency issues)
    chip_bit_width: usize,
}

impl RangeChip {
    // TODO: document
    pub fn new(chip_bit_width: usize) -> Self {
        Self { chip_bit_width }
    }

    // TODO: document
    pub fn small_range_check<Ext: ExtensionField>(
        &mut self,
        rom_handler: &mut ROMHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        value: MixedCell<Ext>,
        bit_width: usize,
    ) -> Result<(), UtilError> {
        if bit_width > self.chip_bit_width {
            return Err(UtilError::ChipHandlerError);
        }

        let items = [value.mul(Ext::BaseField::from(1 << (self.chip_bit_width - bit_width)))];
        rom_handler.read_mixed(circuit_builder, &[], &items);
        Ok(())
    }

    // range check helper functions

    // TODO: document
    pub fn check_stack_top<Ext: ExtensionField>(
        &mut self,
        rom_handler: &mut ROMHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
    ) -> Result<(), UtilError> {
        self.small_range_check(rom_handler, circuit_builder, stack_top, STACK_TOP_BIT_WIDTH)
    }

    // TODO: document
    pub fn range_check_bytes<Ext: ExtensionField>(
        &mut self,
        rom_handler: &mut ROMHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        bytes: &[CellId],
    ) -> Result<(), UtilError> {
        let bytes = cell_to_mixed(bytes);
        for byte in bytes {
            self.small_range_check(rom_handler, circuit_builder, byte, 8)?
        }
        Ok(())
    }

    // TODO: document
    pub fn range_check_table_item<Ext: ExtensionField>(&mut self, rom_handler: &mut ROMHandler<Ext>, circuit_builder: &mut CircuitBuilder<Ext>, item: CellId) {
        rom_handler.read(circuit_builder, &[], &[item])
    }

    // TODO: document
    pub fn range_check_uint<const M: usize, const C: usize, Ext: ExtensionField>(
        &mut self,
        rom_handler: &mut ROMHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        uint: &UInt<M, C>,
        range_value_witness: Option<&[CellId]>
    ) -> Result<UInt<M, C>, UtilError> {
        // TODO: make an explicit type for range_value_witness that explain it's structure

        // the goal of this function is to verify that the values in a uint cell are

        todo!()
    }
}
