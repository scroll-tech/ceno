use crate::{
    chip_handler::{ram_handler::RAMHandler, util::cell_to_mixed, ChipHandler},
    structs::RAMType,
};
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};
use std::{cell::RefCell, rc::Rc};

pub struct StackChip {}

impl StackChip {
    pub fn push<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
        stack_ts: &[CellId],
        values: &[CellId],
    ) {
        let key = [
            MixedCell::Constant(Ext::BaseField::from(RAMType::Stack as u64)),
            stack_top,
        ];
        let stack_ts = cell_to_mixed(stack_ts);
        let values = cell_to_mixed(values);
        chip_handler
            .ram_handler
            .write_oam_mixed(circuit_builder, &stack_ts, &key, &values);
    }

    pub fn pop<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
        stack_ts: &[CellId],
        values: &[CellId],
    ) {
        let key = [
            MixedCell::Constant(Ext::BaseField::from(RAMType::Stack as u64)),
            stack_top,
        ];
        let stack_ts = cell_to_mixed(stack_ts);
        let values = cell_to_mixed(values);
        chip_handler
            .ram_handler
            .read_oam_mixed(circuit_builder, &stack_ts, &key, &values);
    }
}
