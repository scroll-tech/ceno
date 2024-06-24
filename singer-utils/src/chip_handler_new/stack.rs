use crate::chip_handler_new::oam_handler::OAMHandler;
use crate::structs::RAMType;
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

struct StackChip {}

impl StackChip {
    // TODO: rename and document
    fn push<Ext: ExtensionField>(
        &mut self,
        oam_handler: &mut OAMHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
        stack_ts: &[CellId],
        values: &[CellId],
    ) {
        let key = [
            MixedCell::Constant(Ext::BaseField::from(RAMType::Stack as u64)),
            stack_top,
        ];
        let stack_ts = stack_ts.iter().map(|&x| MixedCell::Cell(x)).collect_vec();
        let values = values.iter().map(|&x| MixedCell::Cell(x)).collect_vec();
        oam_handler.write_mixed(circuit_builder, &stack_ts, &key, &values);
    }

    // TODO: rename and document
    fn pop<Ext: ExtensionField>(
        &mut self,
        oam_handler: &mut OAMHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        stack_top: MixedCell<Ext>,
        stack_ts: &[CellId],
        values: &[CellId],
    ) {
        let key = [
            MixedCell::Constant(Ext::BaseField::from(RAMType::Stack as u64)),
            stack_top,
        ];
        let stack_ts = stack_ts.iter().map(|&x| MixedCell::Cell(x)).collect_vec();
        let values = values.iter().map(|&x| MixedCell::Cell(x)).collect_vec();
        oam_handler.read_mixed(circuit_builder, &stack_ts, &key, &values);
    }
}
