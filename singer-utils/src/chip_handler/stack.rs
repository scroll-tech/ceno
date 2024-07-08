use crate::chip_handler::oam_handler::OAMHandler;
use crate::chip_handler::util::cell_to_mixed;
use crate::structs::RAMType;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};
use std::cell::RefCell;
use std::rc::Rc;

pub struct StackChip<Ext: ExtensionField> {
    oam_handler: Rc<RefCell<OAMHandler<Ext>>>,
}

impl<Ext: ExtensionField> StackChip<Ext> {
    pub fn new(oam_handler: Rc<RefCell<OAMHandler<Ext>>>) -> Self {
        Self { oam_handler }
    }

    pub fn push(
        &self,
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
        self.oam_handler
            .borrow_mut()
            .write_mixed(circuit_builder, &stack_ts, &key, &values);
    }

    pub fn pop(
        &self,
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
        self.oam_handler
            .borrow_mut()
            .read_mixed(circuit_builder, &stack_ts, &key, &values);
    }
}
