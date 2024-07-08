use crate::chip_handler::oam_handler::OAMHandler;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell, WitnessId};
use std::cell::RefCell;
use std::rc::Rc;

pub struct RAMHandler<Ext: ExtensionField> {
    oam_handler: Rc<RefCell<OAMHandler<Ext>>>,
}

impl<Ext: ExtensionField> RAMHandler<Ext> {
    pub fn new(oam_handler: Rc<RefCell<OAMHandler<Ext>>>) -> Self {
        Self { oam_handler }
    }

    pub fn read(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        value: &[CellId],
    ) {
        self.oam_handler
            .borrow_mut()
            .read(circuit_builder, old_ts, key, value);
        self.oam_handler
            .borrow_mut()
            .write(circuit_builder, cur_ts, key, value);
    }

    pub fn read_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        value: &[MixedCell<Ext>],
    ) {
        self.oam_handler
            .borrow_mut()
            .read_mixed(circuit_builder, old_ts, key, value);
        self.oam_handler
            .borrow_mut()
            .write_mixed(circuit_builder, cur_ts, key, value);
    }

    pub fn write(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[CellId],
        cur_ts: &[CellId],
        key: &[CellId],
        old_value: &[CellId],
        cur_value: &[CellId],
    ) {
        self.oam_handler
            .borrow_mut()
            .read(circuit_builder, old_ts, key, old_value);
        self.oam_handler
            .borrow_mut()
            .write(circuit_builder, cur_ts, key, cur_value);
    }

    pub fn write_mixed(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        old_ts: &[MixedCell<Ext>],
        cur_ts: &[MixedCell<Ext>],
        key: &[MixedCell<Ext>],
        old_value: &[MixedCell<Ext>],
        cur_value: &[MixedCell<Ext>],
    ) {
        self.oam_handler
            .borrow_mut()
            .read_mixed(circuit_builder, old_ts, key, old_value);
        self.oam_handler
            .borrow_mut()
            .write_mixed(circuit_builder, cur_ts, key, cur_value);
    }

    pub fn finalize(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
    ) -> (Option<(WitnessId, usize)>, Option<(WitnessId, usize)>) {
        self.oam_handler.borrow_mut().finalize(circuit_builder)
    }
}
