use crate::{
    chip_handler::{ram_handler::RAMHandler, util::cell_to_mixed},
    structs::RAMType,
};
use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};
use std::{cell::RefCell, rc::Rc};

pub struct MemoryChip<Ext: ExtensionField> {
    ram_handler: Rc<RefCell<RAMHandler<Ext>>>,
}

impl<Ext: ExtensionField> MemoryChip<Ext> {
    pub fn new(ram_handler: Rc<RefCell<RAMHandler<Ext>>>) -> Self {
        Self { ram_handler }
    }

    pub fn read(
        &self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        offset: &[CellId],
        old_ts: &[CellId],
        cur_ts: &[CellId],
        byte: CellId,
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                RAMType::Memory as u64,
            ))],
            cell_to_mixed(offset),
        ]
        .concat();
        let old_ts = cell_to_mixed(old_ts);
        let cur_ts = cell_to_mixed(cur_ts);
        self.ram_handler.borrow_mut().read_mixed(
            circuit_builder,
            &old_ts,
            &cur_ts,
            &key,
            &[byte.into()],
        );
    }

    pub fn write(
        &self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        offset: &[CellId],
        old_ts: &[CellId],
        cur_ts: &[CellId],
        old_byte: CellId,
        cur_byte: CellId,
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                RAMType::Memory as u64,
            ))],
            cell_to_mixed(offset),
        ]
        .concat();
        let old_ts = cell_to_mixed(old_ts);
        let cur_ts = cell_to_mixed(cur_ts);
        self.ram_handler.borrow_mut().write_mixed(
            circuit_builder,
            &old_ts,
            &cur_ts,
            &key,
            &[old_byte.into()],
            &[cur_byte.into()],
        );
    }
}
