use crate::{
    chip_handler::{rom_handler::ROMHandler, util::cell_to_mixed},
    structs::ROMType,
};
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};
use std::{cell::RefCell, rc::Rc};

pub struct CalldataChip<Ext: ExtensionField> {
    rom_handler: Rc<RefCell<ROMHandler<Ext>>>,
}

impl<Ext: ExtensionField> CalldataChip<Ext> {
    pub fn new(rom_handler: Rc<RefCell<ROMHandler<Ext>>>) -> Self {
        Self { rom_handler }
    }

    pub fn load(
        &self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        offset: &[CellId],
        data: &[CellId],
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                ROMType::Calldata as u64,
            ))],
            cell_to_mixed(offset),
        ]
        .concat();
        let data = data.iter().map(|&x| x.into()).collect_vec();
        self.rom_handler
            .borrow_mut()
            .read_mixed(circuit_builder, &key, &data);
    }
}
