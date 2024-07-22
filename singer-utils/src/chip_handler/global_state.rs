use crate::chip_handler::ram_handler::RAMHandler;
use crate::chip_handler::util::cell_to_mixed;
use crate::structs::RAMType;
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{Cell, CellId, CircuitBuilder, MixedCell};
use std::cell::RefCell;
use std::rc::Rc;

pub struct GlobalStateChip<Ext: ExtensionField> {
    ram_handler: Rc<RefCell<RAMHandler<Ext>>>,
}

impl<Ext: ExtensionField> GlobalStateChip<Ext> {
    pub fn new(ram_handler: Rc<RefCell<RAMHandler<Ext>>>) -> Self {
        Self { ram_handler }
    }

    pub fn state_in(
        &self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: CellId,
        clk: CellId,
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                RAMType::GlobalState as u64,
            ))],
            cell_to_mixed(pc),
            cell_to_mixed(stack_ts),
            cell_to_mixed(memory_ts),
            vec![stack_top.into(), clk.into()],
        ]
        .concat();

        self.ram_handler
            .borrow_mut()
            .read_oam_mixed(circuit_builder, &[], &key, &[]);
    }

    pub fn state_out(
        &self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: MixedCell<Ext>,
        clk: MixedCell<Ext>,
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                RAMType::GlobalState as u64,
            ))],
            // TODO: implement helper method on &[CellId]
            cell_to_mixed(pc),
            cell_to_mixed(stack_ts),
            cell_to_mixed(memory_ts),
            vec![stack_top.into(), clk.into()],
        ]
        .concat();

        self.ram_handler
            .borrow_mut()
            .write_oam_mixed(circuit_builder, &[], &key, &[]);
    }
}
