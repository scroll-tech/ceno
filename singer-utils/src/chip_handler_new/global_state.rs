use crate::chip_handler_new::oam_handler::OAMHandler;
use crate::chip_handler_new::ram_handler::RAMHandler;
use crate::structs::RAMType;
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{Cell, CellId, CircuitBuilder, MixedCell};

struct GlobalStateChip {}

// TODO: rather than giving access to the oam handler, we can allow access for the ram internal oam handler
impl GlobalStateChip {
    // TODO: rename and document
    fn state_in<Ext: ExtensionField>(
        &mut self,
        oam_handler: &mut OAMHandler<Ext>,
        circuit_builder: &mut CircuitBuilder<Ext>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: CellId,
        clk: CellId,
    ) {
        // TODO: can make a structure that does concat automatically to make things neater
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                RAMType::GlobalState as u64,
            ))],
            // TODO: implement helper method on &[CellId]
            pc.iter().map(|&x| x.into()).collect_vec(),
            stack_ts.iter().map(|&x| x.into()).collect_vec(),
            memory_ts.iter().map(|&x| x.into()).collect_vec(),
            vec![stack_top.into(), clk.into()],
        ]
        .concat();

        oam_handler.read_mixed(circuit_builder, &[], &key, &[]);
    }

    // TODO: rename and document
    fn state_out<Ext: ExtensionField>(
        &mut self,
        oam_handler: &mut OAMHandler<Ext>,
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
            pc.iter().map(|&x| x.into()).collect_vec(),
            stack_ts.iter().map(|&x| x.into()).collect_vec(),
            memory_ts.iter().map(|&x| x.into()).collect_vec(),
            vec![stack_top.into(), clk.into()],
        ]
        .concat();

        oam_handler.write_mixed(circuit_builder, &[], &key, &[]);
    }
}
