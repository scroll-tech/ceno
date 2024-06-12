use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::structs::{RAMHandler, RAMType};

use super::{GlobalStateChipOperations, OAMOperations};

impl<Ext: ExtensionField> GlobalStateChipOperations<Ext> for RAMHandler<Ext> {
    fn state_in(
        &mut self,
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
            pc.iter().map(|&x| x.into()).collect::<Vec<_>>(),
            stack_ts.iter().map(|&x| x.into()).collect::<Vec<_>>(),
            memory_ts.iter().map(|&x| x.into()).collect::<Vec<_>>(),
            vec![stack_top.into(), clk.into()],
        ]
        .concat();
        self.oam_load_mixed(circuit_builder, &[], &key, &[]);
    }

    fn state_out(
        &mut self,
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
            pc.iter().map(|&x| x.into()).collect::<Vec<_>>(),
            stack_ts.iter().map(|&x| x.into()).collect::<Vec<_>>(),
            memory_ts.iter().map(|&x| x.into()).collect::<Vec<_>>(),
            vec![stack_top.into(), clk.into()],
        ]
        .concat();
        self.oam_store_mixed(circuit_builder, &[], &key, &[]);
    }
}
