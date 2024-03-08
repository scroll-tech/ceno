use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::structs::{RAMHandler, RAMType};

use super::{OAMOperations, StackChipOperations};

impl<Ext: SmallField> StackChipOperations<Ext> for RAMHandler<Ext> {
    fn stack_push(
        &mut self,
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
        self.oam_store_mixed(circuit_builder, &stack_ts, &key, &values);
    }

    fn stack_pop(
        &mut self,
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
        self.oam_load_mixed(circuit_builder, &stack_ts, &key, &values);
    }
}
