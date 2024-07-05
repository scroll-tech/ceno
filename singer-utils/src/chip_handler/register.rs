use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::structs::{RAMHandler, RAMType};

use super::{OAMOperations, RegisterChipOperations};

impl<Ext: ExtensionField> RegisterChipOperations<Ext> for RAMHandler<Ext> {
    fn register_read(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        register_id: &[CellId],
        timestamp: &[CellId],
        values: &[CellId],
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                RAMType::Memory as u64,
            ))],
            register_id.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();
        let timestamp = timestamp.iter().map(|&x| MixedCell::Cell(x)).collect_vec();
        let values = values.iter().map(|&x| MixedCell::Cell(x)).collect_vec();
        self.oam_load_mixed(circuit_builder, &timestamp, &key, &values);
    }

    fn register_store(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        register_id: &[CellId],
        timestamp: &[CellId],
        values: &[CellId],
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                RAMType::Memory as u64,
            ))],
            register_id.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();
        let timestamp = timestamp.iter().map(|&x| x.into()).collect_vec();
        let values = values.iter().map(|&x| x.into()).collect_vec();
        self.oam_load_mixed(circuit_builder, &timestamp, &key, &values);
    }
}
