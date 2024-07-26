use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::structs::{RAMHandler, RAMType};

use super::{RAMOperations, RegisterChipOperations};

impl<Ext: ExtensionField> RegisterChipOperations<Ext> for RAMHandler<Ext> {
    fn register_read(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        register_id: &[CellId],
        prev_timestamp: &[CellId],
        timestamp: &[CellId],
        value: &[CellId],
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                RAMType::Register as u64,
            ))],
            register_id.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();
        let prev_timestamp = prev_timestamp.iter().map(|&x| x.into()).collect_vec();
        let timestamp = timestamp.iter().map(|&x| x.into()).collect_vec();
        let value = value.iter().map(|&x| x.into()).collect_vec();
        self.ram_load_mixed(circuit_builder, &prev_timestamp, &timestamp, &key, &value);
    }

    fn register_store(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        register_id: &[CellId],
        prev_timestamp: &[CellId],
        timestamp: &[CellId],
        prev_value: &[CellId],
        value: &[CellId],
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                RAMType::Register as u64,
            ))],
            register_id.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();
        let prev_timestamp = prev_timestamp.iter().map(|&x| x.into()).collect_vec();
        let timestamp = timestamp.iter().map(|&x| x.into()).collect_vec();
        let value = value.iter().map(|&x| x.into()).collect_vec();
        let prev_value = prev_value.iter().map(|&x| x.into()).collect_vec();
        self.ram_store_mixed(
            circuit_builder,
            &prev_timestamp,
            &timestamp,
            &key,
            &prev_value,
            &value,
        );
    }
}
