use crate::chip_handler_new::ram_handler::RAMHandler;
use crate::structs::RAMType;
use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

struct MemoryChip {}

impl MemoryChip {
    // TODO: rename and document
    // TODO: should that really be called byte?
    fn read<Ext: ExtensionField>(
        &mut self,
        ram_handler: &mut RAMHandler<Ext>,
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
            offset.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();
        let old_ts = old_ts.iter().map(|&x| x.into()).collect_vec();
        let cur_ts = cur_ts.iter().map(|&x| x.into()).collect_vec();
        ram_handler.read_mixed(circuit_builder, &old_ts, &cur_ts, &key, &[byte.into()]);
    }

    // TODO: rename and document
    fn write<Ext: ExtensionField>(
        &mut self,
        ram_handler: &mut RAMHandler<Ext>,
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
            offset.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();
        let old_ts = old_ts.iter().map(|&x| x.into()).collect_vec();
        let cur_ts = cur_ts.iter().map(|&x| x.into()).collect_vec();
        ram_handler.write_mixed(
            circuit_builder,
            &old_ts,
            &cur_ts,
            &key,
            &[old_byte.into()],
            &[cur_byte.into()],
        );
    }
}
