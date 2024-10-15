use crate::{
    chip_handler::{util::cell_to_mixed, ChipHandler},
    structs::RAMType,
};
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

pub struct MemoryChip {}

impl MemoryChip {
    pub fn read<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
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
        chip_handler.ram_handler.read_mixed(
            circuit_builder,
            &old_ts,
            &cur_ts,
            &key,
            &[byte.into()],
        );
    }

    pub fn write<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
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
        chip_handler.ram_handler.write_mixed(
            circuit_builder,
            &old_ts,
            &cur_ts,
            &key,
            &[old_byte.into()],
            &[cur_byte.into()],
        );
    }
}
