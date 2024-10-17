use crate::{
    chip_handler::{ChipHandler, util::cell_to_mixed},
    structs::ROMType,
};
use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

pub struct CalldataChip {}

impl CalldataChip {
    pub fn load<Ext: ExtensionField>(
        chip_handler: &mut ChipHandler<Ext>,
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
        chip_handler
            .rom_handler
            .read_mixed(circuit_builder, &key, &data);
    }
}
