use ff_ext::ExtensionField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::structs::{ROMHandler, ROMType};

use super::{CalldataChipOperations, ROMOperations};

impl<Ext: ExtensionField> CalldataChipOperations<Ext> for ROMHandler<Ext> {
    fn calldataload(
        &mut self,
        circuit_builder: &mut CircuitBuilder<Ext>,
        offset: &[CellId],
        data: &[CellId],
    ) {
        let key = [
            vec![MixedCell::Constant(Ext::BaseField::from(
                ROMType::Calldata as u64,
            ))],
            offset.iter().map(|&x| x.into()).collect_vec(),
        ]
        .concat();
        let data = data.iter().map(|&x| x.into()).collect_vec();
        self.rom_load_mixed(circuit_builder, &key, &data);
    }
}
