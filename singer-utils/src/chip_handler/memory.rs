use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::structs::{RAMHandler, RAMType};

use super::{MemoryChipOperations, RAMOperations};

impl<Ext: SmallField> MemoryChipOperations<Ext> for RAMHandler<Ext> {
    fn mem_load(
        &mut self,
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
        self.ram_load_mixed(circuit_builder, &old_ts, &cur_ts, &key, &[byte.into()]);
    }

    fn mem_store(
        &mut self,
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
        self.ram_store_mixed(
            circuit_builder,
            &old_ts,
            &cur_ts,
            &key,
            &[old_byte.into()],
            &[cur_byte.into()],
        );
    }
}
