use goldilocks::SmallField;
use simple_frontend::structs::{CellId, CircuitBuilder};

use super::{ChipHandler, MemoryChipOperations};

impl<F: SmallField> MemoryChipOperations<F> for ChipHandler<F> {
    fn mem_load(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        offset: &[CellId],
        memory_ts: &[CellId],
        byte: CellId,
    ) {
        let out = circuit_builder.create_ext_cell();
        let mut items = offset.to_vec();
        items.extend_from_slice(memory_ts);
        items.push(byte);
        circuit_builder.rlc(&out, &items, self.challenge);
        self.records.push(out);
    }

    fn mem_store(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        offset: &[CellId],
        memory_ts: &[CellId],
        byte: CellId,
    ) {
        let out = circuit_builder.create_ext_cell();
        let mut items = offset.to_vec();
        items.extend_from_slice(memory_ts);
        items.push(byte);
        circuit_builder.rlc(&out, &items, self.challenge);
        self.records.push(out);
    }
}
