use goldilocks::SmallField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use super::{ChipHandler, GlobalStateChipOperations};

impl<F: SmallField> GlobalStateChipOperations<F> for ChipHandler<F> {
    fn state_in(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: CellId,
        clk: CellId,
    ) {
        let out = circuit_builder.create_ext_cell();
        let mut items = pc.to_vec();
        items.extend_from_slice(stack_ts);
        items.extend_from_slice(memory_ts);
        items.push(stack_top);
        items.push(clk);
        circuit_builder.rlc(&out, &items, self.challenge);
        self.records.push(out);
    }

    fn state_out(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        stack_ts: &[CellId],
        memory_ts: &[CellId],
        stack_top: MixedCell<F>,
        clk: MixedCell<F>,
    ) {
        let out = circuit_builder.create_ext_cell();
        let mut items = pc.to_vec();
        items.extend_from_slice(stack_ts);
        items.extend_from_slice(memory_ts);
        let mut items = items.into_iter().map(|x| x.into()).collect::<Vec<_>>();
        items.push(stack_top);
        items.push(clk);
        circuit_builder.rlc_mixed(&out, &items, self.challenge);
        self.records.push(out);
    }
}
