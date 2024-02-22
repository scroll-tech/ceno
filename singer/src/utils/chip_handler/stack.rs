use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use super::{ChipHandler, StackChipOperations};

impl<F: SmallField> StackChipOperations<F> for ChipHandler<F> {
    fn stack_push(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
        stack_ts: &[CellId],
        values: &[CellId],
    ) {
        let out = circuit_builder.create_ext_cell();
        let mut items = vec![stack_top];
        items.extend(stack_ts.iter().map(|x| MixedCell::Cell(*x)).collect_vec());
        items.extend(values.iter().map(|x| MixedCell::Cell(*x)).collect_vec());
        circuit_builder.rlc_mixed(&out, &items, self.challenge);
        self.records.push(out);
    }

    fn stack_pop(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        stack_top: MixedCell<F>,
        stack_ts: &[CellId],
        values: &[CellId],
    ) {
        let out = circuit_builder.create_ext_cell();
        let mut items = vec![stack_top];
        items.extend(stack_ts.iter().map(|x| MixedCell::Cell(*x)).collect_vec());
        items.extend(values.iter().map(|x| MixedCell::Cell(*x)).collect_vec());
        circuit_builder.rlc_mixed(&out, &items, self.challenge);
        self.records.push(out);
    }
}
