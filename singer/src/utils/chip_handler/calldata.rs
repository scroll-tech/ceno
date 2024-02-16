use goldilocks::SmallField;
use simple_frontend::structs::{CellId, CircuitBuilder};

use super::{CalldataChip, ChipHandler};

impl<F: SmallField> CalldataChip<F> for ChipHandler<F> {
    fn calldataload(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        offset: &[CellId],
        data: &[CellId],
    ) {
        let out = circuit_builder.create_ext_cell();
        let mut items = offset.to_vec();
        items.extend_from_slice(data);
        circuit_builder.rlc(&out, &items, self.challenge);
        self.records.push(out);
    }
}
