use goldilocks::SmallField;
use simple_frontend::structs::{CellId, CircuitBuilder, MixedCell};

use crate::constants::OpcodeType;

use super::{BytecodeChipOperations, ChipHandler};

impl<F: SmallField> BytecodeChipOperations<F> for ChipHandler<F> {
    fn bytecode_with_pc_opcode(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        opcode: OpcodeType,
    ) {
        let out = circuit_builder.create_ext_cell();
        let mut items = pc.iter().map(|x| MixedCell::Cell(*x)).collect::<Vec<_>>();
        items.push(MixedCell::Constant(F::BaseField::from(opcode as u64)));
        circuit_builder.rlc_mixed(&out, &items, self.challenge);
        self.records.push(out);
    }

    fn bytecode_with_pc_byte(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F>,
        pc: &[CellId],
        byte: CellId,
    ) {
        let out = circuit_builder.create_ext_cell();
        let mut items = pc.iter().map(|x| *x).collect::<Vec<_>>();
        items.push(byte);
        circuit_builder.rlc(&out, &items, self.challenge);
        self.records.push(out);
    }
}
