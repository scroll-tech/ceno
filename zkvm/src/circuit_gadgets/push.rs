use std::collections::HashMap;

use frontend::structs::{CircuitBuilder, ConstantType};
use goldilocks::SmallField;

use crate::constants::{OpcodeType, EVM_STACK_BIT_WIDTH, STACK_CELL_BIT_WIDTH};

use super::{OpcodeCircuitBuilder, OpcodeLayoutIn, OpcodeLayoutOut};

impl<F: SmallField> OpcodeCircuitBuilder<F> {
    pub fn push_basic(challenge: usize) -> Self {
        let mut circuit_builder = CircuitBuilder::new();

        // State
        // TODO: pc is u64.
        let (pc_idx, pc) = circuit_builder.create_wire_in(1);
        let (stack_ts_idx, stack_ts) = circuit_builder.create_wire_in(1);
        let (memory_ts_idx, memory_ts) = circuit_builder.create_wire_in(1);
        let (stack_top_idx, stack_top) = circuit_builder.create_wire_in(1);
        let (next_pc_idx, next_pc) = circuit_builder.create_wire_out(1);
        let (next_stack_ts_idx, next_stack_ts) = circuit_builder.create_wire_out(1);
        let (next_memory_ts_idx, next_memory_ts) = circuit_builder.create_wire_out(1);
        let (next_stack_top_idx, next_stack_top) = circuit_builder.create_wire_out(1);

        // Execution
        let (stack_push_idx, stack_push) =
            circuit_builder.create_wire_out(EVM_STACK_BIT_WIDTH / STACK_CELL_BIT_WIDTH);
        let (wit_idx, wit) = circuit_builder.create_wire_in(1);

        // Chips
        let (bytecode_chip_idx, bytecode_chip) = circuit_builder.create_wire_out(1);
        let (range_chip_idx, range_chip) = circuit_builder.create_wire_out(1);

        // Constraints
        circuit_builder.add(next_pc[0], pc[0], ConstantType::Field(F::ONE));
        circuit_builder.add_const(next_pc[0], ConstantType::Field(F::ONE));

        circuit_builder.add(next_memory_ts[0], memory_ts[0], ConstantType::Field(F::ONE));

        circuit_builder.add(next_stack_ts[0], stack_ts[0], ConstantType::Field(F::ONE));
        circuit_builder.add(
            next_stack_top[0],
            stack_top[0],
            ConstantType::Field(-F::ONE),
        );
        circuit_builder.add(range_chip[0], stack_top[0], ConstantType::Field(F::ONE));

        // Let the pushed value be one of the witness that looked up from bytecode table.
        circuit_builder.add(stack_push[0], wit[0], ConstantType::Field(F::ONE));
        circuit_builder.add(bytecode_chip[0], wit[0], ConstantType::Challenge(challenge));
        circuit_builder.add_const(
            bytecode_chip[0],
            ConstantType::Field(F::from(OpcodeType::PUSH1 as u64)),
        );
        circuit_builder.configure();

        let layout_in: HashMap<OpcodeLayoutIn, usize> = vec![
            (OpcodeLayoutIn::PC, pc_idx),
            (OpcodeLayoutIn::StackTS, stack_ts_idx),
            (OpcodeLayoutIn::MemoryTS, memory_ts_idx),
            (OpcodeLayoutIn::StackTop, stack_top_idx),
            (OpcodeLayoutIn::Witness, wit_idx),
        ]
        .into_iter()
        .collect();
        let layout_out: HashMap<OpcodeLayoutOut, usize> = vec![
            (OpcodeLayoutOut::NextPC, next_pc_idx),
            (OpcodeLayoutOut::NextStackTS, next_stack_ts_idx),
            (OpcodeLayoutOut::NextMemoryTS, next_memory_ts_idx),
            (OpcodeLayoutOut::NextStackTop, next_stack_top_idx),
            (OpcodeLayoutOut::StackPush, stack_push_idx),
            (OpcodeLayoutOut::BytecodeChip, bytecode_chip_idx),
            (OpcodeLayoutOut::RangeChip, range_chip_idx),
        ]
        .into_iter()
        .collect();
        OpcodeCircuitBuilder {
            circuit_builder,
            layout_in,
            layout_out,
        }
    }

    pub fn push_pro(challenge: usize) -> Self {
        todo!()
    }
}
