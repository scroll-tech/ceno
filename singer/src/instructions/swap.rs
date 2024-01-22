use ff::Field;
use gkr::structs::Circuit;
use goldilocks::SmallField;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use std::sync::Arc;

use crate::{
    constants::OpcodeType,
    error::ZKVMError,
    utils::{
        chip_handler::{
            BytecodeChipOperations, ChipHandler, GlobalStateChipOperations, RangeChipOperations,
            StackChipOperations,
        },
        uint::{PCUInt, StackUInt, TSUInt, UIntAddSub, UIntCmp},
    },
};

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};
pub struct SwapInstruction<const N: usize>;

impl<const N: usize> InstructionGraph for SwapInstruction<N> {
    type InstType = Self;
}

register_witness!(
    SwapInstruction<N>,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        stack_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        old_stack_ts_1 => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt_1 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        old_stack_ts_n_plus_1 => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt_n_plus_1 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        stack_values_1 => StackUInt::N_OPRAND_CELLS,
        stack_values_n_plus_1 => StackUInt::N_OPRAND_CELLS
    }
);

impl<const N: usize> SwapInstruction<N> {
    const OPCODE: OpcodeType = match N {
        1 => OpcodeType::SWAP1,
        2 => OpcodeType::SWAP2,
        4 => OpcodeType::SWAP4,
        _ => unimplemented!(),
    };
}

impl<const N: usize> Instruction for SwapInstruction<N> {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut global_state_in_handler = ChipHandler::new(challenges.global_state());
        let mut global_state_out_handler = ChipHandler::new(challenges.global_state());
        let mut bytecode_chip_handler = ChipHandler::new(challenges.bytecode());
        let mut stack_push_handler = ChipHandler::new(challenges.stack());
        let mut stack_pop_handler = ChipHandler::new(challenges.stack());
        let mut range_chip_handler = ChipHandler::new(challenges.range());

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = &phase0[Self::phase0_memory_ts()];
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            &memory_ts,
            stack_top,
            clk,
        );

        let next_pc = ChipHandler::add_pc_const(
            &mut circuit_builder,
            &pc,
            1,
            &phase0[Self::phase0_pc_add()],
        )?;
        let next_stack_ts = range_chip_handler.add_ts_with_const(
            &mut circuit_builder,
            &stack_ts,
            1,
            &phase0[Self::phase0_stack_ts_add()],
        )?;

        global_state_out_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            next_stack_ts.values(),
            &memory_ts,
            stack_top_expr,
            clk_expr.add(F::BaseField::ONE),
        );

        // Check the range of stack_top - (N + 1) is within [0, 1 << STACK_TOP_BIT_WIDTH).
        range_chip_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(N as u64 + 1)),
        )?;

        // Pop rlc of stack[top - (N + 1)] from stack
        let old_stack_ts_n_plus_1 = (&phase0[Self::phase0_old_stack_ts_n_plus_1()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_n_plus_1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_n_plus_1()],
        )?;
        let stack_values_n_plus_1 = &phase0[Self::phase0_stack_values_n_plus_1()];
        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(N as u64 + 1)),
            old_stack_ts_n_plus_1.values(),
            stack_values_n_plus_1,
        );

        // Pop rlc of stack[top - 1] from stack
        let old_stack_ts_1 = (&phase0[Self::phase0_old_stack_ts_1()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_1()],
        )?;
        let stack_values_1 = &phase0[Self::phase0_stack_values_1()];
        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::ONE),
            old_stack_ts_1.values(),
            stack_values_1,
        );

        // Push stack_1 to the stack at top - (N + 1)
        stack_push_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(N as u64 + 1)),
            stack_ts.values(),
            stack_values_1,
        );
        // Push stack_n_plus_1 to the stack at top - 1
        stack_push_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::ONE),
            stack_ts.values(),
            stack_values_n_plus_1,
        );

        // Bytecode check for (pc, SWAP{N}).
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );

        let global_state_in_id = global_state_in_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let global_state_out_id = global_state_out_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let bytecode_chip_id =
            bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let stack_push_id =
            stack_push_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let stack_pop_id =
            stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_id),
            Some(global_state_out_id),
            Some(bytecode_chip_id),
            Some(stack_pop_id),
            Some(stack_push_id),
            Some(range_chip_id),
            None,
            None,
            None,
        ];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: vec![phase0_wire_id],
                ..Default::default()
            },
        })
    }
}
