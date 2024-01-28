use ff::Field;
use gkr::structs::Circuit;
use goldilocks::SmallField;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use std::sync::Arc;
use strum::IntoEnumIterator;

use crate::{
    component::{
        BBStartCircuit, BBStartLayout, ChipChallenges, ChipType, FromWitness, ToBBFinal, ToSuccInst,
    },
    error::ZKVMError,
    utils::{
        add_assign_each_cell,
        chip_handler::{
            ChipHandler, GlobalStateChipOperations, RangeChipOperations, StackChipOperations,
        },
        i64_to_base_field,
        uint::{PCUInt, StackUInt, TSUInt, UIntCmp},
    },
};

use super::BasicBlockInfo;

pub(crate) struct BasicBlockStart;

register_witness_multi!(BasicBlockStart, phase0(n_stack_items) {
    // State in related
    pc(1) => PCUInt::N_OPRAND_CELLS,
    stack_ts(1) => TSUInt::N_OPRAND_CELLS,
    memory_ts(1) => TSUInt::N_OPRAND_CELLS,
    stack_top(1) => 1,
    clk(1) => 1,

    // Stack values
    old_stack_values(n_stack_items) => StackUInt::N_OPRAND_CELLS,
    old_stack_ts(n_stack_items) => TSUInt::N_OPRAND_CELLS,
    old_stack_ts_lt(n_stack_items) => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS
});

impl BasicBlockStart {
    pub(crate) fn construct_circuit<F: SmallField>(
        params: &BasicBlockInfo,
        challenges: ChipChallenges,
    ) -> Result<BBStartCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let stack_top_offsets = &params.bb_start_stack_top_offsets;
        let n_stack_items = stack_top_offsets.len();

        // From witness
        let (phase0_wire_id, phase0) =
            circuit_builder.create_wire_in(Self::phase0_size(n_stack_items));

        let mut global_state_in_handler = ChipHandler::new(challenges.global_state());
        let mut stack_pop_handler = ChipHandler::new(challenges.stack());
        let mut range_chip_handler = ChipHandler::new(challenges.range());

        // State update
        let pc = &phase0[Self::phase0_pc(0)];
        let stack_ts = &phase0[Self::phase0_stack_ts(0)];
        let memory_ts = &phase0[Self::phase0_memory_ts(0)];
        let stack_top = phase0[Self::phase0_stack_top(0).start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk(0).start];
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc,
            stack_ts,
            memory_ts,
            stack_top,
            clk,
        );

        // Check the of stack_top + offset.
        let stack_top_l = stack_top_expr.add(i64_to_base_field::<F>(stack_top_offsets[0]));
        range_chip_handler.range_check_stack_top(&mut circuit_builder, stack_top_l)?;
        let stack_top_r =
            stack_top_expr.add(i64_to_base_field::<F>(stack_top_offsets[n_stack_items - 1]));
        range_chip_handler.range_check_stack_top(&mut circuit_builder, stack_top_r)?;

        // pop all elements from the stack.
        let stack_ts = TSUInt::try_from(stack_ts)?;
        for (i, offset) in stack_top_offsets.iter().enumerate() {
            let old_stack_ts = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts(i)])?;
            UIntCmp::<TSUInt>::assert_lt(
                &mut circuit_builder,
                &mut range_chip_handler,
                &old_stack_ts,
                &stack_ts,
                &phase0[Self::phase0_old_stack_ts_lt(i)],
            )?;
            stack_pop_handler.stack_pop(
                &mut circuit_builder,
                stack_top_expr.add(i64_to_base_field::<F>(*offset)),
                old_stack_ts.values(),
                &phase0[Self::phase0_old_stack_values(i)],
            );
        }

        // To successor instruction
        let mut stack_result_ids = Vec::with_capacity(n_stack_items);
        for i in 0..n_stack_items {
            let (stack_operand_id, stack_operand) =
                circuit_builder.create_wire_out(StackUInt::N_OPRAND_CELLS);
            let old_stack = &phase0[Self::phase0_old_stack_values(i)];
            for j in 0..StackUInt::N_OPRAND_CELLS {
                circuit_builder.add(stack_operand[j], old_stack[j], F::BaseField::ONE);
            }
            stack_result_ids.push(stack_operand_id);
        }
        let (out_memory_ts_id, out_memory_ts) = circuit_builder.create_wire_out(memory_ts.len());
        add_assign_each_cell(&mut circuit_builder, &out_memory_ts, &memory_ts);

        // To BB final
        let (out_stack_ts_id, out_stack_ts) =
            circuit_builder.create_wire_out(TSUInt::N_OPRAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &out_stack_ts, stack_ts.values());
        let (out_stack_top_id, out_stack_top) = circuit_builder.create_wire_out(1);
        circuit_builder.add(out_stack_top[0], stack_top, F::BaseField::ONE);
        let (out_clk_id, out_clk) = circuit_builder.create_wire_out(1);
        circuit_builder.add(out_clk[0], clk, F::BaseField::ONE);

        // To chips
        let global_state_in_id = global_state_in_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let stack_pop_id =
            stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let mut to_chip_ids = vec![None; ChipType::iter().count()];
        to_chip_ids[ChipType::GlobalStateIn as usize] = Some(global_state_in_id);
        to_chip_ids[ChipType::StackPop as usize] = Some(stack_pop_id);
        to_chip_ids[ChipType::RangeChip as usize] = Some(range_chip_id);

        circuit_builder.configure();
        Ok(BBStartCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: BBStartLayout {
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                to_chip_ids,
                to_succ_inst: ToSuccInst {
                    next_memory_ts_id: out_memory_ts_id,
                    stack_result_ids,
                },
                to_bb_final: ToBBFinal {
                    stack_ts_id: out_stack_ts_id,
                    stack_top_id: out_stack_top_id,
                    clk_id: out_clk_id,
                },
            },
        })
    }
}
