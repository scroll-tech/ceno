use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        global_state::GlobalStateChip, ram_handler::RAMHandler, range::RangeChip,
        rom_handler::ROMHandler, stack::StackChip, ChipHandler,
    },
    chips::IntoEnumIterator,
    register_multi_witness,
    structs::{ChipChallenges, InstOutChipType, PCUInt, StackUInt, TSUInt},
    uint::constants::AddSubConstants,
};
use std::{cell::RefCell, rc::Rc, sync::Arc};

use crate::{
    component::{BBStartCircuit, BBStartLayout, FromWitness, ToBBFinal, ToSuccInst},
    error::ZKVMError,
    utils::{add_assign_each_cell, i64_to_base_field},
};

use super::BasicBlockInfo;

pub(crate) struct BasicBlockStart;

register_multi_witness!(BasicBlockStart, phase0(n_stack_items) {
    // State in related
    pc => PCUInt::N_OPERAND_CELLS,
    stack_ts => TSUInt::N_OPERAND_CELLS,
    memory_ts => TSUInt::N_OPERAND_CELLS,
    stack_top => 1,
    clk => 1,

    // Stack values
    old_stack_values(n_stack_items) => StackUInt::N_OPERAND_CELLS,
    old_stack_ts(n_stack_items) => TSUInt::N_OPERAND_CELLS,
    old_stack_ts_lt(n_stack_items) => AddSubConstants::<TSUInt>::N_WITNESS_CELLS_NO_CARRY_OVERFLOW
});

impl BasicBlockStart {
    pub(crate) fn construct_circuit<E: ExtensionField>(
        params: &BasicBlockInfo,
        challenges: ChipChallenges,
    ) -> Result<BBStartCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let stack_top_offsets = &params.bb_start_stack_top_offsets;
        let n_stack_items = stack_top_offsets.len();

        // From witness
        let (phase0_wire_id, phase0) =
            circuit_builder.create_witness_in(Self::phase0_size(n_stack_items));

        let mut chip_handler = ChipHandler::new(challenges.clone());

        // State update
        let pc = &phase0[Self::phase0_pc(n_stack_items)];
        let stack_ts = &phase0[Self::phase0_stack_ts(n_stack_items)];
        let memory_ts = &phase0[Self::phase0_memory_ts(n_stack_items)];
        let stack_top = phase0[Self::phase0_stack_top(n_stack_items).start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk(n_stack_items).start];
        GlobalStateChip::state_in(
            &mut chip_handler,
            &mut circuit_builder,
            pc,
            stack_ts,
            memory_ts,
            stack_top,
            clk,
        );

        // Check the of stack_top + offset.
        let stack_top_l = stack_top_expr.add(i64_to_base_field::<E>(stack_top_offsets[0]));
        RangeChip::range_check_stack_top(&mut chip_handler, &mut circuit_builder, stack_top_l)?;
        let stack_top_r =
            stack_top_expr.add(i64_to_base_field::<E>(stack_top_offsets[n_stack_items - 1]));
        RangeChip::range_check_stack_top(&mut chip_handler, &mut circuit_builder, stack_top_r)?;

        // pop all elements from the stack.
        let stack_ts = TSUInt::try_from(stack_ts)?;
        for (i, offset) in stack_top_offsets.iter().enumerate() {
            let old_stack_ts =
                TSUInt::try_from(&phase0[Self::phase0_old_stack_ts(i, n_stack_items)])?;
            TSUInt::assert_lt(
                &mut circuit_builder,
                &mut chip_handler,
                &old_stack_ts,
                &stack_ts,
                &phase0[Self::phase0_old_stack_ts_lt(i, n_stack_items)],
            )?;
            StackChip::pop(
                &mut chip_handler,
                &mut circuit_builder,
                stack_top_expr.add(i64_to_base_field::<E>(*offset)),
                old_stack_ts.values(),
                &phase0[Self::phase0_old_stack_values(i, n_stack_items)],
            );
        }

        // To successor instruction
        let mut stack_result_ids = Vec::with_capacity(n_stack_items);
        for i in 0..n_stack_items {
            let (stack_operand_id, stack_operand) =
                circuit_builder.create_witness_out(StackUInt::N_OPERAND_CELLS);
            let old_stack = &phase0[Self::phase0_old_stack_values(i, n_stack_items)];
            for j in 0..StackUInt::N_OPERAND_CELLS {
                circuit_builder.add(stack_operand[j], old_stack[j], E::BaseField::ONE);
            }
            stack_result_ids.push(stack_operand_id);
        }
        let (out_memory_ts_id, out_memory_ts) = circuit_builder.create_witness_out(memory_ts.len());
        add_assign_each_cell(&mut circuit_builder, &out_memory_ts, &memory_ts);

        // To BB final
        let (out_stack_ts_id, out_stack_ts) =
            circuit_builder.create_witness_out(TSUInt::N_OPERAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &out_stack_ts, stack_ts.values());
        let (out_stack_top_id, out_stack_top) = circuit_builder.create_witness_out(1);
        circuit_builder.add(out_stack_top[0], stack_top, E::BaseField::ONE);
        let (out_clk_id, out_clk) = circuit_builder.create_witness_out(1);
        circuit_builder.add(out_clk[0], clk, E::BaseField::ONE);

        // To chips
        let (ram_load_id, ram_store_id, rom_id) = chip_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::RAMLoad as usize] = ram_load_id;
        to_chip_ids[InstOutChipType::RAMStore as usize] = ram_store_id;
        to_chip_ids[InstOutChipType::ROMInput as usize] = rom_id;

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
