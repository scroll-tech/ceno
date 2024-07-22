use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use itertools::Itertools;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::chip_handler::bytecode::BytecodeChip;
use singer_utils::chip_handler::global_state::GlobalStateChip;
use singer_utils::chip_handler::ram_handler::RAMHandler;
use singer_utils::chip_handler::range::RangeChip;
use singer_utils::chip_handler::rom_handler::ROMHandler;
use singer_utils::chip_handler::stack::StackChip;
use singer_utils::uint::constants::AddSubConstants;
use singer_utils::{
    chips::IntoEnumIterator,
    register_witness,
    structs::{ChipChallenges, InstOutChipType, PCUInt, StackUInt, TSUInt},
};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use crate::{
    component::{BBFinalCircuit, BBFinalLayout, FromBBStart, FromPredInst, FromWitness},
    error::ZKVMError,
    utils::i64_to_base_field,
};

use super::BasicBlockInfo;

pub struct BasicBlockFinal;

register_witness!(BasicBlockFinal, phase0 {
    // State in related
    stack_ts_add => AddSubConstants::<TSUInt>::N_WITNESS_CELLS_NO_CARRY_OVERFLOW
});

impl BasicBlockFinal {
    pub(crate) fn construct_circuit<E: ExtensionField>(
        params: &BasicBlockInfo,
        challenges: ChipChallenges,
    ) -> Result<BBFinalCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let BasicBlockInfo {
            delta_stack_top,
            pc_start: _,
            bb_start_stack_top_offsets: _,
            bb_final_stack_top_offsets: stack_top_offsets,
        } = params.clone();
        let n_stack_items = stack_top_offsets.len();

        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        // From BB start
        let (stack_ts_id, stack_ts) = circuit_builder.create_witness_in(TSUInt::N_OPERAND_CELLS);
        let (stack_top_id, stack_top) = circuit_builder.create_witness_in(1);
        let (clk_id, clk) = circuit_builder.create_witness_in(1);

        // From inst pc.
        let (next_pc_id, next_pc) = circuit_builder.create_witness_in(PCUInt::N_OPERAND_CELLS);

        let mut rom_handler = Rc::new(RefCell::new(ROMHandler::new(challenges.clone())));
        let mut ram_handler = Rc::new(RefCell::new(RAMHandler::new(challenges.clone())));

        // instantiate chips
        let global_state_chip = GlobalStateChip::new(ram_handler.clone());
        let mut range_chip = RangeChip::new(rom_handler.clone());
        let stack_chip = StackChip::new(ram_handler.clone());

        let stack_ts = TSUInt::try_from(stack_ts)?;
        let stack_ts_add_witness = &phase0[Self::phase0_stack_ts_add()];
        let next_stack_ts = range_chip.add_ts_with_const(
            &mut circuit_builder,
            &stack_ts,
            1,
            stack_ts_add_witness,
        )?;

        let (memory_ts_id, memory_ts) = circuit_builder.create_witness_in(TSUInt::N_OPERAND_CELLS);
        let stack_top_expr = MixedCell::Cell(stack_top[0]);
        let clk_expr = MixedCell::Cell(clk[0]);
        global_state_chip.state_out(
            &mut circuit_builder,
            &next_pc,
            next_stack_ts.values(),
            &memory_ts,
            stack_top_expr.add(i64_to_base_field::<E>(delta_stack_top)),
            clk_expr.add(E::BaseField::ONE),
        );

        // Check the of stack_top + offset.
        let stack_top_l = stack_top_expr.add(i64_to_base_field::<E>(stack_top_offsets[0]));
        range_chip.range_check_stack_top(&mut circuit_builder, stack_top_l)?;
        let stack_top_r =
            stack_top_expr.add(i64_to_base_field::<E>(stack_top_offsets[n_stack_items - 1]));
        range_chip.range_check_stack_top(&mut circuit_builder, stack_top_r)?;

        // From predesessor instruction
        let stack_operand_ids = stack_top_offsets
            .iter()
            .map(|offset| {
                let (stack_from_insts_id, stack_from_insts) =
                    circuit_builder.create_witness_in(StackUInt::N_OPERAND_CELLS);
                stack_chip.push(
                    &mut circuit_builder,
                    stack_top_expr.add(i64_to_base_field::<E>(*offset)),
                    stack_ts.values(),
                    &stack_from_insts,
                );
                stack_from_insts_id
            })
            .collect_vec();

        // To chips
        let (ram_load_id, ram_store_id) = ram_handler.borrow_mut().finalize(&mut circuit_builder);
        let rom_id = rom_handler.borrow_mut().finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::RAMLoad as usize] = ram_load_id;
        to_chip_ids[InstOutChipType::RAMStore as usize] = ram_store_id;
        to_chip_ids[InstOutChipType::ROMInput as usize] = rom_id;

        circuit_builder.configure();

        // TODO other wire in ids.
        Ok(BBFinalCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: BBFinalLayout {
                to_chip_ids,
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_bb_start: FromBBStart {
                    stack_top_id,
                    stack_ts_id,
                    clk_id,
                },
                from_pred_inst: FromPredInst {
                    memory_ts_id,
                    stack_operand_ids,
                },
                next_pc_id: Some(next_pc_id),
            },
        })
    }
}
