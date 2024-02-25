use gkr::structs::Circuit;
use goldilocks::SmallField;
use itertools::Itertools;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{OAMOperations, ROMOperations, RangeChipOperations, StackChipOperations},
    chips::IntoEnumIterator,
    register_witness,
    structs::{ChipChallenges, InstOutChipType, RAMHandler, ROMHandler, StackUInt, TSUInt},
};
use std::sync::Arc;

use crate::{
    component::{
        AccessoryCircuit, AccessoryLayout, BBFinalCircuit, BBFinalLayout, FromBBStart,
        FromPredInst, FromWitness,
    },
    error::ZKVMError,
    utils::i64_to_base_field,
};

use super::BasicBlockInfo;

pub struct BasicBlockReturn;
/// This circuit is to load the remaining elmeents after the program execution
/// from memory, which is a data-parallel circuit load one element in each
/// sub-circuit.
pub struct BBReturnRestMemLoad;
/// This circuit is to initialize the memory with 0 at the beginning. It can
/// only touches the used addresses.
pub struct BBReturnRestMemStore;

impl BasicBlockReturn {
    pub(crate) fn construct_circuit<F: SmallField>(
        params: &BasicBlockInfo,
        challenges: ChipChallenges,
    ) -> Result<BBFinalCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let BasicBlockInfo {
            delta_stack_top: _,
            pc_start: _,
            bb_start_stack_top_offsets: _,
            bb_final_stack_top_offsets: stack_top_offsets,
        } = params.clone();
        let n_stack_items = stack_top_offsets.len();

        // From BB Start
        let (stack_ts_id, stack_ts) = circuit_builder.create_witness_in(TSUInt::N_OPRAND_CELLS);
        let (stack_top_id, stack_top) = circuit_builder.create_witness_in(1);
        let (clk_id, _) = circuit_builder.create_witness_in(1);

        let mut ram_handler = RAMHandler::new(&challenges);
        let mut rom_handler = ROMHandler::new(&challenges);

        // Check the of stack_top + offset.
        let stack_top_expr = MixedCell::Cell(stack_top[0]);
        let stack_top_l = stack_top_expr.add(i64_to_base_field::<F>(stack_top_offsets[0]));
        rom_handler.range_check_stack_top(&mut circuit_builder, stack_top_l)?;
        let stack_top_r =
            stack_top_expr.add(i64_to_base_field::<F>(stack_top_offsets[n_stack_items - 1]));
        rom_handler.range_check_stack_top(&mut circuit_builder, stack_top_r)?;

        // From predesessor instruction
        let (memory_ts_id, _) = circuit_builder.create_witness_in(TSUInt::N_OPRAND_CELLS);
        let stack_operand_ids = stack_top_offsets
            .iter()
            .map(|offset| {
                let (stack_from_insts_id, stack_from_insts) = circuit_builder.create_witness_in(1);
                ram_handler.stack_push(
                    &mut circuit_builder,
                    stack_top_expr.add(i64_to_base_field::<F>(*offset)),
                    &stack_ts,
                    &stack_from_insts,
                );
                stack_from_insts_id
            })
            .collect_vec();

        // To chips.
        let (ram_load_id, ram_store_id) = ram_handler.finalize(&mut circuit_builder);
        let rom_id = rom_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::RAMLoad as usize] = ram_load_id;
        to_chip_ids[InstOutChipType::RAMStore as usize] = ram_store_id;
        to_chip_ids[InstOutChipType::ROMInput as usize] = rom_id;

        circuit_builder.configure();

        Ok(BBFinalCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: BBFinalLayout {
                to_chip_ids,
                from_witness: FromWitness { phase_ids: vec![] },
                from_bb_start: FromBBStart {
                    stack_top_id,
                    stack_ts_id,
                    clk_id,
                },
                from_pred_inst: FromPredInst {
                    stack_operand_ids,
                    memory_ts_id,
                },
                next_pc_id: None,
            },
        })
    }
}

register_witness!(
    BBReturnRestMemLoad,
    phase0 {
        mem_byte => 1,
        old_memory_ts => TSUInt::N_OPRAND_CELLS,
        offset => StackUInt::N_OPRAND_CELLS
    }
);

impl BBReturnRestMemLoad {
    pub(crate) fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<AccessoryCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut ram_handler = RAMHandler::new(&challenges);

        // Load from memory
        let offset = &phase0[Self::phase0_offset()];
        let mem_byte = phase0[Self::phase0_mem_byte().start];
        let old_memory_ts = &phase0[Self::phase0_old_memory_ts()];
        ram_handler.oam_load(&mut circuit_builder, offset, old_memory_ts, &[mem_byte]);

        let (ram_load_id, ram_store_id) = ram_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::RAMLoad as usize] = ram_load_id;
        to_chip_ids[InstOutChipType::RAMStore as usize] = ram_store_id;
        to_chip_ids[InstOutChipType::ROMInput as usize] = None;

        circuit_builder.configure();

        Ok(AccessoryCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: AccessoryLayout {
                to_chip_ids,
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_pred_ooo: None,
                from_pred_dup: None,
            },
        })
    }
}

register_witness!(
    BBReturnRestMemStore,
    phase0 {
        mem_byte => 1,
        offset => StackUInt::N_OPRAND_CELLS
    }
);

impl BBReturnRestMemStore {
    pub(crate) fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<AccessoryCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut ram_handler = RAMHandler::new(&challenges);

        // Load from memory
        let offset = &phase0[Self::phase0_offset()];
        let mem_byte = phase0[Self::phase0_mem_byte().start];
        // memory_ts is zero.
        let memory_ts = circuit_builder.create_cells(StackUInt::N_OPRAND_CELLS);
        ram_handler.oam_store(&mut circuit_builder, offset, &memory_ts, &[mem_byte]);

        let (ram_load_id, ram_store_id) = ram_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::RAMLoad as usize] = ram_load_id;
        to_chip_ids[InstOutChipType::RAMStore as usize] = ram_store_id;
        to_chip_ids[InstOutChipType::ROMInput as usize] = None;

        Ok(AccessoryCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: AccessoryLayout {
                to_chip_ids,
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_pred_ooo: None,
                from_pred_dup: None,
            },
        })
    }
}

pub struct BBReturnRestStackPop;

register_witness!(
    BBReturnRestStackPop,
    phase0 {
        old_stack_ts => TSUInt::N_OPRAND_CELLS,
        stack_values => StackUInt::N_OPRAND_CELLS
    }
);

impl BBReturnRestStackPop {
    pub(crate) fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<AccessoryCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut ram_handler = RAMHandler::new(&challenges);

        // Pop from stack
        let stack_top = circuit_builder.create_counter_in(0);
        let stack_values = &phase0[Self::phase0_stack_values()];
        let old_stack_ts = &phase0[Self::phase0_old_stack_ts()];
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top[0].into(),
            old_stack_ts,
            stack_values,
        );

        let (ram_load_id, ram_store_id) = ram_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::RAMLoad as usize] = ram_load_id;
        to_chip_ids[InstOutChipType::RAMStore as usize] = ram_store_id;
        to_chip_ids[InstOutChipType::ROMInput as usize] = None;

        circuit_builder.configure();

        Ok(AccessoryCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: AccessoryLayout {
                to_chip_ids,
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_pred_ooo: None,
                from_pred_dup: None,
            },
        })
    }
}
