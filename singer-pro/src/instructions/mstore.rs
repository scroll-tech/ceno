use ff::Field;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::Itertools;
use paste::paste;
use simple_frontend::structs::CircuitBuilder;
use std::{mem, sync::Arc};
use strum::IntoEnumIterator;

use crate::{
    chips::SingerChipBuilder,
    component::{
        AccessoryCircuit, AccessoryLayout, ChipChallenges, ChipType, FromPredInst, FromWitness,
        InstCircuit, InstLayout, ToSuccInst,
    },
    constants::EVM_STACK_BYTE_WIDTH,
    error::ZKVMError,
    utils::{
        add_assign_each_cell,
        chip_handler::{ChipHandler, MemoryChipOperations, RangeChipOperations},
        uint::{StackUInt, TSUInt, UIntAddSub, UIntCmp},
    },
    CircuitWitnessIn, SingerParams,
};

use super::{Instruction, InstructionGraph};

pub struct MstoreInstruction;

impl<F: SmallField> InstructionGraph<F> for MstoreInstruction {
    type InstType = Self;

    fn construct_circuits(
        challenges: ChipChallenges,
    ) -> Result<(InstCircuit<F>, Vec<AccessoryCircuit<F>>), ZKVMError> {
        Ok((
            Self::InstType::construct_circuit(challenges)?,
            vec![MstoreAccessory::construct_circuit(challenges)?],
        ))
    }

    fn construct_circuit_graph(
        graph_builder: &mut CircuitGraphBuilder<F>,
        chip_builder: &mut SingerChipBuilder<F>,
        inst_circuit: &InstCircuit<F>,
        acc_circuits: &[AccessoryCircuit<F>],
        preds: Vec<PredType>,
        mut sources: Vec<CircuitWitnessIn<F::BaseField>>,
        real_challenges: &[F],
        real_n_instances: usize,
        _: SingerParams,
    ) -> Result<(Vec<usize>, Vec<NodeOutputType>, Option<NodeOutputType>), ZKVMError> {
        // Add the instruction circuit to the graph.
        let node_id = graph_builder.add_node_with_witness(
            stringify!(Self::InstType),
            &inst_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[0]),
            real_n_instances,
        )?;
        let stack = inst_circuit
            .layout
            .to_succ_inst
            .stack_result_ids
            .iter()
            .map(|&wire_id| NodeOutputType::WireOut(node_id, wire_id))
            .collect_vec();

        chip_builder.construct_chip_checks(
            graph_builder,
            node_id,
            &inst_circuit.layout.to_chip_ids,
            real_challenges,
            real_n_instances,
        )?;

        // Add the memory accessory circuit to the graph.
        let preds = acc_circuits[0].layout.input(
            inst_circuit
                .layout
                .to_acc_ooo
                .map(|wire_id| NodeOutputType::WireOut(node_id, wire_id)),
            inst_circuit
                .layout
                .to_acc_dup
                .map(|wire_id| NodeOutputType::WireOut(node_id, wire_id)),
        );
        let acc_node_id = graph_builder.add_node_with_witness(
            stringify!(MstoreAccessory),
            &acc_circuits[0].circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[1]),
            real_n_instances * EVM_STACK_BYTE_WIDTH,
        )?;

        chip_builder.construct_chip_checks(
            graph_builder,
            acc_node_id,
            &acc_circuits[0].layout.to_chip_ids,
            real_challenges,
            real_n_instances * EVM_STACK_BYTE_WIDTH,
        )?;

        Ok((vec![node_id, acc_node_id], stack, None))
    }
}

register_witness!(
    MstoreInstruction,
    phase0 {
        memory_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        mem_bytes => EVM_STACK_BYTE_WIDTH
    }
);

impl<F: SmallField> Instruction<F> for MstoreInstruction {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_witness_in(TSUInt::N_OPRAND_CELLS);
        let (offset_id, offset) = circuit_builder.create_witness_in(StackUInt::N_OPRAND_CELLS);
        let (mem_value_id, mem_values) =
            circuit_builder.create_witness_in(StackUInt::N_OPRAND_CELLS);

        let mut range_chip_handler = ChipHandler::new(challenges.range());

        // Update memory timestamp.
        let memory_ts = TSUInt::try_from(memory_ts.as_slice())?;
        let next_memory_ts = range_chip_handler.add_ts_with_const(
            &mut circuit_builder,
            &memory_ts,
            1,
            &phase0[Self::phase0_memory_ts_add()],
        )?;
        // To successor instruction
        let next_memory_ts_id =
            circuit_builder.create_witness_out_from_cells(next_memory_ts.values());

        // Pop mem_bytes from stack
        let mem_bytes = &phase0[Self::phase0_mem_bytes()];
        range_chip_handler.range_check_bytes(&mut circuit_builder, mem_bytes)?;

        let mem_values = StackUInt::try_from(mem_values.as_slice())?;
        let mem_values_from_bytes =
            StackUInt::from_bytes_big_endien(&mut circuit_builder, &mem_bytes)?;
        UIntCmp::<StackUInt>::assert_eq(&mut circuit_builder, &mem_values_from_bytes, &mem_values)?;

        // To chips.
        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let mut to_chip_ids = vec![None; ChipType::iter().count()];
        to_chip_ids[ChipType::RangeChip as usize] = Some(range_chip_id);

        // To accessory circuits.
        let (to_acc_dup_id, to_acc_dup) =
            circuit_builder.create_witness_out(MstoreAccessory::pred_dup_size());
        add_assign_each_cell(
            &mut circuit_builder,
            &to_acc_dup[MstoreAccessory::pred_dup_memory_ts()],
            next_memory_ts.values(),
        );
        add_assign_each_cell(
            &mut circuit_builder,
            &to_acc_dup[MstoreAccessory::pred_dup_offset()],
            &offset,
        );

        let (to_acc_ooo_id, to_acc_ooo) = circuit_builder
            .create_witness_out(MstoreAccessory::pred_ooo_size() * EVM_STACK_BYTE_WIDTH);
        add_assign_each_cell(&mut circuit_builder, &to_acc_ooo, mem_bytes);

        circuit_builder.configure();

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstLayout {
                from_pred_inst: FromPredInst {
                    memory_ts_id,
                    stack_operand_ids: vec![offset_id, mem_value_id],
                },

                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_public_io: None,

                to_chip_ids,
                to_succ_inst: ToSuccInst {
                    next_memory_ts_id,
                    stack_result_ids: vec![],
                },
                to_bb_final: None,
                to_acc_dup: Some(to_acc_dup_id),
                to_acc_ooo: Some(to_acc_ooo_id),
            },
        })
    }
}

pub struct MstoreAccessory;

register_witness!(
    MstoreAccessory,
    pred_dup {
        memory_ts => TSUInt::N_OPRAND_CELLS,
        offset => StackUInt::N_OPRAND_CELLS
    },
    pred_ooo {
        mem_byte => 1
    },
    phase0 {
        old_memory_ts => TSUInt::N_OPRAND_CELLS,
        old_memory_ts_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        offset_add_delta => UIntAddSub::<StackUInt>::N_WITNESS_CELLS,
        prev_mem_byte => 1
    }
);

impl MstoreAccessory {
    pub fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<AccessoryCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From predesessor circuit.
        let (pred_dup_wire_id, pred_dup) = circuit_builder.create_witness_in(Self::pred_dup_size());
        let (pred_ooo_wire_id, pred_ooo) = circuit_builder.create_witness_in(Self::pred_ooo_size());

        // From witness.
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        let mut range_chip_handler = ChipHandler::new(challenges.range());
        let mut memory_load_handler = ChipHandler::new(challenges.mem());
        let mut memory_store_handler = ChipHandler::new(challenges.mem());

        // Compute offset, offset + 1, ..., offset + EVM_STACK_BYTE_WIDTH - 1.
        // Load previous memory bytes.
        let memory_ts = TSUInt::try_from(&pred_dup[Self::pred_dup_memory_ts()])?;
        let old_memory_ts = TSUInt::try_from(&phase0[Self::phase0_old_memory_ts()])?;
        let old_memory_ts_lt = &phase0[Self::phase0_old_memory_ts_lt()];
        let offset = StackUInt::try_from(&pred_dup[Self::pred_dup_offset()])?;
        let offset_add_delta = &phase0[Self::phase0_offset_add_delta()];
        let delta = circuit_builder.create_counter_in(0)[0];
        let offset_plus_delta = UIntAddSub::<StackUInt>::add_small(
            &mut circuit_builder,
            &mut range_chip_handler,
            &offset,
            delta,
            offset_add_delta,
        )?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_memory_ts,
            &memory_ts,
            old_memory_ts_lt,
        )?;

        let mem_byte = pred_ooo[Self::pred_ooo_mem_byte().start];
        let prev_mem_byte = phase0[Self::phase0_prev_mem_byte().start];
        memory_load_handler.mem_load(
            &mut circuit_builder,
            offset_plus_delta.values(),
            old_memory_ts.values(),
            prev_mem_byte,
        );
        memory_store_handler.mem_store(
            &mut circuit_builder,
            offset_plus_delta.values(),
            memory_ts.values(),
            mem_byte,
        );

        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let memory_load_id =
            memory_load_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let memory_store_id =
            memory_store_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let mut to_chip_ids = vec![None; ChipType::iter().count()];
        to_chip_ids[ChipType::RangeChip as usize] = Some(range_chip_id);
        to_chip_ids[ChipType::MemoryLoad as usize] = Some(memory_load_id);
        to_chip_ids[ChipType::MemoryStore as usize] = Some(memory_store_id);

        circuit_builder.configure();

        Ok(AccessoryCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: AccessoryLayout {
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_pred_dup: Some(pred_dup_wire_id),
                from_pred_ooo: Some(pred_ooo_wire_id),
                to_chip_ids,
            },
        })
    }
}
