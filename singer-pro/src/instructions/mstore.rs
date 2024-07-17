use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use itertools::Itertools;
use paste::paste;
use simple_frontend::structs::CircuitBuilder;
use singer_utils::{
    chip_handler::{MemoryChipOperations, ROMOperations, RangeChipOperations},
    chips::{IntoEnumIterator, SingerChipBuilder},
    constants::{OpcodeType, EVM_STACK_BYTE_WIDTH},
    register_witness,
    structs::{ChipChallenges, InstOutChipType, RAMHandler, ROMHandler, StackUInt, TSUInt},
    uint::constants::AddSubConstants,
};
use std::{collections::BTreeMap, mem, sync::Arc};

use crate::{
    component::{
        AccessoryCircuit, AccessoryLayout, FromPredInst, FromWitness, InstCircuit, InstLayout,
        ToSuccInst,
    },
    error::ZKVMError,
    utils::add_assign_each_cell,
    CircuitWitnessIn, SingerParams,
};

use super::{Instruction, InstructionGraph};

pub struct MstoreInstruction;

impl<E: ExtensionField> InstructionGraph<E> for MstoreInstruction {
    type InstType = Self;

    fn construct_circuits(
        challenges: ChipChallenges,
    ) -> Result<(InstCircuit<E>, Vec<AccessoryCircuit<E>>), ZKVMError> {
        Ok((
            Self::InstType::construct_circuit(challenges)?,
            vec![MstoreAccessory::construct_circuit(challenges)?],
        ))
    }

    fn construct_graph_and_witness(
        graph_builder: &mut CircuitGraphBuilder<E>,
        chip_builder: &mut SingerChipBuilder<E>,
        inst_circuit: &InstCircuit<E>,
        acc_circuits: &[AccessoryCircuit<E>],
        preds: Vec<PredType>,
        mut sources: Vec<CircuitWitnessIn<E::BaseField>>,
        real_challenges: &[E],
        real_n_instances: usize,
        _: &SingerParams,
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

        chip_builder.construct_chip_check_graph_and_witness(
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

        chip_builder.construct_chip_check_graph_and_witness(
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
        memory_ts_add => AddSubConstants::<TSUInt>::N_WITNESS_CELLS_NO_CARRY_OVERFLOW,
        mem_bytes => EVM_STACK_BYTE_WIDTH
    }
);

impl<E: ExtensionField> Instruction<E> for MstoreInstruction {
    const OPCODE: OpcodeType = OpcodeType::MSTORE;
    const NAME: &'static str = "MSTORE";
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::<E>::new();
        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_witness_in(TSUInt::N_OPERAND_CELLS);
        let (offset_id, offset) = circuit_builder.create_witness_in(StackUInt::N_OPERAND_CELLS);
        let (mem_value_id, mem_values) =
            circuit_builder.create_witness_in(StackUInt::N_OPERAND_CELLS);

        let mut rom_handler = ROMHandler::new(&challenges);

        // Update memory timestamp.
        let memory_ts = TSUInt::try_from(memory_ts.as_slice())?;
        let next_memory_ts = rom_handler.add_ts_with_const(
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
        rom_handler.range_check_bytes(&mut circuit_builder, mem_bytes)?;

        let mem_values = StackUInt::try_from(mem_values.as_slice())?;
        let mem_values_from_bytes =
            StackUInt::from_bytes_big_endian(&mut circuit_builder, &mem_bytes)?;
        StackUInt::assert_eq(&mut circuit_builder, &mem_values_from_bytes, &mem_values)?;

        // To chips.
        let rom_id = rom_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::ROMInput as usize] = rom_id;

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
        memory_ts => TSUInt::N_OPERAND_CELLS,
        offset => StackUInt::N_OPERAND_CELLS
    },
    pred_ooo {
        mem_byte => 1
    },
    phase0 {
        old_memory_ts => TSUInt::N_OPERAND_CELLS,
        old_memory_ts_lt => AddSubConstants::<TSUInt>::N_WITNESS_CELLS,

        offset_add_delta => AddSubConstants::<StackUInt>::N_WITNESS_CELLS,
        prev_mem_byte => 1
    }
);

impl MstoreAccessory {
    pub fn construct_circuit<E: ExtensionField>(
        challenges: ChipChallenges,
    ) -> Result<AccessoryCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From predesessor circuit.
        let (pred_dup_wire_id, pred_dup) = circuit_builder.create_witness_in(Self::pred_dup_size());
        let (pred_ooo_wire_id, pred_ooo) = circuit_builder.create_witness_in(Self::pred_ooo_size());

        // From witness.
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        let mut ram_handler = RAMHandler::new(&challenges);
        let mut rom_handler = ROMHandler::new(&challenges);

        // Compute offset, offset + 1, ..., offset + EVM_STACK_BYTE_WIDTH - 1.
        // Load previous memory bytes.
        let memory_ts = TSUInt::try_from(&pred_dup[Self::pred_dup_memory_ts()])?;
        let old_memory_ts = TSUInt::try_from(&phase0[Self::phase0_old_memory_ts()])?;
        let old_memory_ts_lt = &phase0[Self::phase0_old_memory_ts_lt()];
        let offset = StackUInt::try_from(&pred_dup[Self::pred_dup_offset()])?;
        let offset_add_delta = &phase0[Self::phase0_offset_add_delta()];
        let delta = circuit_builder.create_counter_in(0)[0];
        let offset_plus_delta = StackUInt::add_cell(
            &mut circuit_builder,
            &mut rom_handler,
            &offset,
            delta,
            offset_add_delta,
        )?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_memory_ts,
            &memory_ts,
            old_memory_ts_lt,
        )?;

        let mem_byte = pred_ooo[Self::pred_ooo_mem_byte().start];
        let prev_mem_byte = phase0[Self::phase0_prev_mem_byte().start];
        ram_handler.mem_store(
            &mut circuit_builder,
            offset_plus_delta.values(),
            old_memory_ts.values(),
            memory_ts.values(),
            prev_mem_byte,
            mem_byte,
        );

        let rom_id = rom_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::ROMInput as usize] = rom_id;

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
