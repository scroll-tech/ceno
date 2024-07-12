use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use paste::paste;
use simple_frontend::structs::CircuitBuilder;
use singer_utils::uint::constants::AddSubConstants;
use singer_utils::{
    chip_handler::{OAMOperations, ROMOperations},
    chips::{IntoEnumIterator, SingerChipBuilder},
    constants::OpcodeType,
    register_witness,
    structs::{ChipChallenges, InstOutChipType, RAMHandler, ROMHandler, StackUInt, TSUInt},
};
use std::{mem, sync::Arc};

use crate::{
    component::{
        AccessoryCircuit, FromPredInst, FromPublicIO, FromWitness, InstCircuit, InstLayout,
        ToSuccInst,
    },
    error::ZKVMError,
    utils::add_assign_each_cell,
    CircuitWitnessIn, SingerParams,
};

use super::{Instruction, InstructionGraph};
/// This circuit is to load public output from memory, which is a data-parallel
/// circuit load one element in each sub-circuit.
pub struct ReturnInstruction;

impl<E: ExtensionField> InstructionGraph<E> for ReturnInstruction {
    type InstType = Self;

    fn construct_graph_and_witness(
        graph_builder: &mut CircuitGraphBuilder<E>,
        chip_builder: &mut SingerChipBuilder<E>,
        inst_circuit: &InstCircuit<E>,
        _: &[AccessoryCircuit<E>],
        preds: Vec<PredType>,
        mut sources: Vec<CircuitWitnessIn<E::BaseField>>,
        real_challenges: &[E],
        _: usize,
        params: &SingerParams,
    ) -> Result<(Vec<usize>, Vec<NodeOutputType>, Option<NodeOutputType>), ZKVMError> {
        let public_output_size =
            preds[inst_circuit.layout.from_pred_inst.stack_operand_ids[1] as usize].clone();

        // Add the instruction circuit to the graph.
        let node_id = graph_builder.add_node_with_witness(
            <ReturnInstruction as Instruction<E>>::NAME,
            &inst_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[0]),
            1,
        )?;

        chip_builder.construct_chip_check_graph_and_witness(
            graph_builder,
            node_id,
            &inst_circuit.layout.to_chip_ids,
            real_challenges,
            params.n_public_output_bytes,
        )?;

        if let PredType::PredWire(out) = public_output_size {
            Ok((vec![node_id], vec![], Some(out)))
        } else {
            Err(ZKVMError::CircuitError)
        }
    }

    fn construct_graph(
        graph_builder: &mut CircuitGraphBuilder<E>,
        chip_builder: &mut SingerChipBuilder<E>,
        inst_circuit: &InstCircuit<E>,
        _acc_circuits: &[AccessoryCircuit<E>],
        preds: Vec<PredType>,
        real_n_instances: usize,
        _: &SingerParams,
    ) -> Result<(Vec<usize>, Vec<NodeOutputType>, Option<NodeOutputType>), ZKVMError> {
        let public_output_size =
            preds[inst_circuit.layout.from_pred_inst.stack_operand_ids[1] as usize].clone();

        // Add the instruction circuit to the graph.
        let node_id = graph_builder.add_node(
            <ReturnInstruction as Instruction<E>>::NAME,
            &inst_circuit.circuit,
            preds,
        )?;

        chip_builder.construct_chip_check_graph(
            graph_builder,
            node_id,
            &inst_circuit.layout.to_chip_ids,
            real_n_instances,
        )?;

        if let PredType::PredWire(out) = public_output_size {
            Ok((vec![node_id], vec![], Some(out)))
        } else {
            Err(ZKVMError::CircuitError)
        }
    }
}

register_witness!(
    ReturnInstruction,
    public_io {
        byte => 1
    },
    phase0 {
        old_memory_ts => TSUInt::N_OPERAND_CELLS,
        offset_add => AddSubConstants::<StackUInt>::N_WITNESS_CELLS
    }
);

impl<E: ExtensionField> Instruction<E> for ReturnInstruction {
    const OPCODE: OpcodeType = OpcodeType::RETURN;
    const NAME: &'static str = "RETURN";
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From public io
        let (public_io_id, public_io) = circuit_builder.create_witness_in(Self::public_io_size());

        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_witness_in(TSUInt::N_OPERAND_CELLS);
        let (offset_id, offset) = circuit_builder.create_witness_in(StackUInt::N_OPERAND_CELLS);

        let mut rom_handler = ROMHandler::new(&challenges);
        let mut ram_handler = RAMHandler::new(&challenges);

        // Compute offset + counter
        let delta = circuit_builder.create_counter_in(0)[0];
        let offset = StackUInt::try_from(offset.as_slice())?;
        let offset_add_delta = &phase0[Self::phase0_offset_add()];
        let offset_plus_delta = StackUInt::add_cell(
            &mut circuit_builder,
            &mut rom_handler,
            &offset,
            delta,
            offset_add_delta,
        )?;

        // Load from memory
        let mem_byte = public_io[Self::public_io_byte().start];
        let memory_ts = TSUInt::try_from(memory_ts.as_slice())?;
        let old_memory_ts = TSUInt::try_from(&phase0[Self::phase0_old_memory_ts()])?;

        ram_handler.oam_load(
            &mut circuit_builder,
            offset_plus_delta.values(),
            old_memory_ts.values(),
            &[mem_byte],
        );

        // To successor instruction
        let (next_memory_ts_id, next_memory_ts) =
            circuit_builder.create_witness_out(TSUInt::N_OPERAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &next_memory_ts, memory_ts.values());

        let (ram_load_id, ram_store_id) = ram_handler.finalize(&mut circuit_builder);
        let rom_id = rom_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; InstOutChipType::iter().count()];
        to_chip_ids[InstOutChipType::RAMLoad as usize] = ram_load_id;
        to_chip_ids[InstOutChipType::RAMStore as usize] = ram_store_id;
        to_chip_ids[InstOutChipType::ROMInput as usize] = rom_id;

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstLayout {
                to_chip_ids,
                from_pred_inst: FromPredInst {
                    memory_ts_id,
                    stack_operand_ids: vec![offset_id],
                },
                to_succ_inst: ToSuccInst {
                    next_memory_ts_id,
                    stack_result_ids: vec![],
                },
                from_witness: FromWitness {
                    phase_ids: vec![phase0_wire_id],
                },
                from_public_io: Some(FromPublicIO {
                    public_output_id: public_io_id,
                }),
                to_bb_final: None,
                to_acc_dup: None,
                to_acc_ooo: None,
            },
        })
    }
}
