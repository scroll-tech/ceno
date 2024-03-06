use ff::Field;
use std::{mem, sync::Arc};

use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use goldilocks::SmallField;
use paste::paste;
use simple_frontend::structs::CircuitBuilder;
use strum::IntoEnumIterator;

use crate::{
    chips::SingerChipBuilder,
    component::{
        AccessoryCircuit, ChipChallenges, ChipType, FromPredInst, FromPublicIO, FromWitness,
        InstCircuit, InstLayout, ToSuccInst,
    },
    error::ZKVMError,
    utils::{
        add_assign_each_cell,
        chip_handler::{ChipHandler, MemoryChipOperations},
        uint::{StackUInt, TSUInt, UIntAddSub, UIntCmp},
    },
    CircuitWiresInValues, SingerParams,
};

use super::{Instruction, InstructionGraph};
/// This circuit is to load public output from memory, which is a data-parallel
/// circuit load one element in each sub-circuit.
pub struct ReturnInstruction;

impl<F: SmallField> InstructionGraph<F> for ReturnInstruction {
    type InstType = Self;

    fn construct_circuit_graph(
        graph_builder: &mut CircuitGraphBuilder<F>,
        chip_builder: &mut SingerChipBuilder<F>,
        inst_circuit: &InstCircuit<F>,
        _: &[AccessoryCircuit<F>],
        preds: Vec<PredType>,
        mut sources: Vec<CircuitWiresInValues<F::BaseField>>,
        real_challenges: &[F],
        _: usize,
        params: SingerParams,
    ) -> Result<(Vec<usize>, Vec<NodeOutputType>, Option<NodeOutputType>), ZKVMError> {
        let public_output_size =
            preds[inst_circuit.layout.from_pred_inst.stack_operand_ids[1] as usize];

        // Add the instruction circuit to the graph.
        let node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnInstruction),
            &inst_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[0]),
        )?;

        chip_builder.construct_chip_checks(
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
}

register_witness!(
    ReturnInstruction,
    public_io {
        byte => 1
    },
    phase0 {
        old_memory_ts => TSUInt::N_OPRAND_CELLS,
        offset_add => UIntAddSub::<StackUInt>::N_WITNESS_CELLS
    }
);

impl<F: SmallField> Instruction<F> for ReturnInstruction {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From public io
        let (public_io_id, public_io) = circuit_builder.create_wire_in(Self::public_io_size());

        // From witness
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());

        // From predesessor instruction
        let (memory_ts_id, memory_ts) = circuit_builder.create_wire_in(TSUInt::N_OPRAND_CELLS);
        let (offset_id, offset) = circuit_builder.create_wire_in(StackUInt::N_OPRAND_CELLS);

        let mut range_chip_handler = ChipHandler::new(challenges.range());
        let mut memory_load_handler = ChipHandler::new(challenges.mem());

        // Compute offset + counter
        let delta = circuit_builder.create_counter_in(0)[0];
        let offset = StackUInt::try_from(offset.as_slice())?;
        let offset_add_delta = &phase0[Self::phase0_offset_add()];
        let offset_plus_delta = UIntAddSub::<StackUInt>::add_small(
            &mut circuit_builder,
            &mut range_chip_handler,
            &offset,
            delta,
            offset_add_delta,
        )?;

        // Load from memory
        let mem_byte = public_io[Self::public_io_byte().start];
        let memory_ts = TSUInt::try_from(memory_ts.as_slice())?;
        let old_memory_ts = TSUInt::try_from(&phase0[Self::phase0_old_memory_ts()])?;

        memory_load_handler.mem_load(
            &mut circuit_builder,
            offset_plus_delta.values(),
            old_memory_ts.values(),
            mem_byte,
        );

        // To successor instruction
        let (next_memory_ts_id, next_memory_ts) =
            circuit_builder.create_wire_out(TSUInt::N_OPRAND_CELLS);
        add_assign_each_cell(&mut circuit_builder, &next_memory_ts, memory_ts.values());

        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let memory_load_id =
            memory_load_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        circuit_builder.configure();

        let mut to_chip_ids = vec![None; ChipType::iter().count()];
        to_chip_ids[ChipType::RangeChip as usize] = Some(range_chip_id);
        to_chip_ids[ChipType::MemoryLoad as usize] = Some(memory_load_id);

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
