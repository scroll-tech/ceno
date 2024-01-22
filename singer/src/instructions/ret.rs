use ff::Field;
use gkr::structs::Circuit;
use gkr_graph::structs::{NodeOutputType, PredType};
use goldilocks::SmallField;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use std::{mem, sync::Arc};

use crate::{
    constants::OpcodeType,
    error::ZKVMError,
    utils::{
        add_assign_each_cell,
        chip_handler::{
            BytecodeChipOperations, ChipHandler, GlobalStateChipOperations, MemoryChipOperations,
            RangeChipOperations, StackChipOperations,
        },
        uint::{PCUInt, StackUInt, TSUInt, UIntAddSub},
    },
    CircuitWiresIn, SingerParams,
};

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

/// This circuit is to pop offset and public output size from stack.
pub struct ReturnInstruction;
/// This circuit is to load public output from memory, which is a data-parallel
/// circuit load one element in each sub-circuit.
pub struct ReturnPublicOutLoad;
/// This circuit is to load the remaining elmeents after the program execution
/// from memory, which is a data-parallel circuit load one element in each
/// sub-circuit.
pub struct ReturnRestMemLoad;
/// This circuit is to initialize the memory with 0 at the beginning. It can
/// only touches the used addresses.
pub struct ReturnRestMemStore;

impl InstructionGraph for ReturnInstruction {
    type InstType = Self;

    fn construct_circuits<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<Vec<InstCircuit<F>>, ZKVMError> {
        let circuits = vec![
            ReturnInstruction::construct_circuit::<F>(challenges)?,
            ReturnPublicOutLoad::construct_circuit::<F>(challenges)?,
            ReturnRestMemLoad::construct_circuit::<F>(challenges)?,
            ReturnRestMemStore::construct_circuit::<F>(challenges)?,
            ReturnRestStackPop::construct_circuit::<F>(challenges)?,
        ];
        Ok(circuits)
    }

    fn construct_circuit_graph<F: SmallField>(
        graph_builder: &mut gkr_graph::structs::CircuitGraphBuilder<F>,
        chip_builder: &mut crate::chips::SingerChipBuilder<F>,
        inst_circuits: &[InstCircuit<F>],
        mut sources: Vec<CircuitWiresIn<F::BaseField>>,
        real_challenges: &[F],
        _: usize,
        params: SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        // Add the instruction circuit to the graph.
        let inst_circuit = &inst_circuits[0];
        let n_witness_in = inst_circuit.circuit.n_witness_in;
        let inst_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnInstruction),
            &inst_circuit.circuit,
            vec![PredType::Source; n_witness_in],
            real_challenges.to_vec(),
            mem::take(&mut sources[0]),
            1,
        )?;
        chip_builder.construct_chip_checks(
            graph_builder,
            inst_node_id,
            &inst_circuit.layout.chip_check_wire_id,
            real_challenges,
            1,
        )?;

        // Add the public output load circuit to the graph.
        let pub_out_load_circuit = &inst_circuits[1];
        let n_witness_in = pub_out_load_circuit.circuit.n_witness_in;
        let mut preds = vec![PredType::Source; n_witness_in];
        preds[pub_out_load_circuit.layout.pred_dup_wire_id.unwrap() as usize] =
            PredType::PredWireDup(NodeOutputType::WireOut(
                inst_node_id,
                inst_circuit.layout.succ_dup_wires_id[0],
            ));
        let pub_out_load_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnPublicOutLoad),
            &pub_out_load_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[1]),
            params.n_public_output_bytes,
        )?;
        chip_builder.construct_chip_checks(
            graph_builder,
            pub_out_load_node_id,
            &pub_out_load_circuit.layout.chip_check_wire_id,
            real_challenges,
            params.n_public_output_bytes,
        )?;

        // Add the rest memory load circuit to the graph.
        let rest_mem_load_circuit = &inst_circuits[2];
        let n_witness_in = rest_mem_load_circuit.circuit.n_witness_in;
        let rest_mem_load_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnRestMemLoad),
            &rest_mem_load_circuit.circuit,
            vec![PredType::Source; n_witness_in],
            real_challenges.to_vec(),
            mem::take(&mut sources[2]),
            params.n_mem_finalize,
        )?;
        chip_builder.construct_chip_checks(
            graph_builder,
            rest_mem_load_node_id,
            &rest_mem_load_circuit.layout.chip_check_wire_id,
            real_challenges,
            params.n_mem_finalize,
        )?;

        // Add the rest memory store circuit to the graph.
        let rest_mem_store_circuit = &inst_circuits[3];
        let n_witness_in = rest_mem_store_circuit.circuit.n_witness_in;
        let rest_mem_store_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnRestMemStore),
            &rest_mem_store_circuit.circuit,
            vec![PredType::Source; n_witness_in],
            real_challenges.to_vec(),
            mem::take(&mut sources[3]),
            params.n_mem_initialize,
        )?;
        chip_builder.construct_chip_checks(
            graph_builder,
            rest_mem_store_node_id,
            &rest_mem_store_circuit.layout.chip_check_wire_id,
            real_challenges,
            params.n_mem_initialize,
        )?;

        // Add the rest stack pop circuit to the graph.
        let rest_stack_pop_circuit = &inst_circuits[4];
        let n_witness_in = rest_stack_pop_circuit.circuit.n_witness_in;
        let rest_stack_pop_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnRestStackPop),
            &rest_stack_pop_circuit.circuit,
            vec![PredType::Source; n_witness_in],
            real_challenges.to_vec(),
            mem::take(&mut sources[4]),
            params.n_stack_finalize,
        )?;
        chip_builder.construct_chip_checks(
            graph_builder,
            rest_stack_pop_node_id,
            &rest_stack_pop_circuit.layout.chip_check_wire_id,
            real_challenges,
            params.n_stack_finalize,
        )?;

        Ok(inst_circuit
            .layout
            .target_wire_id
            .map(|target_wire_id| NodeOutputType::WireOut(inst_node_id, target_wire_id)))
    }
}

register_witness!(
    ReturnInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        old_stack_ts0 => TSUInt::N_OPRAND_CELLS,
        old_stack_ts1 => TSUInt::N_OPRAND_CELLS,

        offset => StackUInt::N_OPRAND_CELLS,
        mem_length => StackUInt::N_OPRAND_CELLS
    }
);

impl ReturnInstruction {
    const OPCODE: OpcodeType = OpcodeType::RETURN;
}

impl Instruction for ReturnInstruction {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut global_state_in_handler = ChipHandler::new(challenges.global_state());
        let mut bytecode_chip_handler = ChipHandler::new(challenges.bytecode());
        let mut stack_pop_handler = ChipHandler::new(challenges.stack());
        let mut range_chip_handler = ChipHandler::new(challenges.range());

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = &phase0[Self::phase0_memory_ts()];
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            &memory_ts,
            stack_top,
            clk,
        );

        // Check the range of stack_top - 2 is within [0, 1 << STACK_TOP_BIT_WIDTH).
        range_chip_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
        )?;

        // Pop offset and mem_size from stack
        let old_stack_ts0 = StackUInt::try_from(&phase0[Self::phase0_old_stack_ts0()])?;
        let offset = StackUInt::try_from(&phase0[Self::phase0_offset()])?;
        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(1)),
            old_stack_ts0.values(),
            offset.values(),
        );

        let old_stack_ts1 = StackUInt::try_from(&phase0[Self::phase0_old_stack_ts1()])?;
        let length = StackUInt::try_from(&phase0[Self::phase0_mem_length()])?;
        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
            &old_stack_ts1.values(),
            length.values(),
        );

        // Bytecode check for (pc, ret)
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );

        let global_state_in_id = global_state_in_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let bytecode_chip_id =
            bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let stack_pop_id =
            stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_id),
            None,
            Some(bytecode_chip_id),
            Some(stack_pop_id),
            None,
            Some(range_chip_id),
            None,
            None,
            None,
        ];

        // Copy length to the target wire.
        let (target_wire_id, target) =
            circuit_builder.create_witness_out(StackUInt::N_OPRAND_CELLS);
        let length = length.values();
        for i in 1..length.len() {
            circuit_builder.assert_const(length[i], 0);
        }
        circuit_builder.add(target[0], length[0], F::BaseField::ONE);

        // Copy offset to wires of public output load circuit.
        let (pub_out_wire_id, pub_out) =
            circuit_builder.create_witness_out(ReturnPublicOutLoad::pred_size());
        let pub_out_offset = &pub_out[ReturnPublicOutLoad::pred_offset()];
        let offset = offset.values();
        add_assign_each_cell(&mut circuit_builder, pub_out_offset, offset);

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: vec![phase0_wire_id],
                target_wire_id: Some(target_wire_id),
                succ_dup_wires_id: vec![pub_out_wire_id],
                ..Default::default()
            },
        })
    }
}

register_witness!(
    ReturnPublicOutLoad,
    pred {
        offset => StackUInt::N_OPRAND_CELLS
    },
    public_io {
        byte => 1
    },
    phase0 {
        old_memory_ts => TSUInt::N_OPRAND_CELLS,

        offset_add => UIntAddSub::<StackUInt>::N_WITNESS_CELLS
    }
);

impl Instruction for ReturnPublicOutLoad {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (pred_wire_id, pred) = circuit_builder.create_witness_in(Self::pred_size());
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut range_chip_handler = ChipHandler::new(challenges.range());
        let mut memory_load_handler = ChipHandler::new(challenges.mem());

        // Compute offset + counter
        let delta = circuit_builder.create_counter_in(0);
        let offset = StackUInt::try_from(&pred[Self::pred_offset()])?;
        let offset_add_delta_witness = &phase0[Self::phase0_offset_add()];
        let new_offset = UIntAddSub::<StackUInt>::add_small(
            &mut circuit_builder,
            &mut range_chip_handler,
            &offset,
            delta[0],
            offset_add_delta_witness,
        )?;

        // Load from memory
        let mem_byte = pred[Self::public_io_byte().start];
        let old_memory_ts = TSUInt::try_from(&phase0[Self::phase0_old_memory_ts()])?;
        memory_load_handler.mem_load(
            &mut circuit_builder,
            new_offset.values(),
            old_memory_ts.values(),
            mem_byte,
        );

        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let memory_load_id =
            memory_load_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        circuit_builder.configure();

        let outputs_wire_id = [
            None,
            None,
            None,
            None,
            None,
            Some(range_chip_id),
            Some(memory_load_id),
            None,
            None,
        ];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: vec![phase0_wire_id],
                pred_dup_wire_id: Some(pred_wire_id),
                ..Default::default()
            },
        })
    }
}

register_witness!(
    ReturnRestMemLoad,
    phase0 {
        mem_byte => 1,
        offset => StackUInt::N_OPRAND_CELLS,
        old_memory_ts => TSUInt::N_OPRAND_CELLS
    }
);

impl Instruction for ReturnRestMemLoad {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut range_chip_handler = ChipHandler::new(challenges.range());
        let mut memory_load_handler = ChipHandler::new(challenges.mem());

        // Load from memory
        let offset = &phase0[Self::phase0_offset()];
        let mem_byte = phase0[Self::phase0_mem_byte().start];
        let old_memory_ts = TSUInt::try_from(&phase0[Self::phase0_old_memory_ts()])?;
        memory_load_handler.mem_load(
            &mut circuit_builder,
            &offset,
            old_memory_ts.values(),
            mem_byte,
        );

        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let memory_load_id =
            memory_load_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        circuit_builder.configure();

        let outputs_wire_id = [
            None,
            None,
            None,
            None,
            None,
            Some(range_chip_id),
            Some(memory_load_id),
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

register_witness!(
    ReturnRestMemStore,
    phase0 {
        mem_byte => 1,
        offset => StackUInt::N_OPRAND_CELLS
    }
);

impl Instruction for ReturnRestMemStore {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut memory_store_handler = ChipHandler::new(challenges.mem());

        // Load from memory
        let offset = &phase0[Self::phase0_offset()];
        let mem_byte = phase0[Self::phase0_mem_byte().start];
        let memory_ts = circuit_builder.create_cells(StackUInt::N_OPRAND_CELLS);
        memory_store_handler.mem_store(&mut circuit_builder, offset, &memory_ts, mem_byte);

        let memory_store_id =
            memory_store_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        circuit_builder.configure();

        let outputs_wire_id = [
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(memory_store_id),
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

pub struct ReturnRestStackPop;

register_witness!(
    ReturnRestStackPop,
    phase0 {
        old_stack_ts => TSUInt::N_OPRAND_CELLS,
        stack_values => StackUInt::N_OPRAND_CELLS
    }
);

impl Instruction for ReturnRestStackPop {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut range_chip_handler = ChipHandler::new(challenges.range());
        let mut stack_pop_handler = ChipHandler::new(challenges.stack());

        // Pop from stack
        let stack_top = circuit_builder.create_counter_in(0);
        let stack_values = &phase0[Self::phase0_stack_values()];

        let old_stack_ts = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts()])?;
        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            stack_top[0].into(),
            old_stack_ts.values(),
            stack_values,
        );

        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let stack_pop_id =
            stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        circuit_builder.configure();

        let outputs_wire_id = [
            None,
            None,
            None,
            Some(stack_pop_id),
            None,
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
