use std::sync::Arc;
use std::{iter, mem};

use frontend::structs::{CircuitBuilder, ConstantType, MixedCell};
use gkr::structs::Circuit;
use gkr_graph::structs::{NodeOutputType, PredType};
use goldilocks::SmallField;
use itertools::{izip, Itertools};
use revm_interpreter::Record;
use strum::IntoEnumIterator;

use crate::chips::ChipCircuitGadgets;
use crate::instructions::InstCircuitLayout;
use crate::{constants::OpcodeType, error::ZKVMError};
use crate::{CircuitWiresIn, SingerGraphBuilder};

use super::{
    utils::{
        uint::{UIntAddSub, UIntCmp},
        ChipHandler, PCUInt, StackUInt, TSUInt,
    },
    ChipChallenges, InstCircuit, InstOutputType,
};
use super::{Instruction, InstructionGraph};
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
        builder: &mut SingerGraphBuilder<F>,
        inst_circuits: &[InstCircuit<F>],
        chip_gadgets: &ChipCircuitGadgets<F>,
        mut sources: Vec<CircuitWiresIn<F>>,
        real_challenges: &[F],
    ) -> Result<(), ZKVMError> {
        // Add the instruction circuit to the graph.
        let mut ns_instances = Vec::new();
        let inst_circuit = &inst_circuits[0];
        let n_wires_in = inst_circuit.circuit.n_wires_in;
        ns_instances.push(sources[0][0].len());
        let graph_builder = &mut builder.graph_builder;
        let inst_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnInstruction),
            &inst_circuit.circuit,
            vec![PredType::Source; n_wires_in],
            real_challenges.to_vec(),
            mem::take(&mut sources[0]),
        )?;
        builder.public_output_size = inst_circuit
            .layout
            .target_wire_id
            .map(|target_wire_id| NodeOutputType::WireOut(inst_node_id, target_wire_id));

        // Add the public output load circuit to the graph.
        let pub_out_load_circuit = &inst_circuits[1];
        let n_wires_in = pub_out_load_circuit.circuit.n_wires_in;
        let preds = iter::once(PredType::PredWireDup(NodeOutputType::WireOut(
            inst_node_id,
            inst_circuit.layout.succ_wires_id[Self::succ_public_out_load()],
        )))
        .chain(iter::repeat(PredType::Source).take(n_wires_in - 1))
        .collect_vec();
        ns_instances.push(sources[1][0].len());
        let pub_out_load_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnPublicOutLoad),
            &pub_out_load_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[1]),
        )?;

        // Add the rest memory load circuit to the graph.
        let rest_mem_load_circuit = &inst_circuits[2];
        let n_wires_in = rest_mem_load_circuit.circuit.n_wires_in;
        let preds = iter::once(PredType::PredWireDup(NodeOutputType::WireOut(
            inst_node_id,
            inst_circuit.layout.succ_wires_id[Self::succ_rest_mem_load()],
        )))
        .chain(iter::repeat(PredType::Source).take(n_wires_in - 1))
        .collect_vec();
        ns_instances.push(sources[2][0].len());
        let rest_mem_load_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnRestMemLoad),
            &rest_mem_load_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[2]),
        )?;

        // Add the rest memory store circuit to the graph.
        let rest_mem_store_circuit = &inst_circuits[3];
        let n_wires_in = rest_mem_store_circuit.circuit.n_wires_in;
        ns_instances.push(sources[3][0].len());
        let rest_mem_store_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnRestMemStore),
            &rest_mem_store_circuit.circuit,
            vec![PredType::Source; n_wires_in],
            real_challenges.to_vec(),
            mem::take(&mut sources[3]),
        )?;

        // Add the rest stack pop circuit to the graph.
        let rest_stack_pop_circuit = &inst_circuits[4];
        let n_wires_in = rest_stack_pop_circuit.circuit.n_wires_in;
        let preds = iter::once(PredType::PredWire(NodeOutputType::WireOut(
            inst_node_id,
            inst_circuit.layout.succ_wires_id[Self::succ_rest_stack_pop()],
        )))
        .chain(iter::repeat(PredType::Source).take(n_wires_in - 1))
        .collect_vec();
        ns_instances.push(sources[4][0].len());
        let rest_stack_pop_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnRestStackPop),
            &rest_stack_pop_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[4]),
        )?;
        let inst_nodes_id = [
            inst_node_id,
            pub_out_load_node_id,
            rest_mem_load_node_id,
            rest_mem_store_node_id,
            rest_stack_pop_node_id,
        ];

        for (circuit, node_id, n_instances) in izip!(inst_circuits, inst_nodes_id, ns_instances) {
            for output_type in InstOutputType::iter() {
                if let Some(output_wire_id) =
                    circuit.layout.chip_check_wire_id[output_type as usize]
                {
                    let chip_out_node_id = crate::chips::construct_inst_chip_circuits(
                        graph_builder,
                        output_type,
                        NodeOutputType::WireOut(node_id, output_wire_id),
                        n_instances,
                        &chip_gadgets,
                        real_challenges,
                    )?;
                    builder.output_wires_id[output_type as usize].push(chip_out_node_id);
                }
            }
        }
        Ok(())
    }
}

register_wires_in!(
    ReturnInstruction,
    phase0_size {
        phase0_pc => PCUInt::N_OPRAND_CELLS,
        phase0_stack_ts => TSUInt::N_OPRAND_CELLS,
        phase0_memory_ts => TSUInt::N_OPRAND_CELLS,
        phase0_stack_top => 1,
        phase0_clk => 1,

        phase0_old_stack_ts0 => TSUInt::N_OPRAND_CELLS,
        phase0_old_stack_ts_lt0 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        phase0_old_stack_ts1 => TSUInt::N_OPRAND_CELLS,
        phase0_old_stack_ts_lt1 => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        phase0_offset => StackUInt::N_OPRAND_CELLS,
        phase0_mem_length => StackUInt::N_OPRAND_CELLS
    }
);

register_wires_out!(
    ReturnInstruction,
    global_state_in_size {
        state_in => 1
    },
    bytecode_chip_size {
        current => 1
    },
    stack_pop_size {
        addend_0 => 1,
        addend_1 => 1
    },
    range_chip_size {
        stack_top => 1,
        old_stack_ts_lt0 => TSUInt::N_RANGE_CHECK_CELLS,
        old_stack_ts_lt1 => TSUInt::N_RANGE_CHECK_CELLS
    },
    target_size {
        stack_top => 1,
        length => 1
    }
);

register_succ_wire_out!(
    ReturnInstruction,
    succ_public_out_load,
    succ_rest_mem_load,
    succ_rest_stack_pop
);

impl ReturnInstruction {
    const OPCODE: OpcodeType = OpcodeType::RETURN;
}

impl Instruction for ReturnInstruction {
    fn witness_size(phase: usize) -> usize {
        match phase {
            0 => Self::phase0_size(),
            _ => todo!(),
        }
    }

    fn output_size(inst_out: InstOutputType) -> usize {
        match inst_out {
            InstOutputType::GlobalStateIn => Self::global_state_in_size(),
            InstOutputType::BytecodeChip => Self::bytecode_chip_size(),
            InstOutputType::StackPop => Self::stack_pop_size(),
            InstOutputType::RangeChip => Self::range_chip_size(),
            _ => todo!(),
        }
    }

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let mut global_state_in_handler = ChipHandler::new(
            &mut circuit_builder,
            challenges,
            Self::global_state_in_size(),
        );
        let mut bytecode_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::bytecode_chip_size());
        let mut stack_pop_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::stack_pop_size());
        let mut range_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::range_chip_size());

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
            memory_ts,
            stack_top,
            clk,
        );

        // Check the range of stack_top - 2 is within [0, 1 << STACK_TOP_BIT_WIDTH).
        range_chip_handler
            .range_check_stack_top(&mut circuit_builder, stack_top_expr.sub(F::from(2)))?;

        // Pop offset and mem_size from stack
        let old_stack_ts0 = (&phase0[Self::phase0_old_stack_ts0()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts0,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt0()],
        )?;
        let offset = StackUInt::try_from(&phase0[Self::phase0_offset()])?;
        stack_pop_handler.stack_pop_values(
            &mut circuit_builder,
            stack_top_expr.sub(F::from(1)),
            old_stack_ts0.values(),
            offset.values(),
        );

        let old_stack_ts1 = (&phase0[Self::phase0_old_stack_ts1()]).try_into()?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt1()],
        )?;
        let length = StackUInt::try_from(&phase0[Self::phase0_mem_length()])?;
        stack_pop_handler.stack_pop_values(
            &mut circuit_builder,
            stack_top_expr.sub(F::from(2)),
            &old_stack_ts1.values(),
            length.values(),
        );

        // Bytecode check for (pc, ret)
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );

        global_state_in_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_handler.wire_out_id()),
            None,
            Some(bytecode_chip_handler.wire_out_id()),
            Some(stack_pop_handler.wire_out_id()),
            None,
            Some(range_chip_handler.wire_out_id()),
            None,
            None,
            None,
        ];

        // Copy length to the target wire.
        let (target_wire_id, target) = circuit_builder.create_wire_out(Self::target_size());
        let length = length.values();
        for i in 1..length.len() {
            circuit_builder.assert_const(length[i], &F::ZERO);
        }
        circuit_builder.add(target[0], length[0], ConstantType::Field(F::ONE));

        let mut succ_wires_id = vec![0; Self::succ_wire_out_num()];
        // Copy memory_ts and offset to wires of public output load circuit.
        let (pub_out_wire_id, pub_out) =
            circuit_builder.create_wire_out(ReturnPublicOutLoad::pred_size());
        let pub_out_memory_ts = &pub_out[ReturnPublicOutLoad::pred_memory_ts()];
        for i in 0..pub_out_memory_ts.len() {
            circuit_builder.add(
                pub_out_memory_ts[i],
                memory_ts[i],
                ConstantType::Field(F::ONE),
            );
        }
        let pub_out_offset = &pub_out[ReturnPublicOutLoad::pred_offset()];
        let offset = offset.values();
        for i in 0..pub_out_offset.len() {
            circuit_builder.add(pub_out_offset[i], offset[i], ConstantType::Field(F::ONE));
        }
        succ_wires_id[Self::succ_public_out_load()] = pub_out_wire_id;

        // Copy memory_ts to wires of rest memory load circuit.
        let (rest_mem_load_wire_id, rest_mem_load) =
            circuit_builder.create_wire_out(ReturnRestMemLoad::pred_size());
        let rest_mem_load_memory_ts = &rest_mem_load[ReturnRestMemLoad::pred_memory_ts()];
        for i in 0..rest_mem_load_memory_ts.len() {
            circuit_builder.add(
                rest_mem_load_memory_ts[i],
                memory_ts[i],
                ConstantType::Field(F::ONE),
            );
        }
        succ_wires_id[Self::succ_rest_mem_load()] = rest_mem_load_wire_id;

        // Copy stack_ts to wires of rest stack pop circuit.
        let (rest_stack_pop_wire_id, rest_stack_pop) =
            circuit_builder.create_wire_out(ReturnRestStackPop::pred_size());
        let rest_stack_pop_stack_ts = &rest_stack_pop[ReturnRestStackPop::pred_stack_ts()];
        let stack_ts = stack_ts.values();
        for i in 0..rest_stack_pop_stack_ts.len() {
            circuit_builder.add(
                rest_stack_pop_stack_ts[i],
                stack_ts[i],
                ConstantType::Field(F::ONE),
            );
        }
        succ_wires_id[Self::succ_rest_stack_pop()] = rest_stack_pop_wire_id;

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: [Some(phase0_wire_id), None],
                target_wire_id: Some(target_wire_id),
                succ_wires_id,
                ..Default::default()
            },
        })
    }

    fn generate_wires_in<F: SmallField>(
        record: &Record,
        challenge: &Option<Vec<F>>,
        index: usize,
    ) -> Option<Vec<F>> {
        todo!()
    }
}

register_wires_in!(
    ReturnPublicOutLoad,
    pred_size {
        pred_memory_ts => TSUInt::N_OPRAND_CELLS,
        pred_offset => StackUInt::N_OPRAND_CELLS
    },
    public_io_size {
        public_io_byte => 1
    },
    phase0_size {
        phase0_old_memory_ts => TSUInt::N_OPRAND_CELLS,
        phase0_old_memory_ts_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        phase0_offset_add => UIntAddSub::<StackUInt>::N_WITNESS_CELLS
    }
);

register_wires_out!(
    ReturnPublicOutLoad,
    memory_load_size  {
        mem_load => 1
    },
    range_chip_size {
        old_memory_ts_lt => TSUInt::N_RANGE_CHECK_CELLS,
        offset_add => StackUInt::N_RANGE_CHECK_CELLS
    }
);

impl Instruction for ReturnPublicOutLoad {
    #[inline]
    fn witness_size(phase: usize) -> usize {
        match phase {
            0 => Self::phase0_size(),
            _ => 0,
        }
    }

    #[inline]
    fn output_size(inst_out: InstOutputType) -> usize {
        match inst_out {
            InstOutputType::MemoryLoad => Self::memory_load_size(),
            InstOutputType::RangeChip => Self::range_chip_size(),
            _ => 0,
        }
    }

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (pred_wire_id, pred) = circuit_builder.create_wire_in(Self::pred_size());
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let mut range_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::range_chip_size());
        let mut memory_load_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::memory_load_size());

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
        let memory_ts = TSUInt::try_from(&pred[Self::pred_memory_ts()])?;
        let old_memory_ts = TSUInt::try_from(&phase0[Self::phase0_old_memory_ts()])?;
        let old_memory_ts_lt = &phase0[Self::phase0_old_memory_ts_lt()];
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_memory_ts,
            &memory_ts,
            old_memory_ts_lt,
        )?;
        memory_load_handler.mem_load(
            &mut circuit_builder,
            new_offset.values(),
            old_memory_ts.values(),
            mem_byte,
        );

        range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        memory_load_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        circuit_builder.configure();

        let outputs_wire_id = [
            None,
            None,
            None,
            None,
            None,
            Some(range_chip_handler.wire_out_id()),
            Some(memory_load_handler.wire_out_id()),
            None,
            None,
        ];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: [Some(phase0_wire_id), None],
                pred_wire_id: Some(pred_wire_id),
                ..Default::default()
            },
        })
    }

    fn generate_wires_in<F: SmallField>(
        record: &Record,
        challenge: &Option<Vec<F>>,
        index: usize,
    ) -> Option<Vec<F>> {
        todo!()
    }
}

register_wires_in!(
    ReturnRestMemLoad,
    pred_size {
        pred_memory_ts => TSUInt::N_OPRAND_CELLS
    },
    phase0_size {
        phase0_mem_byte => 1,
        phase0_old_memory_ts => TSUInt::N_OPRAND_CELLS,
        phase0_old_memory_ts_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS
    },
    phase1_size {
        phase1_offset_rlc => 1
    }
);

register_wires_out!(
    ReturnRestMemLoad,
    memory_load_size  {
        mem_load => 1
    },
    range_chip_size {
        old_memory_ts_lt => TSUInt::N_RANGE_CHECK_CELLS
    }
);

impl Instruction for ReturnRestMemLoad {
    #[inline]
    fn witness_size(phase: usize) -> usize {
        match phase {
            0 => Self::phase0_size(),
            _ => 0,
        }
    }

    #[inline]
    fn output_size(inst_out: InstOutputType) -> usize {
        match inst_out {
            InstOutputType::MemoryLoad => Self::memory_load_size(),
            InstOutputType::RangeChip => Self::range_chip_size(),
            _ => 0,
        }
    }

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (pred_wire_id, pred) = circuit_builder.create_wire_in(Self::pred_size());
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let (phase1_wire_id, phase1) = circuit_builder.create_wire_in(Self::phase1_size());
        let mut range_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::range_chip_size());
        let mut memory_load_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::memory_load_size());

        // Load from memory
        let offset_rlc = phase1[Self::phase1_offset_rlc().start];
        let mem_byte = phase0[Self::phase0_mem_byte().start];
        let memory_ts = TSUInt::try_from(&pred[Self::pred_memory_ts()])?;
        let old_memory_ts = TSUInt::try_from(&phase0[Self::phase0_old_memory_ts()])?;
        let old_memory_ts_lt = &phase0[Self::phase0_old_memory_ts_lt()];
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_memory_ts,
            &memory_ts,
            old_memory_ts_lt,
        )?;
        memory_load_handler.mem_load(
            &mut circuit_builder,
            &[offset_rlc],
            old_memory_ts.values(),
            mem_byte,
        );

        range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        memory_load_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        circuit_builder.configure();

        let outputs_wire_id = [
            None,
            None,
            None,
            None,
            None,
            Some(range_chip_handler.wire_out_id()),
            Some(memory_load_handler.wire_out_id()),
            None,
            None,
        ];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: [Some(phase0_wire_id), Some(phase1_wire_id)],
                pred_wire_id: Some(pred_wire_id),
                ..Default::default()
            },
        })
    }

    fn generate_wires_in<F: SmallField>(
        record: &Record,
        challenge: &Option<Vec<F>>,
        index: usize,
    ) -> Option<Vec<F>> {
        todo!()
    }
}

register_wires_in!(
    ReturnRestMemStore,
    phase0_size {
        phase0_mem_byte => 1
    },
    phase1_size {
        phase1_offset_rlc => 1
    }
);

register_wires_out!(
    ReturnRestMemStore,
    memory_store_size  {
        mem_store => 1
    }
);

impl Instruction for ReturnRestMemStore {
    #[inline]
    fn witness_size(phase: usize) -> usize {
        match phase {
            0 => Self::phase0_size(),
            _ => 0,
        }
    }

    #[inline]
    fn output_size(inst_out: InstOutputType) -> usize {
        match inst_out {
            InstOutputType::MemoryStore => Self::memory_store_size(),
            _ => 0,
        }
    }

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let (phase1_wire_id, phase1) = circuit_builder.create_wire_in(Self::phase1_size());
        let mut memory_load_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::memory_store_size());

        let offset_rlc = phase1[Self::phase1_offset_rlc().start];

        // Load from memory
        let mem_byte = phase0[Self::phase0_mem_byte().start];
        let memory_ts_rlc = circuit_builder.create_cell();
        circuit_builder.rlc_mixed(
            memory_ts_rlc,
            &[MixedCell::Constant(F::ZERO); TSUInt::N_OPRAND_CELLS],
            challenges.record_item_rlc(),
        );
        memory_load_handler.mem_store(
            &mut circuit_builder,
            &[offset_rlc],
            &[memory_ts_rlc],
            mem_byte,
        );

        memory_load_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        circuit_builder.configure();

        let outputs_wire_id = [
            None,
            None,
            None,
            None,
            None,
            None,
            Some(memory_load_handler.wire_out_id()),
            None,
            None,
        ];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: [Some(phase0_wire_id), Some(phase1_wire_id)],
                ..Default::default()
            },
        })
    }

    fn generate_wires_in<F: SmallField>(
        record: &Record,
        challenge: &Option<Vec<F>>,
        index: usize,
    ) -> Option<Vec<F>> {
        todo!()
    }
}

pub struct ReturnRestStackPop;

register_wires_in!(
    ReturnRestStackPop,
    pred_size {
        pred_stack_ts => TSUInt::N_OPRAND_CELLS
    },
    phase0_size {
        phase0_old_stack_ts => TSUInt::N_OPRAND_CELLS,
        phase0_old_stack_ts_lt => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS
    },
    phase1_size {
        phase1_stack_rlc => 1
    }
);

register_wires_out!(
    ReturnRestStackPop,
    stack_pop_size  {
        stack_pop => 1
    },
    range_chip_size {
        old_memory_ts_lt => TSUInt::N_RANGE_CHECK_CELLS
    }
);

impl Instruction for ReturnRestStackPop {
    #[inline]
    fn witness_size(phase: usize) -> usize {
        match phase {
            0 => Self::phase0_size(),
            _ => 0,
        }
    }

    #[inline]
    fn output_size(inst_out: InstOutputType) -> usize {
        match inst_out {
            InstOutputType::StackPop => Self::stack_pop_size(),
            InstOutputType::RangeChip => Self::range_chip_size(),
            _ => 0,
        }
    }

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (pred_wire_id, pred) = circuit_builder.create_wire_in(Self::pred_size());
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let (phase1_wire_id, phase1) = circuit_builder.create_wire_in(Self::phase1_size());
        let mut range_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::range_chip_size());
        let mut stack_pop_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::stack_pop_size());

        // Pop from stack
        let stack_top = circuit_builder.create_counter_in(0);
        let stack_rlc = phase1[Self::phase1_stack_rlc().start];

        let stack_ts = TSUInt::try_from(&pred[Self::pred_stack_ts()])?;
        let old_stack_ts = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts()])?;
        let old_stack_ts_lt = &phase0[Self::phase0_old_stack_ts_lt()];
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts,
            &stack_ts,
            old_stack_ts_lt,
        )?;
        stack_pop_handler.stack_pop_rlc(
            &mut circuit_builder,
            stack_top[0].into(),
            old_stack_ts.values(),
            stack_rlc,
        );

        range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        circuit_builder.configure();

        let outputs_wire_id = [
            None,
            None,
            None,
            Some(stack_pop_handler.wire_out_id()),
            None,
            Some(range_chip_handler.wire_out_id()),
            None,
            None,
            None,
        ];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: [Some(phase0_wire_id), Some(phase1_wire_id)],
                pred_wire_id: Some(pred_wire_id),
                ..Default::default()
            },
        })
    }

    fn generate_wires_in<F: SmallField>(
        record: &Record,
        challenge: &Option<Vec<F>>,
        index: usize,
    ) -> Option<Vec<F>> {
        todo!()
    }
}
