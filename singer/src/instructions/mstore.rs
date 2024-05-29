use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        BytecodeChipOperations, GlobalStateChipOperations, MemoryChipOperations, OAMOperations,
        ROMOperations, RangeChipOperations, StackChipOperations,
    },
    chips::SingerChipBuilder,
    constants::{OpcodeType, EVM_STACK_BYTE_WIDTH},
    register_witness,
    structs::{PCUInt, RAMHandler, ROMHandler, StackUInt, TSUInt},
    uint::{UIntAddSub, UIntCmp},
};
use std::{mem, sync::Arc};

use crate::{error::ZKVMError, utils::add_assign_each_cell, CircuitWiresIn, SingerParams};

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct MstoreInstruction;

impl<E: ExtensionField> InstructionGraph<E> for MstoreInstruction {
    type InstType = Self;

    fn construct_circuits(challenges: ChipChallenges) -> Result<Vec<InstCircuit<E>>, ZKVMError> {
        let circuits = vec![
            MstoreInstruction::construct_circuit(challenges)?,
            MstoreAccessory::construct_circuit(challenges)?,
        ];
        Ok(circuits)
    }

    fn construct_graph_and_witness(
        graph_builder: &mut CircuitGraphBuilder<E>,
        chip_builder: &mut SingerChipBuilder<E>,
        inst_circuits: &[InstCircuit<E>],
        mut sources: Vec<CircuitWiresIn<E::BaseField>>,
        real_challenges: &[E],
        real_n_instances: usize,
        _: &SingerParams,
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
            real_n_instances,
        )?;
        chip_builder.construct_chip_check_graph_and_witness(
            graph_builder,
            inst_node_id,
            &inst_circuit.layout.chip_check_wire_id,
            real_challenges,
            real_n_instances,
        )?;

        let mstore_acc_circuit = &inst_circuits[1];
        let n_witness_in = mstore_acc_circuit.circuit.n_witness_in;
        let mut preds = vec![PredType::Source; n_witness_in];
        // The order is consistent with the order of creating wires in.
        preds[mstore_acc_circuit.layout.pred_dup_wire_id.unwrap() as usize] = PredType::PredWireDup(
            NodeOutputType::WireOut(inst_node_id, inst_circuit.layout.succ_dup_wires_id[0]),
        );
        preds[mstore_acc_circuit.layout.pred_ooo_wire_id.unwrap() as usize] = PredType::PredWire(
            NodeOutputType::WireOut(inst_node_id, inst_circuit.layout.succ_ooo_wires_id[0]),
        );
        let mstore_acc_node_id = graph_builder.add_node_with_witness(
            stringify!(MstoreAccessory),
            &mstore_acc_circuit.circuit,
            preds,
            real_challenges.to_vec(),
            mem::take(&mut sources[1]),
            real_n_instances * EVM_STACK_BYTE_WIDTH,
        )?;
        chip_builder.construct_chip_check_graph_and_witness(
            graph_builder,
            mstore_acc_node_id,
            &mstore_acc_circuit.layout.chip_check_wire_id,
            real_challenges,
            real_n_instances * EVM_STACK_BYTE_WIDTH,
        )?;
        Ok(None)
    }

    fn construct_graph(
        graph_builder: &mut CircuitGraphBuilder<E>,
        chip_builder: &mut SingerChipBuilder<E>,
        inst_circuits: &[InstCircuit<E>],
        real_n_instances: usize,
        _: &SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        // Add the instruction circuit to the graph.
        let inst_circuit = &inst_circuits[0];
        let n_witness_in = inst_circuit.circuit.n_witness_in;
        let inst_node_id = graph_builder.add_node(
            stringify!(ReturnInstruction),
            &inst_circuit.circuit,
            vec![PredType::Source; n_witness_in],
        )?;
        chip_builder.construct_chip_check_graph(
            graph_builder,
            inst_node_id,
            &inst_circuit.layout.chip_check_wire_id,
            real_n_instances,
        )?;

        let mstore_acc_circuit = &inst_circuits[1];
        let n_witness_in = mstore_acc_circuit.circuit.n_witness_in;
        let mut preds = vec![PredType::Source; n_witness_in];
        // The order is consistent with the order of creating wires in.
        preds[mstore_acc_circuit.layout.pred_dup_wire_id.unwrap() as usize] = PredType::PredWireDup(
            NodeOutputType::WireOut(inst_node_id, inst_circuit.layout.succ_dup_wires_id[0]),
        );
        preds[mstore_acc_circuit.layout.pred_ooo_wire_id.unwrap() as usize] = PredType::PredWire(
            NodeOutputType::WireOut(inst_node_id, inst_circuit.layout.succ_ooo_wires_id[0]),
        );
        let mstore_acc_node_id = graph_builder.add_node(
            stringify!(MstoreAccessory),
            &mstore_acc_circuit.circuit,
            preds,
        )?;
        chip_builder.construct_chip_check_graph(
            graph_builder,
            mstore_acc_node_id,
            &mstore_acc_circuit.layout.chip_check_wire_id,
            real_n_instances * EVM_STACK_BYTE_WIDTH,
        )?;
        Ok(None)
    }
}

register_witness!(
    MstoreInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS,
        stack_ts => TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        memory_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        offset => StackUInt::N_OPRAND_CELLS,
        mem_bytes => EVM_STACK_BYTE_WIDTH,
        old_stack_ts_offset => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt_offset => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,
        old_stack_ts_value => TSUInt::N_OPRAND_CELLS,
        old_stack_ts_lt_value => UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS
    }
);

impl MstoreInstruction {
    const OPCODE: OpcodeType = OpcodeType::MSTORE;
}

impl<E: ExtensionField> Instruction<E> for MstoreInstruction {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut ram_handler = RAMHandler::new(&challenges);
        let mut rom_handler = ROMHandler::new(&challenges);

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = TSUInt::try_from(&phase0[Self::phase0_memory_ts()])?;
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        ram_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            memory_ts.values(),
            stack_top,
            clk,
        );

        let next_pc =
            ROMHandler::add_pc_const(&mut circuit_builder, &pc, 1, &phase0[Self::phase0_pc_add()])?;
        let next_memory_ts = rom_handler.add_ts_with_const(
            &mut circuit_builder,
            &memory_ts,
            1,
            &phase0[Self::phase0_memory_ts_add()],
        )?;
        ram_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            stack_ts.values(),
            next_memory_ts.values(),
            stack_top_expr,
            clk_expr.add(E::BaseField::ONE),
        );

        rom_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
        )?;

        // Pop offset from stack
        let offset = StackUInt::try_from(&phase0[Self::phase0_offset()])?;
        let old_stack_ts_offset = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts_offset()])?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts_offset,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_offset()],
        )?;
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::ONE),
            old_stack_ts_offset.values(),
            offset.values(),
        );

        // Pop mem_bytes from stack
        let mem_bytes = &phase0[Self::phase0_mem_bytes()];
        rom_handler.range_check_bytes(&mut circuit_builder, mem_bytes)?;

        let mem_value = StackUInt::from_bytes_big_endien(&mut circuit_builder, &mem_bytes)?;
        let old_stack_ts_value = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts_value()])?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts_value,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_value()],
        )?;
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
            old_stack_ts_value.values(),
            mem_value.values(),
        );

        // Bytecode check for (pc, mstore)
        rom_handler.bytecode_with_pc_opcode(&mut circuit_builder, pc.values(), Self::OPCODE);

        // To accessory
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
            offset.values(),
        );

        let (to_acc_ooo_id, to_acc_ooo) = circuit_builder
            .create_witness_out(MstoreAccessory::pred_ooo_size() * EVM_STACK_BYTE_WIDTH);
        add_assign_each_cell(&mut circuit_builder, &to_acc_ooo, mem_bytes);

        let (ram_load_id, ram_store_id) = ram_handler.finalize(&mut circuit_builder);
        let rom_id = rom_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [ram_load_id, ram_store_id, rom_id];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: vec![phase0_wire_id],
                succ_dup_wires_id: vec![to_acc_dup_id],
                succ_ooo_wires_id: vec![to_acc_ooo_id],
                ..Default::default()
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
        mem_bytes => 1
    },
    phase0 {
        old_memory_ts => TSUInt::N_OPRAND_CELLS,
        old_memory_ts_lt =>  UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        offset_add_delta => UIntAddSub::<StackUInt>::N_WITNESS_CELLS,
        prev_mem_bytes => 1
    }
);

impl<E: ExtensionField> Instruction<E> for MstoreAccessory {
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
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
        let offset_plus_delta = UIntAddSub::<StackUInt>::add_small(
            &mut circuit_builder,
            &mut rom_handler,
            &offset,
            delta,
            offset_add_delta,
        )?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_memory_ts,
            &memory_ts,
            old_memory_ts_lt,
        )?;

        let mem_byte = pred_ooo[Self::pred_ooo_mem_bytes().start];
        let prev_mem_byte = phase0[Self::phase0_prev_mem_bytes().start];
        ram_handler.mem_store(
            &mut circuit_builder,
            offset_plus_delta.values(),
            old_memory_ts.values(),
            memory_ts.values(),
            prev_mem_byte,
            mem_byte,
        );

        let (ram_load_id, ram_store_id) = ram_handler.finalize(&mut circuit_builder);
        let rom_id = rom_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [ram_load_id, ram_store_id, rom_id];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: vec![phase0_wire_id],
                pred_dup_wire_id: Some(pred_dup_wire_id),
                pred_ooo_wire_id: Some(pred_ooo_wire_id),
                ..Default::default()
            },
        })
    }
}
