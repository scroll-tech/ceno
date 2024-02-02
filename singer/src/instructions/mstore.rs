use ff::Field;
use gkr::structs::Circuit;
use gkr_graph::structs::{NodeOutputType, PredType};
use goldilocks::SmallField;

use revm_interpreter::Record;
use revm_primitives::U256;

use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use std::{mem, sync::Arc};

use crate::utils::uint::{u256_to_fvec, u2fvec};
use crate::{
    constants::{OpcodeType, EVM_STACK_BYTE_WIDTH},
    error::ZKVMError,
    instructions::InstCircuitLayout,
    utils::{
        add_assign_each_cell,
        chip_handler::{
            BytecodeChipOperations, ChipHandler, GlobalStateChipOperations, MemoryChipOperations,
            RangeChipOperations, StackChipOperations,
        },
        uint::{PCUInt, StackUInt, TSUInt, UIntAddSub, UIntCmp},
    },
    CircuitWiresIn, SingerParams,
};

use super::{ChipChallenges, InstCircuit, Instruction, InstructionGraph};

pub struct MstoreInstruction;

impl InstructionGraph for MstoreInstruction {
    type InstType = Self;

    fn construct_circuits<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<Vec<InstCircuit<F>>, ZKVMError> {
        let circuits = vec![
            MstoreInstruction::construct_circuit::<F>(challenges)?,
            MstoreAccessory::construct_circuit::<F>(challenges)?,
        ];
        Ok(circuits)
    }

    fn construct_circuit_graph<F: SmallField>(
        graph_builder: &mut gkr_graph::structs::CircuitGraphBuilder<F>,
        chip_builder: &mut crate::chips::SingerChipBuilder<F>,
        inst_circuits: &[InstCircuit<F>],
        mut sources: Vec<CircuitWiresIn<F::BaseField>>,
        real_challenges: &[F],
        real_n_instances: usize,
        _: SingerParams,
    ) -> Result<Option<NodeOutputType>, ZKVMError> {
        // Add the instruction circuit to the graph.
        let inst_circuit = &inst_circuits[0];
        let n_wires_in = inst_circuit.circuit.n_wires_in;
        let inst_node_id = graph_builder.add_node_with_witness(
            stringify!(ReturnInstruction),
            &inst_circuit.circuit,
            vec![PredType::Source; n_wires_in],
            real_challenges.to_vec(),
            mem::take(&mut sources[0]),
        )?;
        chip_builder.construct_chip_checks(
            graph_builder,
            inst_node_id,
            &inst_circuit.layout.chip_check_wire_id,
            real_challenges,
            real_n_instances,
        )?;

        let mstore_acc_circuit = &inst_circuits[1];
        let n_wires_in = mstore_acc_circuit.circuit.n_wires_in;
        let mut preds = vec![PredType::Source; n_wires_in];
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
        )?;
        chip_builder.construct_chip_checks(
            graph_builder,
            mstore_acc_node_id,
            &mstore_acc_circuit.layout.chip_check_wire_id,
            real_challenges,
            real_n_instances * 32,
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

impl Instruction for MstoreInstruction {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let mut global_state_in_handler = ChipHandler::new(challenges.global_state());
        let mut global_state_out_handler = ChipHandler::new(challenges.global_state());
        let mut bytecode_chip_handler = ChipHandler::new(challenges.bytecode());
        let mut stack_pop_handler = ChipHandler::new(challenges.stack());
        let mut range_chip_handler = ChipHandler::new(challenges.range());

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = TSUInt::try_from(&phase0[Self::phase0_memory_ts()])?;
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            memory_ts.values(),
            stack_top,
            clk,
        );

        let next_pc = ChipHandler::add_pc_const(
            &mut circuit_builder,
            &pc,
            1,
            &phase0[Self::phase0_pc_add()],
        )?;
        let next_memory_ts = range_chip_handler.add_ts_with_const(
            &mut circuit_builder,
            &memory_ts,
            1,
            &phase0[Self::phase0_memory_ts_add()],
        )?;
        global_state_out_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            stack_ts.values(),
            next_memory_ts.values(),
            stack_top_expr,
            clk_expr.add(F::BaseField::ONE),
        );

        range_chip_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
        )?;

        // Pop offset from stack
        let offset = StackUInt::try_from(&phase0[Self::phase0_offset()])?;
        let old_stack_ts_offset = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts_offset()])?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_offset,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_offset()],
        )?;
        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::ONE),
            old_stack_ts_offset.values(),
            offset.values(),
        );

        // Pop mem_bytes from stack
        let mem_bytes = &phase0[Self::phase0_mem_bytes()];
        range_chip_handler.range_check_bytes(&mut circuit_builder, mem_bytes)?;

        let mem_value = StackUInt::from_bytes_big_endien(&mut circuit_builder, &mem_bytes)?;
        let old_stack_ts_value = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts_value()])?;
        UIntCmp::<TSUInt>::assert_lt(
            &mut circuit_builder,
            &mut range_chip_handler,
            &old_stack_ts_value,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_value()],
        )?;
        stack_pop_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(F::BaseField::from(2)),
            old_stack_ts_value.values(),
            mem_value.values(),
        );

        // Bytecode check for (pc, mstore)
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );

        // To accessory
        let (to_acc_dup_id, to_acc_dup) =
            circuit_builder.create_wire_out(MstoreAccessory::pred_dup_size());
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
            .create_wire_out(MstoreAccessory::pred_ooo_size() * EVM_STACK_BYTE_WIDTH);
        add_assign_each_cell(&mut circuit_builder, &to_acc_ooo, mem_bytes);

        let global_state_in_id = global_state_in_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let global_state_out_id = global_state_out_handler
            .finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let bytecode_chip_id =
            bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        let stack_pop_id =
            stack_pop_handler.finalize_with_const_pad(&mut circuit_builder, F::BaseField::ONE);
        let range_chip_id = range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);

        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_id),
            Some(global_state_out_id),
            Some(bytecode_chip_id),
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
                succ_dup_wires_id: vec![to_acc_dup_id],
                succ_ooo_wires_id: vec![to_acc_ooo_id],
                ..Default::default()
            },
        })
    }

    fn generate_pre_wires_in<F: SmallField>(record: &Record, index: usize) -> Option<Vec<F>> {
        match index {
            0 => {
                let mut wire_values = vec![F::ZERO; Self::phase0_size()];
                copy_pc_from_record!(wire_values, record);
                copy_stack_ts_from_record!(wire_values, record);
                copy_memory_ts_from_record!(wire_values, record);
                copy_stack_top_from_record!(wire_values, record);
                copy_clock_from_record!(wire_values, record);
                copy_pc_add_from_record!(wire_values, record);
                copy_memory_ts_add_from_record!(wire_values, record);
                copy_stack_ts_lt_from_record!(
                    wire_values,
                    record,
                    phase0_old_stack_ts_offset,
                    phase0_old_stack_ts_lt_offset,
                    0
                );
                copy_stack_ts_lt_from_record!(
                    wire_values,
                    record,
                    phase0_old_stack_ts_value,
                    phase0_old_stack_ts_lt_value,
                    0
                );
                // The memory value timestamps are stored starting from the third cell
                // copy_memory_ts_lt_from_record!(wire_values, record, 2);
                copy_operand_from_record!(wire_values, record, phase0_offset, 0);
                // for offset in 0..EVM_STACK_BYTE_WIDTH {
                //     copy_range_values_from_u256!(
                //         wire_values,
                //         phase0_offset_add_i_plus_1,
                //         record.operands[0] + U256::from(offset),
                //         offset
                //     );
                //     copy_carry_values_from_addends!(
                //         wire_values,
                //         phase0_offset_add_i_plus_1,
                //         record.operands[0],
                //         U256::from(offset)
                //     );
                // }
                wire_values[Self::phase0_mem_bytes()].copy_from_slice(&u256_to_fvec::<
                    F,
                    { StackUInt::BIT_SIZE },
                    8,
                >(
                    record.operands[1]
                ));
                // wire_values[Self::phase0_prev_mem_bytes()].copy_from_slice(&u256_to_fvec::<
                //     F,
                //     { StackUInt::BIT_SIZE },
                //     8,
                // >(
                //     record.operands[2]
                // ));

                Some(wire_values)
            }
            _ => None,
        }
    }
    fn complete_wires_in<F: SmallField>(
        pre_wires_in: &CircuitWiresIn<F>,
        _challenges: &Vec<F>,
    ) -> CircuitWiresIn<F> {
        // Currently the memory timestamp only takes one element, so no need to do anything
        // and no need to use the challenges.
        pre_wires_in.clone()
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
        old_memory_ts => EVM_STACK_BYTE_WIDTH * TSUInt::N_OPRAND_CELLS,
        old_memory_ts_lt => EVM_STACK_BYTE_WIDTH * UIntCmp::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        offset_add_delta => UIntAddSub::<StackUInt>::N_WITNESS_CELLS,
        prev_mem_bytes => EVM_STACK_BYTE_WIDTH
    }
);

impl Instruction for MstoreAccessory {
    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();

        // From predesessor circuit.
        let (pred_dup_wire_id, pred_dup) = circuit_builder.create_wire_in(Self::pred_dup_size());
        let (pred_ooo_wire_id, pred_ooo) = circuit_builder.create_wire_in(Self::pred_ooo_size());

        // From witness.
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());

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

        let mem_byte = pred_ooo[Self::pred_ooo_mem_bytes().start];
        let prev_mem_byte = phase0[Self::phase0_prev_mem_bytes().start];
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
        let outputs_wire_id = [
            None,
            None,
            None,
            None,
            None,
            Some(range_chip_id),
            Some(memory_load_id),
            Some(memory_store_id),
            None,
        ];

        circuit_builder.configure();

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

    fn generate_pre_wires_in<F: SmallField>(record: &Record, index: usize) -> Option<Vec<F>> {
        todo!()
    }

    fn complete_wires_in<F: SmallField>(
        pre_wires_in: &CircuitWiresIn<F>,
        challenges: &Vec<F>,
    ) -> CircuitWiresIn<F> {
        todo!()
    }
}
