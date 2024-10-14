use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use gkr_graph::structs::{CircuitGraphBuilder, NodeOutputType, PredType};
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        bytecode::BytecodeChip, global_state::GlobalStateChip, memory::MemoryChip,
        range::RangeChip, stack::StackChip, ChipHandler,
    },
    chips::SingerChipBuilder,
    constants::{OpcodeType, EVM_STACK_BYTE_WIDTH},
    register_witness,
    structs::{PCUInt, StackUInt, TSUInt},
    uint::constants::AddSubConstants,
};
use std::{collections::BTreeMap, mem, sync::Arc};

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
        mut sources: Vec<CircuitWiresIn<E>>,
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
        pc => PCUInt::N_OPERAND_CELLS,
        stack_ts => TSUInt::N_OPERAND_CELLS,
        memory_ts => TSUInt::N_OPERAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => AddSubConstants::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        memory_ts_add => AddSubConstants::<TSUInt>::N_WITNESS_CELLS_NO_CARRY_OVERFLOW,

        offset => StackUInt::N_OPERAND_CELLS,
        mem_bytes => EVM_STACK_BYTE_WIDTH,
        old_stack_ts_offset => TSUInt::N_OPERAND_CELLS,
        old_stack_ts_lt_offset => AddSubConstants::<TSUInt>::N_WITNESS_CELLS,
        old_stack_ts_value => TSUInt::N_OPERAND_CELLS,
        old_stack_ts_lt_value => AddSubConstants::<TSUInt>::N_WITNESS_CELLS
    }
);

impl<E: ExtensionField> Instruction<E> for MstoreInstruction {
    const OPCODE: OpcodeType = OpcodeType::MSTORE;
    const NAME: &'static str = "MSTORE";
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::default();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        let mut chip_handler = ChipHandler::new(challenges);

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = TSUInt::try_from(&phase0[Self::phase0_memory_ts()])?;
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        GlobalStateChip::state_in(
            &mut chip_handler,
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            memory_ts.values(),
            stack_top,
            clk,
        );

        let next_pc =
            RangeChip::add_pc_const(&mut circuit_builder, &pc, 1, &phase0[Self::phase0_pc_add()])?;
        let next_memory_ts = RangeChip::add_ts_with_const(
            &mut chip_handler,
            &mut circuit_builder,
            &memory_ts,
            1,
            &phase0[Self::phase0_memory_ts_add()],
        )?;
        GlobalStateChip::state_out(
            &mut chip_handler,
            &mut circuit_builder,
            next_pc.values(),
            stack_ts.values(),
            next_memory_ts.values(),
            stack_top_expr,
            clk_expr.add(E::BaseField::ONE),
        );

        RangeChip::range_check_stack_top(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
        )?;

        // Pop offset from stack
        let offset = StackUInt::try_from(&phase0[Self::phase0_offset()])?;
        let old_stack_ts_offset = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts_offset()])?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut chip_handler,
            &old_stack_ts_offset,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_offset()],
        )?;
        StackChip::pop(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::ONE),
            old_stack_ts_offset.values(),
            offset.values(),
        );

        // Pop mem_bytes from stack
        let mem_bytes = &phase0[Self::phase0_mem_bytes()];
        RangeChip::range_check_bytes(&mut chip_handler, &mut circuit_builder, mem_bytes)?;

        let mem_value = StackUInt::from_bytes_big_endian(&mut circuit_builder, mem_bytes)?;
        let old_stack_ts_value = TSUInt::try_from(&phase0[Self::phase0_old_stack_ts_value()])?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut chip_handler,
            &old_stack_ts_value,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt_value()],
        )?;
        StackChip::pop(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
            old_stack_ts_value.values(),
            mem_value.values(),
        );

        // Bytecode check for (pc, mstore)
        BytecodeChip::bytecode_with_pc_opcode(
            &mut chip_handler,
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<E>>::OPCODE,
        );

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

        let (ram_load_id, ram_store_id, rom_id) = chip_handler.finalize(&mut circuit_builder);
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
        memory_ts => TSUInt::N_OPERAND_CELLS,
        offset => StackUInt::N_OPERAND_CELLS
    },
    pred_ooo {
        mem_bytes => 1
    },
    phase0 {
        old_memory_ts => TSUInt::N_OPERAND_CELLS,
        old_memory_ts_lt =>  AddSubConstants::<TSUInt>::N_WITNESS_CELLS,

        offset_add_delta => AddSubConstants::<StackUInt>::N_WITNESS_CELLS,
        prev_mem_bytes => 1
    }
);

impl MstoreAccessory {
    fn construct_circuit<E: ExtensionField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::default();

        // From predesessor circuit.
        let (pred_dup_wire_id, pred_dup) = circuit_builder.create_witness_in(Self::pred_dup_size());
        let (pred_ooo_wire_id, pred_ooo) = circuit_builder.create_witness_in(Self::pred_ooo_size());

        // From witness.
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        let mut chip_handler = ChipHandler::new(challenges);

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
            &mut chip_handler,
            &offset,
            delta,
            offset_add_delta,
        )?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut chip_handler,
            &old_memory_ts,
            &memory_ts,
            old_memory_ts_lt,
        )?;

        let mem_byte = pred_ooo[Self::pred_ooo_mem_bytes().start];
        let prev_mem_byte = phase0[Self::phase0_prev_mem_bytes().start];
        MemoryChip::write(
            &mut chip_handler,
            &mut circuit_builder,
            offset_plus_delta.values(),
            old_memory_ts.values(),
            memory_ts.values(),
            prev_mem_byte,
            mem_byte,
        );

        let (ram_load_id, ram_store_id, rom_id) = chip_handler.finalize(&mut circuit_builder);
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

#[cfg(test)]
mod test {
    #[cfg(not(debug_assertions))]
    use super::MstoreAccessory;
    use crate::utils::u64vec;
    #[cfg(not(debug_assertions))]
    use crate::{
        instructions::{InstructionGraph, SingerCircuitBuilder},
        scheme::GKRGraphProverState,
        CircuitWiresIn, SingerGraphBuilder, SingerParams,
    };
    #[cfg(not(debug_assertions))]
    use ark_std::test_rng;
    #[cfg(not(debug_assertions))]
    use ff::Field;
    #[cfg(not(debug_assertions))]
    use ff_ext::ExtensionField;
    use goldilocks::GoldilocksExt2;
    #[cfg(not(debug_assertions))]
    use multilinear_extensions::mle::DenseMultilinearExtension;
    use singer_utils::structs::ChipChallenges;
    #[cfg(not(debug_assertions))]
    use std::time::Instant;
    #[cfg(not(debug_assertions))]
    use transcript::Transcript;

    use crate::instructions::{mstore::MstoreInstruction, Instruction};

    use crate::test::get_uint_params;
    #[allow(deprecated)]
    use crate::test::test_opcode_circuit;
    use goldilocks::Goldilocks;
    use singer_utils::{constants::RANGE_CHIP_BIT_WIDTH, structs::TSUInt};
    use std::collections::BTreeMap;

    #[test]
    fn test_mstore_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = MstoreInstruction::phase0_idxes_map();
        let phase0_witness_size = MstoreInstruction::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("MSTORE: {:?}", &phase0_idx_map);
            println!("MSTORE witness_size: {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with opcode
        let inst_circuit = MstoreInstruction::construct_circuit(challenges).unwrap();

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_ts".to_string(), vec![Goldilocks::from(3u64)]);
        phase0_values_map.insert("phase0_memory_ts".to_string(), vec![Goldilocks::from(3u64)]);
        phase0_values_map.insert(
            "phase0_stack_top".to_string(),
            vec![Goldilocks::from(100u64)],
        );
        phase0_values_map.insert("phase0_clk".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_pc_add".to_string(),
            vec![], // carry is 0, may test carry using larger values in PCUInt
        );
        phase0_values_map.insert(
            "phase0_memory_ts_add".to_string(),
            vec![
                Goldilocks::from(4u64), /* first TSUInt::N_RANGE_CELLS = 1*(56/16) = 4 cells are
                                         * range values, memory_ts + 1 = 4 */
                Goldilocks::from(0u64),
                Goldilocks::from(0u64),
                Goldilocks::from(0u64),
                // no place for carry
            ],
        );
        phase0_values_map.insert("phase0_offset".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_old_stack_ts_offset".to_string(),
            vec![Goldilocks::from(2u64)],
        );
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            "phase0_old_stack_ts_lt_offset".to_string(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(1u64), // borrow
            ],
        );
        phase0_values_map.insert(
            "phase0_mem_bytes".to_string(),
            vec![], // use 32-byte 0 for mem_bytes
        );
        phase0_values_map.insert(
            "phase0_old_stack_ts_value".to_string(),
            vec![Goldilocks::from(1u64)],
        );
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 2;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            "phase0_old_stack_ts_lt_value".to_string(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                Goldilocks::from(1u64), // borrow
            ],
        );

        let circuit_witness_challenges = vec![
            GoldilocksExt2::from(2),
            GoldilocksExt2::from(2),
            GoldilocksExt2::from(2),
        ];

        #[allow(deprecated)]
        let _circuit_witness = test_opcode_circuit(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
            circuit_witness_challenges,
        );
    }

    #[cfg(not(debug_assertions))]
    fn bench_mstore_instruction_helper<E: ExtensionField>(instance_num_vars: usize) {
        let chip_challenges = ChipChallenges::default();
        let circuit_builder =
            SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
        let mut singer_builder = SingerGraphBuilder::<E>::default();

        let mut rng = test_rng();
        let inst_phase0_size = MstoreInstruction::phase0_size();
        let inst_wit: CircuitWiresIn<E> = vec![
            (0..(1 << instance_num_vars))
                .map(|_| {
                    (0..inst_phase0_size)
                        .map(|_| E::BaseField::random(&mut rng))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
                .into(),
        ];
        let acc_phase0_size = MstoreAccessory::phase0_size();
        let acc_wit: CircuitWiresIn<E> = vec![
            DenseMultilinearExtension::default(),
            DenseMultilinearExtension::default(),
            (0..(1 << instance_num_vars) * 32)
                .map(|_| {
                    (0..acc_phase0_size)
                        .map(|_| E::BaseField::random(&mut rng))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
                .into(),
        ];

        let real_challenges = vec![E::random(&mut rng), E::random(&mut rng)];

        let timer = Instant::now();

        let _ = MstoreInstruction::construct_graph_and_witness(
            &mut singer_builder.graph_builder,
            &mut singer_builder.chip_builder,
            &circuit_builder.insts_circuits[<MstoreInstruction as Instruction<E>>::OPCODE as usize],
            vec![inst_wit, acc_wit],
            &real_challenges,
            1 << instance_num_vars,
            &SingerParams::default(),
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

        println!(
            "MstoreInstruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );

        let point = vec![E::random(&mut rng), E::random(&mut rng)];
        let target_evals = graph.target_evals(&wit, &point);

        let prover_transcript = &mut Transcript::new(b"Singer");

        let timer = Instant::now();
        let _ = GKRGraphProverState::prove(&graph, &wit, &target_evals, prover_transcript, 1)
            .expect("prove failed");
        println!(
            "MstoreInstruction::prove, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn bench_mstore_instruction() {
        bench_mstore_instruction_helper::<GoldilocksExt2>(5);
    }
}
