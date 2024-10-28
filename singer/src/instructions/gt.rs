use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        ChipHandler, bytecode::BytecodeChip, global_state::GlobalStateChip, range::RangeChip,
        stack::StackChip,
    },
    constants::OpcodeType,
    register_witness,
    structs::{PCUInt, StackUInt, TSUInt},
    uint::constants::AddSubConstants,
};
use std::{collections::BTreeMap, sync::Arc};

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct GtInstruction;

impl<E: ExtensionField> InstructionGraph<E> for GtInstruction {
    type InstType = Self;
}

register_witness!(
    GtInstruction,
    phase0 {
        pc => PCUInt::N_OPERAND_CELLS,
        stack_ts => TSUInt::N_OPERAND_CELLS,
        memory_ts => TSUInt::N_OPERAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => AddSubConstants::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        stack_ts_add => AddSubConstants::<TSUInt>::N_WITNESS_CELLS_NO_CARRY_OVERFLOW,

        old_stack_ts0 => TSUInt::N_OPERAND_CELLS,
        old_stack_ts_lt0 => AddSubConstants::<TSUInt>::N_WITNESS_CELLS,
        old_stack_ts1 => TSUInt::N_OPERAND_CELLS,
        old_stack_ts_lt1 => AddSubConstants::<TSUInt>::N_WITNESS_CELLS,

        oprand_0 => StackUInt::N_OPERAND_CELLS,
        oprand_1 => StackUInt::N_OPERAND_CELLS,
        instruction_gt => AddSubConstants::<StackUInt>::N_WITNESS_CELLS
    }
);

impl<E: ExtensionField> Instruction<E> for GtInstruction {
    const OPCODE: OpcodeType = OpcodeType::GT;
    const NAME: &'static str = "GT";
    fn construct_circuit(challenges: ChipChallenges) -> InstCircuit<E> {
        let mut circuit_builder = CircuitBuilder::default();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        let mut chip_handler = ChipHandler::new(challenges);

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()]).unwrap();
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()]).unwrap();
        let memory_ts = &phase0[Self::phase0_memory_ts()];
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        GlobalStateChip::state_in(
            &mut chip_handler,
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            memory_ts,
            stack_top,
            clk,
        );

        let next_pc =
            RangeChip::add_pc_const(&mut circuit_builder, &pc, 1, &phase0[Self::phase0_pc_add()]);
        let next_stack_ts = RangeChip::add_ts_with_const(
            &mut chip_handler,
            &mut circuit_builder,
            &stack_ts,
            1,
            &phase0[Self::phase0_stack_ts_add()],
        );

        GlobalStateChip::state_out(
            &mut chip_handler,
            &mut circuit_builder,
            next_pc.values(),
            next_stack_ts.values(),
            memory_ts,
            stack_top_expr.sub(E::BaseField::from(1)),
            clk_expr.add(E::BaseField::ONE),
        );

        // Execution result = addend0 + addend1, with carry.
        let oprand_0 = (&phase0[Self::phase0_oprand_0()]).try_into().unwrap();
        let oprand_1 = (&phase0[Self::phase0_oprand_1()]).try_into().unwrap();
        let (result, _) = StackUInt::lt(
            &mut circuit_builder,
            &mut chip_handler,
            &oprand_1,
            &oprand_0,
            &phase0[Self::phase0_instruction_gt()],
        );

        // Check the range of stack_top - 2 is within [0, 1 << STACK_TOP_BIT_WIDTH).
        RangeChip::range_check_stack_top(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
        );

        // Pop two values from stack
        let old_stack_ts0 = (&phase0[Self::phase0_old_stack_ts0()]).try_into().unwrap();
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut chip_handler,
            &old_stack_ts0,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt0()],
        );
        StackChip::pop(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(1)),
            old_stack_ts0.values(),
            oprand_0.values(),
        );

        let old_stack_ts1 = (&phase0[Self::phase0_old_stack_ts1()]).try_into().unwrap();
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut chip_handler,
            &old_stack_ts1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt1()],
        );
        StackChip::pop(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
            old_stack_ts1.values(),
            oprand_1.values(),
        );

        // Push one result to stack. Since values are little-endien, it is
        // equivalent to pad result with 0s.
        StackChip::push(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
            stack_ts.values(),
            &[result],
        );

        // Bytecode check for (pc, gt)
        BytecodeChip::bytecode_with_pc_opcode(
            &mut chip_handler,
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<E>>::OPCODE,
        );

        let (ram_load_id, ram_store_id, rom_id) = chip_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [ram_load_id, ram_store_id, rom_id];

        InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: vec![phase0_wire_id],
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(not(debug_assertions))]
    use crate::{
        CircuitWiresIn, SingerGraphBuilder, SingerParams, instructions::InstructionGraph,
        instructions::SingerCircuitBuilder, scheme::GKRGraphProverState,
    };
    #[cfg(not(debug_assertions))]
    use ark_std::test_rng;
    #[cfg(not(debug_assertions))]
    use ff::Field;
    #[cfg(not(debug_assertions))]
    use ff_ext::ExtensionField;
    #[cfg(not(debug_assertions))]
    use std::time::Instant;
    #[cfg(not(debug_assertions))]
    use transcript::Transcript;

    use goldilocks::{Goldilocks, GoldilocksExt2};
    use singer_utils::{constants::RANGE_CHIP_BIT_WIDTH, structs::TSUInt};
    use std::collections::BTreeMap;

    #[allow(deprecated)]
    use crate::test::test_opcode_circuit;
    use crate::{
        instructions::{ChipChallenges, GtInstruction, Instruction},
        test::get_uint_params,
        utils::u64vec,
    };

    #[test]
    fn test_gt_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = GtInstruction::phase0_idxes_map();
        let phase0_witness_size = GtInstruction::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("GT {:?}", &phase0_idx_map);
            println!("GT witness_size {:?}", &phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = GtInstruction::construct_circuit(challenges);

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_ts".to_string(), vec![Goldilocks::from(3u64)]);
        phase0_values_map.insert("phase0_memory_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_top".to_string(), vec![Goldilocks::from(
            100u64,
        )]);
        phase0_values_map.insert("phase0_clk".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_pc_add".to_string(),
            vec![], // carry is 0, may test carry using larger values in PCUInt
        );
        phase0_values_map.insert("phase0_stack_ts_add".to_string(), vec![
            Goldilocks::from(4u64), /* first TSUInt::N_RANGE_CELLS = 1*(56/16) = 4 cells are
                                     * range values, stack_ts + 1 = 4 */
            Goldilocks::from(0u64),
            Goldilocks::from(0u64),
            Goldilocks::from(0u64),
            // no place for carry
        ]);
        phase0_values_map.insert("phase0_old_stack_ts0".to_string(), vec![Goldilocks::from(
            2u64,
        )]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert("phase0_old_stack_ts_lt0".to_string(), vec![
            Goldilocks::from(range_values[0]),
            Goldilocks::from(range_values[1]),
            Goldilocks::from(range_values[2]),
            Goldilocks::from(1u64),
        ]);
        phase0_values_map.insert("phase0_old_stack_ts1".to_string(), vec![Goldilocks::from(
            1u64,
        )]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 2;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert("phase0_old_stack_ts_lt1".to_string(), vec![
            Goldilocks::from(range_values[0]),
            Goldilocks::from(range_values[1]),
            Goldilocks::from(range_values[2]),
            Goldilocks::from(1u64),
        ]);
        phase0_values_map.insert("phase0_oprand_0".to_string(), vec![Goldilocks::from(2u64)]);
        phase0_values_map.insert("phase0_oprand_1".to_string(), vec![Goldilocks::from(1u64)]);
        // given borrow = [1,1,1,1,1,1,1,1]
        // oprand_1 - oprand_0 is vec![2^32-1; 8]
        // its range value is vec![2^16-1; 16]
        let range_values = vec![Goldilocks::from(65535u64); 16];
        let borrow = vec![Goldilocks::from(1u64); 8];
        phase0_values_map.insert(
            "phase0_instruction_gt".to_string(),
            [range_values.as_slice(), borrow.as_slice()].concat(),
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
    fn bench_gt_instruction_helper<E: ExtensionField>(instance_num_vars: usize) {
        let chip_challenges = ChipChallenges::default();
        let circuit_builder = SingerCircuitBuilder::<E>::new(chip_challenges);
        let mut singer_builder = SingerGraphBuilder::<E>::default();

        let mut rng = test_rng();
        let size = GtInstruction::phase0_size();
        let phase0: CircuitWiresIn<E> = vec![
            (0..(1 << instance_num_vars))
                .map(|_| {
                    (0..size)
                        .map(|_| E::BaseField::random(&mut rng))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
                .into(),
        ];

        let real_challenges = vec![E::random(&mut rng), E::random(&mut rng)];

        let timer = Instant::now();

        let _ = GtInstruction::construct_graph_and_witness(
            &mut singer_builder.graph_builder,
            &mut singer_builder.chip_builder,
            &circuit_builder.insts_circuits[<GtInstruction as Instruction<E>>::OPCODE as usize],
            vec![phase0],
            &real_challenges,
            1 << instance_num_vars,
            &SingerParams::default(),
        );

        let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

        println!(
            "GtInstruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
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
            "GtInstruction::prove, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn bench_gt_instruction() {
        bench_gt_instruction_helper::<GoldilocksExt2>(10);
    }
}
