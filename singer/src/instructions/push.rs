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

use crate::error::ZKVMError;

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct PushInstruction<const N: usize>;

impl<E: ExtensionField, const N: usize> InstructionGraph<E> for PushInstruction<N> {
    type InstType = Self;
}

register_witness!(
    PushInstruction<N>,
    phase0 {
        pc => PCUInt::N_OPERAND_CELLS,
        stack_ts => TSUInt::N_OPERAND_CELLS,
        memory_ts => TSUInt::N_OPERAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add_i_plus_1 => N * AddSubConstants::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        stack_ts_add => AddSubConstants::<TSUInt>::N_WITNESS_CELLS_NO_CARRY_OVERFLOW,

        stack_bytes => N
    }
);

impl<E: ExtensionField, const N: usize> Instruction<E> for PushInstruction<N> {
    const OPCODE: OpcodeType = match N {
        1 => OpcodeType::PUSH1,
        _ => unimplemented!(),
    };
    const NAME: &'static str = match N {
        1 => "PUSH1",
        _ => unimplemented!(),
    };
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::default();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());

        let mut chip_handler = ChipHandler::new(challenges);

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
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
        let next_pc = RangeChip::add_pc_const(
            &mut circuit_builder,
            &pc,
            N as i64 + 1,
            &phase0[Self::phase0_pc_add_i_plus_1()],
        )?;
        let next_stack_ts = RangeChip::add_ts_with_const(
            &mut chip_handler,
            &mut circuit_builder,
            &stack_ts,
            1,
            &phase0[Self::phase0_stack_ts_add()],
        )?;

        GlobalStateChip::state_out(
            &mut chip_handler,
            &mut circuit_builder,
            next_pc.values(),
            next_stack_ts.values(),
            memory_ts,
            stack_top_expr.add(E::BaseField::from(1)),
            clk_expr.add(E::BaseField::ONE),
        );

        // Check the range of stack_top is within [0, 1 << STACK_TOP_BIT_WIDTH).
        RangeChip::range_check_stack_top(&mut chip_handler, &mut circuit_builder, stack_top_expr)?;

        let stack_bytes = &phase0[Self::phase0_stack_bytes()];
        let stack_values = StackUInt::from_bytes_big_endian(&mut circuit_builder, stack_bytes)?;
        // Push value to stack
        StackChip::push(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr,
            stack_ts.values(),
            stack_values.values(),
        );

        // Bytecode check for (pc, PUSH{N}), (pc + 1, byte[0]), ..., (pc + N, byte[N - 1])
        BytecodeChip::bytecode_with_pc_opcode(
            &mut chip_handler,
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<E>>::OPCODE,
        );
        for (i, pc_add_i_plus_1) in phase0[Self::phase0_pc_add_i_plus_1()]
            .chunks(AddSubConstants::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS)
            .enumerate()
        {
            let next_pc =
                RangeChip::add_pc_const(&mut circuit_builder, &pc, i as i64 + 1, pc_add_i_plus_1)?;
            BytecodeChip::bytecode_with_pc_byte(
                &mut chip_handler,
                &mut circuit_builder,
                next_pc.values(),
                stack_bytes[i],
            );
        }

        let (ram_load_id, ram_store_id, rom_id) = chip_handler.finalize(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [ram_load_id, ram_store_id, rom_id];

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

#[cfg(test)]
mod test {
    #[cfg(not(debug_assertions))]
    use crate::{
        CircuitWiresIn, SingerGraphBuilder, SingerParams,
        instructions::{InstructionGraph, SingerCircuitBuilder},
        scheme::GKRGraphProverState,
    };
    #[cfg(not(debug_assertions))]
    use ark_std::test_rng;
    #[cfg(not(debug_assertions))]
    use ff::Field;
    #[cfg(not(debug_assertions))]
    use ff_ext::ExtensionField;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use std::collections::BTreeMap;
    #[cfg(not(debug_assertions))]
    use std::time::Instant;
    #[cfg(not(debug_assertions))]
    use transcript::Transcript;

    use crate::instructions::{ChipChallenges, Instruction, PushInstruction};
    #[allow(deprecated)]
    use crate::test::test_opcode_circuit;

    #[test]
    fn test_push1_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = PushInstruction::<1>::phase0_idxes_map();
        let phase0_witness_size = PushInstruction::<1>::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("PUSH1 {:?}", &phase0_idx_map);
            println!("PUSH1 witness_size = {:?}", phase0_witness_size);
        }
        // initialize general test inputs associated with push1
        let inst_circuit = PushInstruction::<1>::construct_circuit(challenges).unwrap();

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_memory_ts".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_top".to_string(), vec![Goldilocks::from(
            100u64,
        )]);
        phase0_values_map.insert("phase0_clk".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert(
            "phase0_pc_add_i_plus_1".to_string(),
            vec![], // carry is 0, may test carry using larger values in PCUInt
        );
        phase0_values_map.insert("phase0_stack_ts_add".to_string(), vec![
            Goldilocks::from(2u64), /* first TSUInt::N_RANGE_CELLS = 1*(56/16) = 4 cells are
                                     * range values, stack_ts + 1 = 4 */
            Goldilocks::from(0u64),
            Goldilocks::from(0u64),
            Goldilocks::from(0u64),
            // no place for carry
        ]);
        phase0_values_map.insert("phase0_stack_bytes".to_string(), vec![
            Goldilocks::from(0u64),
            Goldilocks::from(1u64),
            Goldilocks::from(2u64),
            Goldilocks::from(3u64),
            Goldilocks::from(4u64),
            Goldilocks::from(5u64),
            Goldilocks::from(6u64),
            Goldilocks::from(7u64),
        ]);

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
    fn bench_push_instruction_helper<E: ExtensionField, const N: usize>(instance_num_vars: usize) {
        let chip_challenges = ChipChallenges::default();
        let circuit_builder =
            SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
        let mut singer_builder = SingerGraphBuilder::<E>::default();

        let mut rng = test_rng();
        let size = PushInstruction::<N>::phase0_size();
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

        let _ = PushInstruction::<N>::construct_graph_and_witness(
            &mut singer_builder.graph_builder,
            &mut singer_builder.chip_builder,
            &circuit_builder.insts_circuits
                [<PushInstruction<N> as Instruction<E>>::OPCODE as usize],
            vec![phase0],
            &real_challenges,
            1 << instance_num_vars,
            &SingerParams::default(),
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

        println!(
            "Push{}Instruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
            N,
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
            "Push{}Instruction::prove, instance_num_vars = {}, time = {}",
            N,
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn bench_push1_instruction() {
        bench_push_instruction_helper::<GoldilocksExt2, 1>(10);
    }
}
