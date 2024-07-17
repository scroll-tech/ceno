use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        BytecodeChipOperations, GlobalStateChipOperations, OAMOperations, ROMOperations,
        RangeChipOperations, StackChipOperations,
    },
    constants::OpcodeType,
    register_witness,
    structs::{PCUInt, RAMHandler, ROMHandler, StackUInt, TSUInt},
    uint::constants::AddSubConstants,
};
use std::{collections::BTreeMap, sync::Arc};

use crate::error::ZKVMError;

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct DupInstruction<const N: usize>;

impl<E: ExtensionField, const N: usize> InstructionGraph<E> for DupInstruction<N> {
    type InstType = Self;
}

register_witness!(
    DupInstruction<N>,
    phase0 {
        pc => PCUInt::N_OPERAND_CELLS,
        stack_ts => TSUInt::N_OPERAND_CELLS,
        memory_ts => TSUInt::N_OPERAND_CELLS,
        stack_top => 1,
        clk => 1,

        pc_add => AddSubConstants::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        stack_ts_add => AddSubConstants::<TSUInt>::N_WITNESS_CELLS_NO_CARRY_OVERFLOW,

        stack_values => StackUInt::N_OPERAND_CELLS,
        old_stack_ts => TSUInt::N_OPERAND_CELLS,
        old_stack_ts_lt => AddSubConstants::<TSUInt>::N_WITNESS_CELLS
    }
);

impl<E: ExtensionField, const N: usize> Instruction<E> for DupInstruction<N> {
    const OPCODE: OpcodeType = match N {
        1 => OpcodeType::DUP1,
        2 => OpcodeType::DUP2,
        _ => unimplemented!(),
    };
    const NAME: &'static str = match N {
        1 => "DUP1",
        2 => "DUP2",
        _ => unimplemented!(),
    };
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<E>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut ram_handler = RAMHandler::new(&challenges);
        let mut rom_handler = ROMHandler::new(&challenges);

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = &phase0[Self::phase0_memory_ts()];
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        ram_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            &memory_ts,
            stack_top,
            clk,
        );

        let next_pc =
            ROMHandler::add_pc_const(&mut circuit_builder, &pc, 1, &phase0[Self::phase0_pc_add()])?;
        let next_stack_ts = rom_handler.add_ts_with_const(
            &mut circuit_builder,
            &stack_ts,
            1,
            &phase0[Self::phase0_stack_ts_add()],
        )?;

        ram_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            next_stack_ts.values(),
            &memory_ts,
            stack_top_expr.add(E::BaseField::from(1)),
            clk_expr.add(E::BaseField::ONE),
        );

        // Check the range of stack_top - N is within [0, 1 << STACK_TOP_BIT_WIDTH).
        rom_handler.range_check_stack_top(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(N as u64)),
        )?;

        // Pop rlc of stack[top - N] from stack
        let old_stack_ts = (&phase0[Self::phase0_old_stack_ts()]).try_into()?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt()],
        )?;
        let stack_values = &phase0[Self::phase0_stack_values()];
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(1)),
            old_stack_ts.values(),
            stack_values,
        );

        // Check the range of stack_top within [0, 1 << STACK_TOP_BIT_WIDTH).
        rom_handler.range_check_stack_top(&mut circuit_builder, stack_top.into())?;
        // Push stack_values twice to stack
        ram_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(1)),
            stack_ts.values(),
            stack_values,
        );
        ram_handler.stack_push(
            &mut circuit_builder,
            stack_top_expr,
            stack_ts.values(),
            stack_values,
        );

        // Bytecode check for (pc, DUP{N})
        rom_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<E>>::OPCODE,
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
                ..Default::default()
            },
        })
    }
}

#[cfg(test)]
mod test {
    use ark_std::test_rng;
    use ff::Field;
    use ff_ext::ExtensionField;
    use gkr::structs::LayerWitness;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use singer_utils::{constants::RANGE_CHIP_BIT_WIDTH, structs::TSUInt};
    use std::{collections::BTreeMap, time::Instant};
    use transcript::Transcript;

    use crate::{
        instructions::{
            ChipChallenges, DupInstruction, Instruction, InstructionGraph, SingerCircuitBuilder,
        },
        scheme::GKRGraphProverState,
        test::{get_uint_params, test_opcode_circuit},
        utils::u64vec,
        CircuitWiresIn, SingerGraphBuilder, SingerParams,
    };

    #[test]
    fn test_dup1_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = DupInstruction::<1>::phase0_idxes_map();
        let phase0_witness_size = DupInstruction::<1>::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("DUP1: {:?}", &phase0_idx_map);
            println!("DUP1 witness_size = {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = DupInstruction::<1>::construct_circuit(challenges).unwrap();

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_ts".to_string(), vec![Goldilocks::from(2u64)]);
        phase0_values_map.insert("phase0_memory_ts".to_string(), vec![Goldilocks::from(1u64)]);
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
            "phase0_stack_ts_add".to_string(),
            vec![
                Goldilocks::from(3u64), /* first TSUInt::N_RANGE_CELLS = 1*(56/16) = 4 cells are
                                         * range values, stack_ts + 1 = 4 */
                Goldilocks::from(0u64),
                Goldilocks::from(0u64),
                Goldilocks::from(0u64),
                // no place for carry
            ],
        );
        phase0_values_map.insert(
            "phase0_stack_values".to_string(),
            vec![
                Goldilocks::from(7u64),
                Goldilocks::from(6u64),
                Goldilocks::from(5u64),
                Goldilocks::from(4u64),
                Goldilocks::from(3u64),
                Goldilocks::from(2u64),
                Goldilocks::from(1u64),
                Goldilocks::from(0u64),
            ],
        );
        phase0_values_map.insert(
            "phase0_old_stack_ts".to_string(),
            vec![Goldilocks::from(1u64)],
        );
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            "phase0_old_stack_ts_lt".to_string(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                // Goldilocks::from(range_values[3]),
                Goldilocks::from(1u64),
            ],
        );

        let circuit_witness_challenges = vec![
            GoldilocksExt2::from(2),
            GoldilocksExt2::from(2),
            GoldilocksExt2::from(2),
        ];

        let _circuit_witness = test_opcode_circuit(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
            circuit_witness_challenges,
        );
    }

    fn bench_dup_instruction_helper<E: ExtensionField, const N: usize>(instance_num_vars: usize) {
        let chip_challenges = ChipChallenges::default();
        let circuit_builder =
            SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
        let mut singer_builder = SingerGraphBuilder::<E>::new();

        let mut rng = test_rng();
        let size = DupInstruction::<N>::phase0_size();
        let phase0: CircuitWiresIn<E::BaseField> = vec![LayerWitness {
            instances: (0..(1 << instance_num_vars))
                .map(|_| {
                    (0..size)
                        .map(|_| E::BaseField::random(&mut rng))
                        .collect_vec()
                })
                .collect_vec(),
        }];

        let real_challenges = vec![E::random(&mut rng), E::random(&mut rng)];

        let timer = Instant::now();

        let _ = DupInstruction::<N>::construct_graph_and_witness(
            &mut singer_builder.graph_builder,
            &mut singer_builder.chip_builder,
            &circuit_builder.insts_circuits[<DupInstruction<N> as Instruction<E>>::OPCODE as usize],
            vec![phase0],
            &real_challenges,
            1 << instance_num_vars,
            &SingerParams::default(),
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

        println!(
            "Dup{}Instruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
            N,
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );

        let point = vec![E::random(&mut rng), E::random(&mut rng)];
        let target_evals = graph.target_evals(&wit, &point);

        let mut prover_transcript = &mut Transcript::new(b"Singer");

        let timer = Instant::now();
        let _ = GKRGraphProverState::prove(&graph, &wit, &target_evals, &mut prover_transcript, 1)
            .expect("prove failed");
        println!(
            "Dup{}Instruction::prove, instance_num_vars = {}, time = {}",
            N,
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn bench_dup1_instruction() {
        bench_dup_instruction_helper::<GoldilocksExt2, 1>(10);
    }

    #[test]
    fn bench_dup2_instruction() {
        bench_dup_instruction_helper::<GoldilocksExt2, 2>(10);
    }
}
