use std::sync::Arc;

use ff::Field;
use ff_ext::ExtensionField;
use gkr::structs::Circuit;
use paste::paste;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::uint_new::constants::AddSubConstants;
use singer_utils::{
    chip_handler::{
        BytecodeChipOperations, GlobalStateChipOperations, OAMOperations, ROMOperations,
        RangeChipOperations, StackChipOperations,
    },
    constants::OpcodeType,
    register_witness,
    structs::{PCUInt, RAMHandler, ROMHandler, TSUInt},
};

use crate::error::ZKVMError;

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct JumpInstruction;

impl<E: ExtensionField> InstructionGraph<E> for JumpInstruction {
    type InstType = Self;
}

register_witness!(
    JumpInstruction,
    phase0 {
        pc => PCUInt::N_OPERAND_CELLS,
        stack_ts => TSUInt::N_OPERAND_CELLS,
        memory_ts => TSUInt::N_OPERAND_CELLS,
        stack_top => 1,
        clk => 1,

        next_pc => PCUInt::N_OPERAND_CELLS,

        old_stack_ts => TSUInt::N_OPERAND_CELLS,
        old_stack_ts_lt => AddSubConstants::<TSUInt>::N_WITNESS_CELLS
    }
);

impl<E: ExtensionField> Instruction<E> for JumpInstruction {
    const OPCODE: OpcodeType = OpcodeType::JUMP;
    const NAME: &'static str = "JUMP";
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

        // Pop next pc from stack
        rom_handler
            .range_check_stack_top(&mut circuit_builder, stack_top_expr.sub(E::BaseField::ONE))?;

        let next_pc = &phase0[Self::phase0_next_pc()];
        let old_stack_ts = (&phase0[Self::phase0_old_stack_ts()]).try_into()?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut rom_handler,
            &old_stack_ts,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt()],
        )?;
        ram_handler.stack_pop(
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::ONE),
            old_stack_ts.values(),
            next_pc,
        );

        ram_handler.state_out(
            &mut circuit_builder,
            &next_pc,
            stack_ts.values(), // Because there is no stack push.
            &memory_ts,
            stack_top_expr.sub(E::BaseField::from(1)),
            clk_expr.add(E::BaseField::ONE),
        );

        // Bytecode check for (pc, jump)
        rom_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<E>>::OPCODE,
        );
        // Bytecode check for (next_pc, jumpdest)
        rom_handler.bytecode_with_pc_opcode(&mut circuit_builder, &next_pc, OpcodeType::JUMPDEST);

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
    use crate::instructions::{ChipChallenges, Instruction, JumpInstruction};
    use crate::test::{get_uint_params, test_opcode_circuit, u2vec};
    use ark_std::test_rng;
    use core::ops::Range;
    use ff::Field;
    use ff_ext::ExtensionField;
    use gkr::structs::LayerWitness;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use simple_frontend::structs::CellId;
    use singer_utils::constants::RANGE_CHIP_BIT_WIDTH;
    use singer_utils::structs::TSUInt;
    use std::collections::BTreeMap;
    use std::time::Instant;
    use transcript::Transcript;

    use crate::instructions::{InstructionGraph, SingerCircuitBuilder};
    use crate::scheme::GKRGraphProverState;
    use crate::{CircuitWiresIn, SingerGraphBuilder, SingerParams};

    impl JumpInstruction {
        #[inline]
        fn phase0_idxes_map() -> BTreeMap<String, Range<CellId>> {
            let mut map = BTreeMap::new();
            map.insert("phase0_pc".to_string(), Self::phase0_pc());
            map.insert("phase0_stack_ts".to_string(), Self::phase0_stack_ts());
            map.insert("phase0_memory_ts".to_string(), Self::phase0_memory_ts());
            map.insert("phase0_stack_top".to_string(), Self::phase0_stack_top());
            map.insert("phase0_clk".to_string(), Self::phase0_clk());
            map.insert("phase0_next_pc".to_string(), Self::phase0_next_pc());
            map.insert(
                "phase0_old_stack_ts".to_string(),
                Self::phase0_old_stack_ts(),
            );
            map.insert(
                "phase0_old_stack_ts_lt".to_string(),
                Self::phase0_old_stack_ts_lt(),
            );

            map
        }
    }

    #[test]
    fn test_jump_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = JumpInstruction::phase0_idxes_map();
        let phase0_witness_size = JumpInstruction::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("JUMP {:?}", &phase0_idx_map);
            println!("JUMP witness_size = {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = JumpInstruction::construct_circuit(challenges).unwrap();

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
            "phase0_next_pc".to_string(),
            vec![Goldilocks::from(127u64), Goldilocks::from(125u64)],
        );
        phase0_values_map.insert(
            "phase0_old_stack_ts".to_string(),
            vec![Goldilocks::from(1u64)],
        );
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u2vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(
            "phase0_old_stack_ts_lt".to_string(),
            vec![
                Goldilocks::from(range_values[0]),
                Goldilocks::from(range_values[1]),
                Goldilocks::from(range_values[2]),
                // Goldilocks::from(range_values[3]),
                Goldilocks::from(1u64), // current length has no cells for borrow
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

    fn bench_jump_instruction_helper<E: ExtensionField>(instance_num_vars: usize) {
        let chip_challenges = ChipChallenges::default();
        let circuit_builder =
            SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
        let mut singer_builder = SingerGraphBuilder::<E>::new();

        let mut rng = test_rng();
        let size = JumpInstruction::phase0_size();
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

        let _ = JumpInstruction::construct_graph_and_witness(
            &mut singer_builder.graph_builder,
            &mut singer_builder.chip_builder,
            &circuit_builder.insts_circuits[<JumpInstruction as Instruction<E>>::OPCODE as usize],
            vec![phase0],
            &real_challenges,
            1 << instance_num_vars,
            &SingerParams::default(),
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

        println!(
            "JumpInstruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
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
            "JumpInstruction::prove, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn bench_jump_instruction() {
        bench_jump_instruction_helper::<GoldilocksExt2>(10);
    }
}
