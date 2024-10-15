use std::sync::Arc;

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
    structs::{PCUInt, TSUInt},
    uint::constants::AddSubConstants,
};
use std::collections::BTreeMap;

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

        // Pop next pc from stack
        RangeChip::range_check_stack_top(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::ONE),
        )?;

        let next_pc = &phase0[Self::phase0_next_pc()];
        let old_stack_ts = (&phase0[Self::phase0_old_stack_ts()]).try_into()?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut chip_handler,
            &old_stack_ts,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt()],
        )?;
        StackChip::pop(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::ONE),
            old_stack_ts.values(),
            next_pc,
        );

        GlobalStateChip::state_out(
            &mut chip_handler,
            &mut circuit_builder,
            next_pc,
            stack_ts.values(), // Because there is no stack push.
            memory_ts,
            stack_top_expr.sub(E::BaseField::from(1)),
            clk_expr.add(E::BaseField::ONE),
        );

        // Bytecode check for (pc, jump)
        BytecodeChip::bytecode_with_pc_opcode(
            &mut chip_handler,
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<E>>::OPCODE,
        );
        // Bytecode check for (next_pc, jumpdest)
        BytecodeChip::bytecode_with_pc_opcode(
            &mut chip_handler,
            &mut circuit_builder,
            next_pc,
            OpcodeType::JUMPDEST,
        );

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
    #[allow(deprecated)]
    use crate::test::test_opcode_circuit;
    #[cfg(not(debug_assertions))]
    use crate::{
        CircuitWiresIn, SingerGraphBuilder, SingerParams,
        instructions::{InstructionGraph, SingerCircuitBuilder},
        scheme::GKRGraphProverState,
    };
    use crate::{
        instructions::{ChipChallenges, Instruction, JumpInstruction},
        test::get_uint_params,
        utils::u64vec,
    };
    #[cfg(not(debug_assertions))]
    use ark_std::test_rng;
    #[cfg(not(debug_assertions))]
    use ff::Field;
    #[cfg(not(debug_assertions))]
    use ff_ext::ExtensionField;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use singer_utils::{constants::RANGE_CHIP_BIT_WIDTH, structs::TSUInt};
    use std::collections::BTreeMap;
    #[cfg(not(debug_assertions))]
    use std::time::Instant;
    #[cfg(not(debug_assertions))]
    use transcript::Transcript;

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
        phase0_values_map.insert("phase0_stack_top".to_string(), vec![Goldilocks::from(
            100u64,
        )]);
        phase0_values_map.insert("phase0_clk".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_next_pc".to_string(), vec![
            Goldilocks::from(127u64),
            Goldilocks::from(125u64),
        ]);
        phase0_values_map.insert("phase0_old_stack_ts".to_string(), vec![Goldilocks::from(
            1u64,
        )]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert("phase0_old_stack_ts_lt".to_string(), vec![
            Goldilocks::from(range_values[0]),
            Goldilocks::from(range_values[1]),
            Goldilocks::from(range_values[2]),
            Goldilocks::from(1u64), // current length has no cells for borrow
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
    fn bench_jump_instruction_helper<E: ExtensionField>(instance_num_vars: usize) {
        let chip_challenges = ChipChallenges::default();
        let circuit_builder =
            SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
        let mut singer_builder = SingerGraphBuilder::<E>::default();

        let mut rng = test_rng();
        let size = JumpInstruction::phase0_size();
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

        let prover_transcript = &mut Transcript::new(b"Singer");

        let timer = Instant::now();
        let _ = GKRGraphProverState::prove(&graph, &wit, &target_evals, prover_transcript, 1)
            .expect("prove failed");
        println!(
            "JumpInstruction::prove, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn bench_jump_instruction() {
        bench_jump_instruction_helper::<GoldilocksExt2>(10);
    }
}
