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

pub struct AddInstruction;

impl<E: ExtensionField> InstructionGraph<E> for AddInstruction {
    type InstType = Self;
}

register_witness!(
    AddInstruction,
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

        addend_0 => StackUInt::N_OPERAND_CELLS,
        addend_1 => StackUInt::N_OPERAND_CELLS,
        instruction_add => AddSubConstants::<StackUInt>::N_WITNESS_CELLS
    }
);

impl<E: ExtensionField> Instruction<E> for AddInstruction {
    const OPCODE: OpcodeType = OpcodeType::ADD;
    const NAME: &'static str = "ADD";
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

        let next_pc =
            RangeChip::add_pc_const(&mut circuit_builder, &pc, 1, &phase0[Self::phase0_pc_add()])?;
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
            stack_top_expr.sub(E::BaseField::from(1)),
            clk_expr.add(E::BaseField::ONE),
        );

        // Execution result = addend0 + addend1, with carry.
        let addend_0 = (&phase0[Self::phase0_addend_0()]).try_into()?;
        let addend_1 = (&phase0[Self::phase0_addend_1()]).try_into()?;
        #[cfg(feature = "dbg-add-opcode")]
        println!(
            "addInstCircuit::phase0_instruction_add: {:?}",
            Self::phase0_instruction_add()
        );
        let result = StackUInt::add(
            &mut circuit_builder,
            &mut chip_handler,
            &addend_0,
            &addend_1,
            &phase0[Self::phase0_instruction_add()],
        )?;

        // Check the range of stack_top - 2 is within [0, 1 << STACK_TOP_BIT_WIDTH).
        RangeChip::range_check_stack_top(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
        )?;

        // Pop two values from stack
        let old_stack_ts0 = (&phase0[Self::phase0_old_stack_ts0()]).try_into()?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut chip_handler,
            &old_stack_ts0,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt0()],
        )?;
        StackChip::pop(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(1)),
            old_stack_ts0.values(),
            addend_0.values(),
        );

        let old_stack_ts1 = (&phase0[Self::phase0_old_stack_ts1()]).try_into()?;
        TSUInt::assert_lt(
            &mut circuit_builder,
            &mut chip_handler,
            &old_stack_ts1,
            &stack_ts,
            &phase0[Self::phase0_old_stack_ts_lt1()],
        )?;
        StackChip::pop(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
            old_stack_ts1.values(),
            addend_1.values(),
        );

        // Push one result to stack
        StackChip::push(
            &mut chip_handler,
            &mut circuit_builder,
            stack_top_expr.sub(E::BaseField::from(2)),
            stack_ts.values(),
            result.values(),
        );

        // Bytecode check for (pc, add)
        BytecodeChip::bytecode_with_pc_opcode(
            &mut chip_handler,
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<E>>::OPCODE,
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
    use transcript::Transcript;

    use goldilocks::{Goldilocks, GoldilocksExt2};
    use singer_utils::{
        constants::RANGE_CHIP_BIT_WIDTH,
        structs::{StackUInt, TSUInt},
    };
    use std::collections::BTreeMap;
    #[cfg(not(debug_assertions))]
    use std::time::Instant;

    use crate::{
        instructions::{AddInstruction, ChipChallenges, Instruction},
        test::{get_uint_params, test_opcode_circuit_v2},
        utils::u64vec,
    };

    #[test]
    fn test_add_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = AddInstruction::phase0_idxes_map();
        let phase0_witness_size = AddInstruction::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("ADD: {:?}", &phase0_idx_map);
            println!("ADD witness_size: {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = AddInstruction::construct_circuit(challenges).unwrap();

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        let mut phase0_values_map = BTreeMap::<&'static str, Vec<Goldilocks>>::new();
        phase0_values_map.insert(AddInstruction::phase0_pc_str(), vec![Goldilocks::from(
            1u64,
        )]);
        phase0_values_map.insert(AddInstruction::phase0_stack_ts_str(), vec![
            Goldilocks::from(3u64),
        ]);
        phase0_values_map.insert(AddInstruction::phase0_memory_ts_str(), vec![
            Goldilocks::from(1u64),
        ]);
        phase0_values_map.insert(AddInstruction::phase0_stack_top_str(), vec![
            Goldilocks::from(100u64),
        ]);
        phase0_values_map.insert(AddInstruction::phase0_clk_str(), vec![Goldilocks::from(
            1u64,
        )]);
        phase0_values_map.insert(
            AddInstruction::phase0_pc_add_str(),
            vec![], // carry is 0, may test carry using larger values in PCUInt
        );
        phase0_values_map.insert(AddInstruction::phase0_stack_ts_add_str(), vec![
            Goldilocks::from(4u64), /* first TSUInt::N_RANGE_CELLS = 1*(48/16) = 3 cells are
                                     * range values, stack_ts + 1 = 4 */
            Goldilocks::from(0u64),
            Goldilocks::from(0u64),
            // no place for carry
        ]);
        phase0_values_map.insert(AddInstruction::phase0_old_stack_ts0_str(), vec![
            Goldilocks::from(2u64),
        ]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 1;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(AddInstruction::phase0_old_stack_ts_lt0_str(), vec![
            Goldilocks::from(range_values[0]),
            Goldilocks::from(range_values[1]),
            Goldilocks::from(range_values[2]),
            Goldilocks::from(1u64),
        ]);
        phase0_values_map.insert(AddInstruction::phase0_old_stack_ts1_str(), vec![
            Goldilocks::from(1u64),
        ]);
        let m: u64 = (1 << get_uint_params::<TSUInt>().1) - 2;
        let range_values = u64vec::<{ TSUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m);
        phase0_values_map.insert(AddInstruction::phase0_old_stack_ts_lt1_str(), vec![
            Goldilocks::from(range_values[0]),
            Goldilocks::from(range_values[1]),
            Goldilocks::from(range_values[2]),
            Goldilocks::from(1u64),
        ]);
        let m: u64 = (1 << get_uint_params::<StackUInt>().1) - 1;
        phase0_values_map.insert(AddInstruction::phase0_addend_0_str(), vec![
            Goldilocks::from(m),
        ]);
        phase0_values_map.insert(AddInstruction::phase0_addend_1_str(), vec![
            Goldilocks::from(1u64),
        ]);
        let range_values = u64vec::<{ StackUInt::N_RANGE_CELLS }, RANGE_CHIP_BIT_WIDTH>(m + 1);
        let mut wit_phase0_instruction_add: Vec<Goldilocks> = vec![];
        for &value in &range_values[..16] {
            wit_phase0_instruction_add.push(Goldilocks::from(value))
        }
        wit_phase0_instruction_add.push(Goldilocks::from(1u64)); // carry is [1, 0, ...]
        phase0_values_map.insert(
            AddInstruction::phase0_instruction_add_str(),
            wit_phase0_instruction_add,
        );

        // The actual challenges used is:
        // challenges
        //  { ChallengeConst { challenge: 1, exp: i }: [Goldilocks(c^i)] }
        let c = GoldilocksExt2::from(6u64);
        let circuit_witness_challenges = vec![c; 3];

        let _ = test_opcode_circuit_v2(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
            circuit_witness_challenges,
        );
    }

    #[cfg(not(debug_assertions))]
    fn bench_add_instruction_helper<E: ExtensionField>(instance_num_vars: usize) {
        let chip_challenges = ChipChallenges::default();
        let circuit_builder =
            SingerCircuitBuilder::<E>::new(chip_challenges).expect("circuit builder failed");
        let mut singer_builder = SingerGraphBuilder::<E>::default();

        let mut rng = test_rng();
        let size = AddInstruction::phase0_size();
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

        let _ = AddInstruction::construct_graph_and_witness(
            &mut singer_builder.graph_builder,
            &mut singer_builder.chip_builder,
            &circuit_builder.insts_circuits[<AddInstruction as Instruction<E>>::OPCODE as usize],
            vec![phase0],
            &real_challenges,
            1 << instance_num_vars,
            &SingerParams::default(),
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

        println!(
            "AddInstruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
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
            "AddInstruction::prove, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn bench_add_instruction() {
        bench_add_instruction_helper::<GoldilocksExt2>(10);
    }
}
