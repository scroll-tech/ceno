use ff::Field;
use gkr::structs::{Circuit, LayerWitness};
use goldilocks::SmallField;
use paste::paste;
use revm_interpreter::Record;
use simple_frontend::structs::{CircuitBuilder, MixedCell};
use singer_utils::{
    chip_handler::{
        BytecodeChipOperations, GlobalStateChipOperations, OAMOperations, ROMOperations,
    },
    constants::OpcodeType,
    copy_clock_from_record, copy_pc_add_from_record, copy_pc_from_record,
    copy_stack_top_from_record, register_witness,
    structs::{PCUInt, RAMHandler, ROMHandler, TSUInt},
    uint::{u2fvec, UIntAddSub},
};
use std::sync::Arc;

use crate::{error::ZKVMError, CircuitWiresIn};

use super::{ChipChallenges, InstCircuit, InstCircuitLayout, Instruction, InstructionGraph};

pub struct JumpdestInstruction;

impl<F: SmallField> InstructionGraph<F> for JumpdestInstruction {
    type InstType = Self;
}

register_witness!(
    JumpdestInstruction,
    phase0 {
        pc => PCUInt::N_OPRAND_CELLS ,
        stack_ts=> TSUInt::N_OPRAND_CELLS,
        memory_ts => TSUInt::N_OPRAND_CELLS,
        stack_top => 1,
        clk => 1,
        pc_add => UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS
    }
);

impl<F: SmallField> Instruction<F> for JumpdestInstruction {
    const OPCODE: OpcodeType = OpcodeType::JUMPDEST;
    const NAME: &'static str = "JUMPDEST";
    fn construct_circuit(challenges: ChipChallenges) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_witness_in(Self::phase0_size());
        let mut ram_handler = RAMHandler::new(&challenges);
        let mut rom_handler = ROMHandler::new(&challenges);

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts = &phase0[Self::phase0_memory_ts()];
        let stack_top = phase0[Self::phase0_stack_top().start];
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
        ram_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            stack_ts.values(), // Because there is no stack push.
            memory_ts,
            stack_top.into(),
            clk_expr.add(F::BaseField::ONE),
        );

        // Bytecode check for (pc, jump)
        rom_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            <Self as Instruction<F>>::OPCODE,
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

    fn generate_wires_in(record: &Record) -> CircuitWiresIn<F> {
        let mut wire_values = vec![F::ZERO; Self::phase0_size()];
        copy_pc_from_record!(wire_values, record);
        copy_stack_top_from_record!(wire_values, record);
        copy_clock_from_record!(wire_values, record);
        copy_pc_add_from_record!(wire_values, record);

        vec![LayerWitness {
            instances: vec![wire_values],
        }]
    }
}

#[cfg(test)]
mod test {
    use ark_std::test_rng;
    use core::ops::Range;
    use ff::Field;
    use gkr::structs::LayerWitness;
    use goldilocks::{Goldilocks, GoldilocksExt2, SmallField};
    use itertools::Itertools;
    use revm_interpreter::Interpreter;
    use simple_frontend::structs::CellId;
    use singer_utils::constants::{OpcodeType, RANGE_CHIP_BIT_WIDTH};
    use std::collections::BTreeMap;
    use std::time::Instant;
    use transcript::Transcript;

    use crate::instructions::{
        ChipChallenges, Instruction, InstructionGraph, JumpdestInstruction, SingerCircuitBuilder,
    };
    use crate::scheme::GKRGraphProverState;
    use crate::test::{
        get_uint_params, test_opcode_circuit, test_opcode_circuit_with_witness_vector, u2vec,
    };
    use crate::{CircuitWiresIn, SingerGraphBuilder, SingerParams};

    impl JumpdestInstruction {
        #[inline]
        fn phase0_idxes_map() -> BTreeMap<String, Range<CellId>> {
            let mut map = BTreeMap::new();
            map.insert("phase0_pc".to_string(), Self::phase0_pc());
            map.insert("phase0_stack_ts".to_string(), Self::phase0_stack_ts());
            map.insert("phase0_memory_ts".to_string(), Self::phase0_memory_ts());
            map.insert("phase0_stack_top".to_string(), Self::phase0_stack_top());
            map.insert("phase0_clk".to_string(), Self::phase0_clk());
            map.insert("phase0_pc_add".to_string(), Self::phase0_pc_add());

            map
        }
    }

    #[test]
    fn test_jumpdest_construct_circuit() {
        let challenges = ChipChallenges::default();

        let phase0_idx_map = JumpdestInstruction::phase0_idxes_map();
        let phase0_witness_size = JumpdestInstruction::phase0_size();

        #[cfg(feature = "witness-count")]
        {
            println!("JUMPDEST {:?}", &phase0_idx_map);
            println!("JUMPDEST witness_size = {:?}", phase0_witness_size);
        }

        // initialize general test inputs associated with push1
        let inst_circuit = JumpdestInstruction::construct_circuit(challenges).unwrap();

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert("phase0_pc".to_string(), vec![Goldilocks::from(1u64)]);
        phase0_values_map.insert("phase0_stack_ts".to_string(), vec![Goldilocks::from(1u64)]);
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

        let circuit_witness_challenges = vec![
            Goldilocks::from(2),
            Goldilocks::from(2),
            Goldilocks::from(2),
        ];

        let _circuit_witness = test_opcode_circuit(
            &inst_circuit,
            &phase0_idx_map,
            phase0_witness_size,
            &phase0_values_map,
            circuit_witness_challenges,
        );
    }

    /// Test the correctness of the witness generated by the interpreter
    /// for the jumpdest instruction circuit.
    #[test]
    fn test_interpreter_for_jumpdest_circuit() {
        let challenges = ChipChallenges::default();
        let bytecode = [
            OpcodeType::PUSH1 as u8,
            4,
            OpcodeType::JUMP as u8,
            OpcodeType::POP as u8,
            OpcodeType::JUMPDEST as u8,
        ];
        let records = Interpreter::<Goldilocks>::execute(&bytecode, &[]);
        // The interpreter has ensured the last instruction must be stop, so here
        // we actually executed four instructions.
        assert_eq!(records.len(), 4);
        let circuit_wires_in: Vec<Vec<Goldilocks>> =
            JumpdestInstruction::generate_wires_in(&records[2])[0]
                .instances
                .clone();
        assert_eq!(circuit_wires_in.len(), 1);
        assert_eq!(
            circuit_wires_in[0].len(),
            JumpdestInstruction::phase0_size()
        );

        #[cfg(feature = "witness-count")]
        {
            println!("GT: {:?}", &phase0_idx_map);
            println!("GT witness_size: {:?}", phase0_witness_size);
        }

        let inst_circuit = JumpdestInstruction::construct_circuit(challenges).unwrap();

        #[cfg(feature = "test-dbg")]
        println!("{:?}", inst_circuit);

        // The actual challenges used is:
        // challenges
        //  { ChallengeConst { challenge: 1, exp: i }: [Goldilocks(c^i)] }
        let c: u64 = 6;
        let circuit_witness_challenges = vec![
            Goldilocks::from(c),
            Goldilocks::from(c),
            Goldilocks::from(c),
        ];

        let circuit_witness = test_opcode_circuit_with_witness_vector(
            &inst_circuit,
            circuit_wires_in,
            circuit_witness_challenges,
        );
    }

    fn bench_jumpdest_instruction_helper<F: SmallField>(instance_num_vars: usize) {
        let chip_challenges = ChipChallenges::default();
        let circuit_builder =
            SingerCircuitBuilder::<F>::new(chip_challenges).expect("circuit builder failed");
        let mut singer_builder = SingerGraphBuilder::<F>::new();

        let mut rng = test_rng();
        let size = JumpdestInstruction::phase0_size();
        let phase0: CircuitWiresIn<F::BaseField> = vec![LayerWitness {
            instances: (0..(1 << instance_num_vars))
                .map(|_| {
                    (0..size)
                        .map(|_| F::BaseField::random(&mut rng))
                        .collect_vec()
                })
                .collect_vec(),
        }];

        let real_challenges = vec![F::random(&mut rng), F::random(&mut rng)];

        let timer = Instant::now();

        let _ = JumpdestInstruction::construct_graph_and_witness(
            &mut singer_builder.graph_builder,
            &mut singer_builder.chip_builder,
            &circuit_builder.insts_circuits
                [<JumpdestInstruction as Instruction<F>>::OPCODE as usize],
            vec![phase0],
            &real_challenges,
            1 << instance_num_vars,
            &SingerParams::default(),
        )
        .expect("gkr graph construction failed");

        let (graph, wit) = singer_builder.graph_builder.finalize_graph_and_witness();

        println!(
            "JumpdestInstruction::construct_graph_and_witness, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );

        let point = vec![F::random(&mut rng), F::random(&mut rng)];
        let target_evals = graph.target_evals(&wit, &point);

        let mut prover_transcript = &mut Transcript::new(b"Singer");

        let timer = Instant::now();
        let _ = GKRGraphProverState::prove(&graph, &wit, &target_evals, &mut prover_transcript)
            .expect("prove failed");
        println!(
            "JumpdestInstruction::prove, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn bench_jumpdest_instruction() {
        bench_jumpdest_instruction_helper::<GoldilocksExt2>(10);
    }
}
