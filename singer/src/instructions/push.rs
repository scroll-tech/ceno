use std::sync::Arc;

use frontend::structs::{CircuitBuilder, MixedCell};
use gkr::structs::Circuit;
use goldilocks::SmallField;

use crate::instructions::InstCircuitLayout;
use crate::{
    constants::{OpcodeType, VALUE_BIT_WIDTH},
    error::ZKVMError,
};

use super::InstructionGraph;
use super::{
    utils::{uint::UIntAddSub, ChipHandler, PCUInt, TSUInt, UInt},
    ChipChallenges, InstCircuit, InstOutputType, Instruction,
};

pub struct PushInstruction<const N: usize>;

impl<const N: usize> InstructionGraph for PushInstruction<N> {
    type InstType = Self;
}

register_wires_in!(
    PushInstruction<N>,
    phase0_size {
        phase0_pc => PCUInt::N_OPRAND_CELLS,
        phase0_stack_ts => TSUInt::N_OPRAND_CELLS,
        phase0_stack_top => 1,
        phase0_clk => 1,

        phase0_pc_add_i_plus_1 => N * UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS,
        phase0_stack_ts_add => UIntAddSub::<TSUInt>::N_NO_OVERFLOW_WITNESS_CELLS,

        phase0_stack_bytes => N
    },
    phase1_size {
        phase1_memory_ts_rlc => 1
    }
);

register_wires_out!(
    PushInstruction<N>,
    global_state_in_size {
        state_in => 1
    },
    global_state_out_size {
        state_out => 1
    },
    bytecode_chip_size {
        current => N + 1
    },
    stack_push_size {
        value => N
    },
    range_chip_size {
        stack_top => 1,
        stack_ts_add => TSUInt::N_RANGE_CHECK_NO_OVERFLOW_CELLS,
        old_stack_ts_lt => TSUInt::N_RANGE_CHECK_CELLS
    }
);

impl<const N: usize> PushInstruction<N> {
    const OPCODE: OpcodeType = match N {
        1 => OpcodeType::PUSH1,
        _ => unimplemented!(),
    };
}

impl<const N: usize> Instruction for PushInstruction<N> {
    #[inline]
    fn witness_size(phase: usize) -> usize {
        match phase {
            0 => Self::phase0_size(),
            1 => Self::phase1_size(),
            _ => 0,
        }
    }

    #[inline]
    fn output_size(inst_out: InstOutputType) -> usize {
        match inst_out {
            InstOutputType::GlobalStateIn => Self::global_state_in_size(),
            InstOutputType::GlobalStateOut => Self::global_state_out_size(),
            InstOutputType::BytecodeChip => Self::bytecode_chip_size(),
            InstOutputType::StackPush => Self::stack_push_size(),
            InstOutputType::RangeChip => Self::range_chip_size(),
            _ => 0,
        }
    }

    fn construct_circuit<F: SmallField>(
        challenges: ChipChallenges,
    ) -> Result<InstCircuit<F>, ZKVMError> {
        let mut circuit_builder = CircuitBuilder::new();
        let (phase0_wire_id, phase0) = circuit_builder.create_wire_in(Self::phase0_size());
        let (phase1_wire_id, phase1) = circuit_builder.create_wire_in(Self::phase1_size());
        let mut global_state_in_handler = ChipHandler::new(
            &mut circuit_builder,
            challenges,
            Self::global_state_in_size(),
        );
        let mut global_state_out_handler = ChipHandler::new(
            &mut circuit_builder,
            challenges,
            Self::global_state_out_size(),
        );
        let mut bytecode_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::bytecode_chip_size());
        let mut stack_push_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::stack_push_size());
        let mut range_chip_handler =
            ChipHandler::new(&mut circuit_builder, challenges, Self::range_chip_size());

        // State update
        let pc = PCUInt::try_from(&phase0[Self::phase0_pc()])?;
        let stack_ts = TSUInt::try_from(&phase0[Self::phase0_stack_ts()])?;
        let memory_ts_rlc = phase1[Self::phase1_memory_ts_rlc().start];
        let stack_top = phase0[Self::phase0_stack_top().start];
        let stack_top_expr = MixedCell::Cell(stack_top);
        let clk = phase0[Self::phase0_clk().start];
        let clk_expr = MixedCell::Cell(clk);
        global_state_in_handler.state_in(
            &mut circuit_builder,
            pc.values(),
            stack_ts.values(),
            &[memory_ts_rlc],
            stack_top,
            clk,
        );

        let next_pc = ChipHandler::add_pc_const(
            &mut circuit_builder,
            &pc,
            N as i64 + 1,
            &phase0[Self::phase0_pc_add_i_plus_1()],
        )?;
        let next_stack_ts = range_chip_handler.add_ts_with_const(
            &mut circuit_builder,
            &stack_ts,
            1,
            &phase0[Self::phase0_stack_ts_add()],
        )?;

        global_state_out_handler.state_out(
            &mut circuit_builder,
            next_pc.values(),
            next_stack_ts.values(),
            &[memory_ts_rlc],
            stack_top_expr.add(F::from(1)),
            clk_expr.add(F::ONE),
        );

        // Check the range of stack_top is within [0, 1 << STACK_TOP_BIT_WIDTH).
        range_chip_handler.range_check_stack_top(&mut circuit_builder, stack_top_expr)?;

        let stack_bytes = &phase0[Self::phase0_stack_bytes()];
        let stack_values =
            UInt::<N, VALUE_BIT_WIDTH>::from_bytes_big_endien(&mut circuit_builder, stack_bytes)?;
        // Push value to stack
        stack_push_handler.stack_push_values(
            &mut circuit_builder,
            stack_top_expr,
            stack_ts.values(),
            stack_values.values(),
        );

        // Bytecode check for (pc, PUSH{N}), (pc + 1, byte[0]), ..., (pc + N, byte[N - 1])
        bytecode_chip_handler.bytecode_with_pc_opcode(
            &mut circuit_builder,
            pc.values(),
            Self::OPCODE,
        );
        for (i, pc_add_i_plus_1) in phase0[Self::phase0_pc_add_i_plus_1()]
            .chunks(UIntAddSub::<PCUInt>::N_NO_OVERFLOW_WITNESS_UNSAFE_CELLS)
            .enumerate()
        {
            let next_pc = ChipHandler::add_pc_const(
                &mut circuit_builder,
                &pc,
                i as i64 + 1,
                pc_add_i_plus_1,
            )?;
            bytecode_chip_handler.bytecode_with_pc_byte(
                &mut circuit_builder,
                next_pc.values(),
                stack_bytes[i],
            );
        }

        global_state_in_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        global_state_out_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        bytecode_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        stack_push_handler.finalize_with_const_pad(&mut circuit_builder, &F::ONE);
        range_chip_handler.finalize_with_repeated_last(&mut circuit_builder);
        circuit_builder.configure();

        let outputs_wire_id = [
            Some(global_state_in_handler.wire_out_id()),
            Some(global_state_out_handler.wire_out_id()),
            Some(bytecode_chip_handler.wire_out_id()),
            None,
            Some(stack_push_handler.wire_out_id()),
            Some(range_chip_handler.wire_out_id()),
            None,
            None,
            None,
        ];

        Ok(InstCircuit {
            circuit: Arc::new(Circuit::new(&circuit_builder)),
            layout: InstCircuitLayout {
                chip_check_wire_id: outputs_wire_id,
                phases_wire_id: [Some(phase0_wire_id), Some(phase1_wire_id)],
                ..Default::default()
            },
        })
    }
}


#[cfg(test)]
mod test{
    use core::ops::Range;
    use std::collections::BTreeMap;

    use goldilocks::Goldilocks;
    use crate::instructions::{ChipChallenges, Instruction, PushInstruction};
    use gkr::structs::CircuitWitness;

    impl<const N: usize> PushInstruction<N> {
        #[inline]
        fn phase0_sizes() -> BTreeMap<String, Range<usize>> {
            let mut map = BTreeMap::new();
            map.insert("phase0_pc".to_string(), Self::phase0_pc());
            map.insert("phase0_stack_ts".to_string(), Self::phase0_stack_ts());
            map.insert("phase0_stack_top".to_string(), Self::phase0_stack_top());
            map.insert("phase0_clk".to_string(), Self::phase0_clk());
            map.insert("phase0_pc_add_i_plus_1".to_string(), Self::phase0_pc_add_i_plus_1());
            map.insert("phase0_stack_ts_add".to_string(), Self::phase0_stack_ts_add());
            map.insert("phase0_stack_bytes".to_string(), Self::phase0_stack_bytes());
            
            map
        }

        #[inline]
        fn phase1_sizes() -> BTreeMap<String, Range<usize>> {
            let mut map = BTreeMap::new();
            map.insert("phase1_memory_ts_rlc".to_string(), Self::phase1_memory_ts_rlc());
            
            map
        }
    }

    #[test]
    fn test_push1_construct_circuit() {
        let chip_challenges = ChipChallenges::default();

        // initialize general test inputs associated with push1       
        let InstCircuit 
            = PushInstruction::<1>::construct_circuit::<Goldilocks>(chip_challenges).unwrap();
        let phase0_idx_map = PushInstruction::<1>::phase0_sizes();
        let phase1_idx_map = PushInstruction::<1>::phase1_sizes();
        let phase0_witness_size = PushInstruction::<1>::witness_size(0);
        let phase1_witness_size = PushInstruction::<1>::witness_size(1);
        let mut phase0_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        let mut phase1_values_map = BTreeMap::<String, Vec<Goldilocks>>::new();
        phase0_values_map.insert(
        "phase0_pc".to_string(), 
        vec![
            Goldilocks::from(1u64), 
        ]);
        phase0_values_map.insert(
        "phase0_stack_ts".to_string(),
        vec![
            Goldilocks::from(1u64), 
        ]);
        phase0_values_map.insert(
        "phase0_stack_top".to_string(),
        vec![
            Goldilocks::from(1u64), 
        ]);
        phase0_values_map.insert(
        "phase0_clk".to_string(), 
        vec![
            Goldilocks::from(1u64),
        ]);
        phase0_values_map.insert(
        "phase0_pc_add_i_plus_1".to_string(), 
        vec![
            Goldilocks::from(1u64),
            Goldilocks::from(1u64),
        ]);
        phase0_values_map.insert(
        "phase0_stack_ts_add".to_string(), 
        vec![
            Goldilocks::from(2u64),
        ]);
        phase0_values_map.insert(
        "phase0_stack_bytes".to_string(), 
        vec![
            Goldilocks::from(0u64),
        ]);
        phase1_values_map.insert(
        "phase1_memory_ts_rlc".to_string(), 
        vec![
            Goldilocks::from(0u64),
        ]);

        // TODO: Refactor general opcode test logic below 
        // configure circuit
        let circuit = InstCircuit.circuit.as_ref();
        
        // get indexes for circuit inputs and wire_in
        // they are divided into phase0 and phase1
        let inputs_idxes = &InstCircuit.layout.phases_wire_id;
        let phase0_input_idx = inputs_idxes[0].unwrap();
        let phase1_input_idx = inputs_idxes[1].unwrap();
        
        // assign witnesses to circuit
        let n_wires_in = circuit.n_wires_in;
        let mut wires_in = vec![vec![]; n_wires_in];
        wires_in[phase0_input_idx as usize] = vec![
            Goldilocks::from(0u64); phase0_witness_size
        ];
        wires_in[phase1_input_idx as usize] = vec![
            Goldilocks::from(0u64); phase1_witness_size
        ];

        for phase in 0..2 {
            let idx_map = match phase {
                0 => &phase0_idx_map,
                1 => &phase1_idx_map,
                other => panic!("invalid phase"),
            };
            let values_map = match phase {
                0 => &phase0_values_map,
                1 => &phase1_values_map,
                other => panic!("invalid phase"),
            };
            let input_idx = match phase {
                0 => phase0_input_idx as usize,
                1 => phase1_input_idx as usize,
                other => panic!("invalid phase"),
            };
            for key in idx_map.keys() {
                let range = idx_map
                                        .get(key)
                                        .unwrap()
                                        .clone()
                                        .collect::<Vec<_>>();
                let values = values_map
                                            .get(key)
                                            .unwrap();
                for (value_idx, wire_in_idx) in range
                                                            .into_iter()
                                                            .enumerate() {
                    if value_idx < values.len() {
                        wires_in[input_idx as usize][wire_in_idx] 
                            = values[value_idx];
                    }
                }
            }
        }

        println!("{:?}", wires_in);    

        /*
        let circuit_witness = {
            let challenges = vec![Goldilocks::from(2), Goldilocks::from(1)];
            let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
            circuit_witness.add_instance(&circuit, &wires_in);
            circuit_witness
        };

        println!("{:?}", circuit_witness);
        */
        /*
        //#[cfg(feature = "debug")]
        circuit_witness.check_correctness(&circuit);
        */

        /*
        let instance_num_vars = circuit_witness.instance_num_vars();
    
        let (proof, output_num_vars, output_eval) = {
            let mut prover_transcript = Transcript::<Goldilocks>::new(b"example");
            let output_num_vars = instance_num_vars + circuit.last_layer_ref().num_vars();
    
            let output_point = (0..output_num_vars)
                .map(|_| {
                    prover_transcript
                        .get_and_append_challenge(b"output point")
                        .elements
                })
                .collect_vec();
    
            let output_eval = circuit_witness
                .layer_poly(0, circuit.last_layer_ref().num_vars())
                .evaluate(&output_point);
            (
                IOPProverState::prove_parallel(
                    &circuit,
                    &circuit_witness,
                    &[(output_point, output_eval)],
                    &[],
                    &mut prover_transcript,
                ),
                output_num_vars,
                output_eval,
            )
        };
    
        let gkr_input_claims = {
            let mut verifier_transcript = &mut Transcript::<Goldilocks>::new(b"example");
            let output_point = (0..output_num_vars)
                .map(|_| {
                    verifier_transcript
                        .get_and_append_challenge(b"output point")
                        .elements
                })
                .collect_vec();
            IOPVerifierState::verify_parallel(
                &circuit,
                circuit_witness.challenges(),
                &[(output_point, output_eval)],
                &[],
                &proof,
                instance_num_vars,
                &mut verifier_transcript,
            )
            .expect("verification failed")
        };
    
        let expected_values = circuit_witness
            .wires_in_ref()
            .iter()
            .map(|witness| {
                witness
                    .as_slice()
                    .mle(circuit.max_wires_in_num_vars, instance_num_vars)
                    .evaluate(&gkr_input_claims.point)
            })
            .collect_vec();
        for i in 0..gkr_input_claims.values.len() {
            assert_eq!(expected_values[i], gkr_input_claims.values[i]);
        }
    
        println!("verification succeeded");
        */
    }
}