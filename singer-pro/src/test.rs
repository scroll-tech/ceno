use crate::instructions::InstCircuit;
use core::ops::Range;
use gkr::structs::CircuitWitness;
use goldilocks::SmallField;
use std::collections::BTreeMap;

pub(crate) fn test_opcode_circuit<F: SmallField>(
    inst_circuit: &InstCircuit<F>,
    phase0_idx_map: &BTreeMap<String, Range<usize>>,
    phase1_idx_map: &BTreeMap<String, Range<usize>>,
    phase0_witness_size: usize,
    phase1_witness_size: usize,
    phase0_values_map: &BTreeMap<String, Vec<F>>,
    phase1_values_map: &BTreeMap<String, Vec<F>>,
) {
    // configure circuit
    let circuit = inst_circuit.circuit.as_ref();
    println!("{:?}", circuit);

    // get indexes for circuit inputs and wire_in
    // they are divided into phase0 and phase1
    let inputs_idxes = inst_circuit.layout.phases_wire_id;
    let phase0_input_idx = inputs_idxes[0].unwrap();
    let phase1_input_idx = inputs_idxes[1].unwrap();

    // assign witnesses to circuit
    let n_wires_in = circuit.n_wires_in;
    let mut wires_in = vec![vec![]; n_wires_in];
    wires_in[phase0_input_idx as usize] = vec![F::from(0u64); phase0_witness_size];
    wires_in[phase1_input_idx as usize] = vec![F::from(0u64); phase1_witness_size];

    for phase in 0..2 {
        let idx_map = match phase {
            0 => phase0_idx_map,
            1 => phase1_idx_map,
            other => panic!("invalid phase"),
        };
        let values_map = match phase {
            0 => phase0_values_map,
            1 => phase1_values_map,
            other => panic!("invalid phase"),
        };
        let input_idx = match phase {
            0 => phase0_input_idx as usize,
            1 => phase1_input_idx as usize,
            other => panic!("invalid phase"),
        };
        for key in idx_map.keys() {
            let range = idx_map.get(key).unwrap().clone().collect::<Vec<_>>();
            let values = values_map.get(key).unwrap();
            for (value_idx, wire_in_idx) in range.into_iter().enumerate() {
                if value_idx < values.len() {
                    wires_in[input_idx as usize][wire_in_idx] = values[value_idx];
                }
            }
        }
    }

    println!("{:?}", wires_in);

    /*
    let circuit_witness = {
        let challenges = vec![F::from(2), F::from(1)];
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
