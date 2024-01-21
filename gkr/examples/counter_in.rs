use frontend::structs::{CircuitBuilder, ConstantType, WireId};
use gkr::structs::{Circuit, CircuitWitness, IOPProverState, IOPVerifierState};
use gkr::utils::MultilinearExtensionFromVectors;
use goldilocks::{Goldilocks, SmallField};
use itertools::Itertools;
use transcript::Transcript;

struct AllInputIndex {
    // public
    inputs_idx: WireId,
    // private
    count_idx: WireId,
}

fn construct_circuit<F: SmallField>() -> (Circuit<F>, AllInputIndex) {
    let mut circuit_builder = CircuitBuilder::<F>::new();

    let (inputs_idx, inputs) = circuit_builder.create_wire_in(5);

    let table_size = 4;
    let table = circuit_builder.create_counter_in(2);

    let table_type = 0;
    let count_idx = circuit_builder.define_table_type(table_type);
    // table should be [0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], ...
    for i in 0..table_size {
        circuit_builder.add_table_item(table_type, table[i]);
    }

    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

    circuit_builder.configure();
    (
        Circuit::<F>::new(&circuit_builder),
        AllInputIndex {
            inputs_idx,
            count_idx,
        },
    )
}

fn main() {
    let (circuit, all_input_index) = construct_circuit::<Goldilocks>();
    // println!("circuit: {:?}", circuit);
    let mut wires_in = vec![vec![vec![]; circuit.n_wires_in]; 2];
    wires_in[0][all_input_index.inputs_idx as usize] = vec![
        Goldilocks::from(0u64),
        Goldilocks::from(1u64),
        Goldilocks::from(0u64),
        Goldilocks::from(2u64),
        Goldilocks::from(3u64),
    ];
    wires_in[1][all_input_index.inputs_idx as usize] = vec![
        Goldilocks::from(7u64),
        Goldilocks::from(7u64),
        Goldilocks::from(4u64),
        Goldilocks::from(5u64),
        Goldilocks::from(5u64),
    ];
    wires_in[0][all_input_index.count_idx as usize] = vec![
        Goldilocks::from(2u64),
        Goldilocks::from(1u64),
        Goldilocks::from(1u64),
        Goldilocks::from(1u64),
    ];
    wires_in[1][all_input_index.count_idx as usize] = vec![
        Goldilocks::from(1u64),
        Goldilocks::from(2u64),
        Goldilocks::from(0u64),
        Goldilocks::from(2u64),
    ];

    let circuit_witness = {
        let challenge = Goldilocks::from(9);
        let mut circuit_witness = CircuitWitness::new(&circuit, vec![challenge]);
        for i in 0..2 {
            circuit_witness.add_instance(&circuit, &wires_in[i]);
        }
        circuit_witness
    };

    #[cfg(feature = "debug")]
    circuit_witness.check_correctness(&circuit);

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
}
