use frontend::structs::{CircuitBuilder, ConstantType};
use gkr::structs::{Circuit, CircuitWitness, IOPProverState, IOPVerifierState};
use gkr::utils::MultilinearExtensionFromVectors;
use goldilocks::{Goldilocks, SmallField};
use itertools::Itertools;
use transcript::Transcript;

enum TableType {
    FakeHashTable,
}

struct AllInputIndex {
    // public
    inputs_idx: usize,

    // private
    other_x_pows_idx: usize,
    count_idx: usize,
}

fn construct_circuit<F: SmallField>() -> (Circuit<F>, AllInputIndex) {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let one = ConstantType::Field(F::ONE);
    let neg_one = ConstantType::Field(-F::ONE);

    let table_size = 4;
    let x = circuit_builder.create_constant_in(1, 2);
    let (other_x_pows_idx, other_pows_of_x) = circuit_builder.create_wire_in(table_size - 1);
    let pow_of_xs = [x, other_pows_of_x].concat();
    for i in 0..table_size - 1 {
        // circuit_builder.mul2(
        //     pow_of_xs[i + 1],
        //     pow_of_xs[i],
        //     pow_of_xs[i],
        //     Goldilocks::ONE,
        // );
        let tmp = circuit_builder.create_cell();
        circuit_builder.mul2(tmp, pow_of_xs[i], pow_of_xs[i], one);
        let diff = circuit_builder.create_cell();
        circuit_builder.add(diff, pow_of_xs[i + 1], one);
        circuit_builder.add(diff, tmp, neg_one);
        circuit_builder.assert_const(diff, &F::ZERO);
    }

    let table_type = TableType::FakeHashTable as usize;
    let count_idx = circuit_builder.define_table_type(table_type);
    for i in 0..table_size {
        circuit_builder.add_table_item(table_type, pow_of_xs[i]);
    }

    let (inputs_idx, inputs) = circuit_builder.create_wire_in(5);
    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

    circuit_builder.configure();
    // circuit_builder.print_info();
    (
        Circuit::<F>::new(&circuit_builder),
        AllInputIndex {
            other_x_pows_idx,
            inputs_idx,
            count_idx,
        },
    )
}

fn main() {
    let (circuit, all_input_index) = construct_circuit::<Goldilocks>();
    // println!("circuit: {:?}", circuit);
    let mut wires_in = vec![vec![]; circuit.n_wires_in];
    wires_in[all_input_index.inputs_idx] = vec![
        Goldilocks::from(2u64),
        Goldilocks::from(2u64),
        Goldilocks::from(4u64),
        Goldilocks::from(16u64),
        Goldilocks::from(2u64),
    ];
    // x = 2, 2^2 = 4, 2^2^2 = 16, 2^2^2^2 = 256
    wires_in[all_input_index.other_x_pows_idx] = vec![
        Goldilocks::from(4u64),
        Goldilocks::from(16u64),
        Goldilocks::from(256u64),
    ];
    wires_in[all_input_index.count_idx] = vec![
        Goldilocks::from(3u64),
        Goldilocks::from(1u64),
        Goldilocks::from(1u64),
        Goldilocks::from(0u64),
    ];

    let circuit_witness = {
        let challenge = Goldilocks::from(9);
        let mut circuit_witness = CircuitWitness::new(&circuit, vec![challenge]);
        for _ in 0..4 {
            circuit_witness.add_instance(&circuit, &wires_in);
        }
        circuit_witness
    };

    #[cfg(feature = "debug")]
    circuit_witness.check_correctness(&circuit);

    let instance_num_vars = circuit_witness.instance_num_vars();

    let (proof, output_num_vars, output_eval) = {
        let mut prover_transcript = Transcript::new(b"example");
        let output_num_vars = instance_num_vars + circuit.last_layer_ref().num_vars();

        let output_point = (0..output_num_vars)
            .map(|_| {
                prover_transcript
                    .get_and_append_challenge(b"output point")
                    .elements[0]
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
        let mut verifier_transcript = &mut Transcript::new(b"example");
        let output_point = (0..output_num_vars)
            .map(|_| {
                verifier_transcript
                    .get_and_append_challenge(b"output point")
                    .elements[0]
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
