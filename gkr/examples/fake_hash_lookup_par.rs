use frontend::structs::CircuitBuilder;
use gkr::structs::{Circuit, CircuitWitness, IOPProverState, IOPVerifierState};
use goldilocks::{Goldilocks, SmallField};
use transcript::Transcript;

enum TableType {
    FakeHashTable,
}

fn construct_circuit<F: SmallField>() -> Circuit<F> {
    let public_input_idx = 0;

    let mut circuit_builder = CircuitBuilder::<F>::new();

    let pow_of_xs = circuit_builder.create_cells(4);
    let one = F::from(1u64);
    for i in 0..4 {
        circuit_builder.mul2(pow_of_xs[i + 1], pow_of_xs[i], pow_of_xs[0], one);
    }

    // Public input [x].
    circuit_builder.mark_cell(public_input_idx, pow_of_xs[0]);

    // Define a table with x^0, x^1, ..., x^4.
    let table_type = TableType::FakeHashTable as usize;
    circuit_builder.define_table_type(table_type);
    circuit_builder.add_table_item_const(table_type, one);
    for i in 0..4 {
        circuit_builder.add_table_item(table_type, pow_of_xs[i]);
    }

    let inputs = circuit_builder.create_cells(5);
    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    // First input vector [input_0, ..., input_4].
    circuit_builder.mark_cells(public_input_idx + 1, &inputs);

    circuit_builder.configure();
    Circuit::<F>::new(&circuit_builder)
}

fn main() {
    let circuit = construct_circuit::<Goldilocks>();
    let public_input = vec![Goldilocks::from(2u64)];
    let witness = vec![
        Goldilocks::from(1u64),
        Goldilocks::from(2u64),
        Goldilocks::from(4u64),
        Goldilocks::from(1u64),
        Goldilocks::from(2u64),
    ];
    let mut circuit_witness = CircuitWitness::new(&circuit);

    for _ in 0..4 {
        circuit_witness.add_instance(&circuit, &public_input, &[&witness]);
    }

    let (proof, output_log_size, output_eval) = {
        let mut prover_transcript = Transcript::new(b"example");
        let last_layer_witness = circuit_witness.last_layer_witness_ref();
        let output_log_size = last_layer_witness.log_size();

        let output_point = (0..output_log_size)
            .map(|_| prover_transcript.get_and_append_challenge(b"output point"))
            .collect::<Vec<_>>();

        let output_eval = last_layer_witness.evaluate(&output_point);
        (
            IOPProverState::prove(
                &circuit,
                &circuit_witness,
                &[&output_point],
                &[output_eval],
                &mut prover_transcript,
            ),
            output_log_size,
            output_eval,
        )
    };

    let gkr_input_claims = {
        let mut verifier_transcript = &mut Transcript::new(b"example");
        let output_point = (0..output_log_size)
            .map(|_| verifier_transcript.get_and_append_challenge(b"output point"))
            .collect::<Vec<_>>();
        IOPVerifierState::verify(
            &circuit,
            &[&output_point],
            &[output_eval],
            &proof,
            &mut verifier_transcript,
        )
        .expect("verification failed")
    };

    let mut expected_values = vec![circuit_witness
        .public_input_ref()
        .evaluate(&gkr_input_claims.points[0])];

    for i in 1..gkr_input_claims.points.len() {
        expected_values
            .push(circuit_witness.witness_ref()[i - 1].evaluate(&gkr_input_claims.points[i]));
    }

    for i in 0..gkr_input_claims.points.len() {
        assert_eq!(expected_values[i], gkr_input_claims.evaluations[i]);
    }
}
