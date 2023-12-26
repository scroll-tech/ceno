use frontend::structs::{CellType, CircuitBuilder, ConstantType};
use gkr::structs::{
    Circuit, CircuitWitness, CircuitWitnessGenerator, IOPProverState, IOPVerifierState,
};
use goldilocks::{Goldilocks, SmallField};
use itertools::Itertools;
use transcript::Transcript;

enum TableType {
    FakeHashTable,
}

fn construct_circuit<F: SmallField>() -> Circuit<F> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let one = ConstantType::Field(F::ONE);
    let neg_one = ConstantType::Field(-F::ONE);

    let table_size = 4;
    let pow_of_xs = circuit_builder.create_cells(table_size);
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
        circuit_builder.assert_const(diff, F::ZERO);
    }
    circuit_builder.mark_cell(CellType::WireIn(0), pow_of_xs[0]);
    circuit_builder.mark_cells(CellType::OtherInWitness(0), &pow_of_xs[1..pow_of_xs.len()]);

    let table_type = TableType::FakeHashTable as usize;
    circuit_builder.define_table_type(table_type, CellType::OtherInWitness(1));
    for i in 0..table_size {
        circuit_builder.add_table_item(table_type, pow_of_xs[i]);
    }

    let inputs = circuit_builder.create_cells(5);
    circuit_builder.mark_cells(CellType::WireIn(1), &inputs);
    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

    circuit_builder.configure();
    circuit_builder.print_info();
    Circuit::<F>::new(&circuit_builder)
}

fn main() {
    let circuit = construct_circuit::<Goldilocks>();
    let wires_in = vec![
        vec![Goldilocks::from(2u64)],
        vec![
            Goldilocks::from(2u64),
            Goldilocks::from(2u64),
            Goldilocks::from(4u64),
            Goldilocks::from(16u64),
            Goldilocks::from(2u64),
        ],
    ];
    let other_witnesses = vec![
        vec![
            Goldilocks::from(4u64),
            Goldilocks::from(16u64),
            Goldilocks::from(256u64),
        ],
        vec![
            Goldilocks::from(3u64),
            Goldilocks::from(1u64),
            Goldilocks::from(1u64),
            Goldilocks::from(0u64),
        ],
    ];

    let wires_in_slices = wires_in.iter().map(|x| x.as_slice()).collect_vec();
    let other_witnesses_slices = other_witnesses.iter().map(|x| x.as_slice()).collect_vec();

    let circuit_witness = {
        let challenge = Goldilocks::from(9);
        let mut circuit_witness_gen = CircuitWitnessGenerator::new(&circuit, vec![challenge]);
        for _ in 0..4 {
            circuit_witness_gen.add_instance(&circuit, &wires_in_slices, &other_witnesses_slices);
        }
        CircuitWitness::new(circuit_witness_gen)
    };

    let (proof, output_log_size, output_eval) = {
        let mut prover_transcript = Transcript::new(b"example");
        let last_layer_witness = circuit_witness.last_layer_witness_ref();
        let output_log_size = last_layer_witness.log_size();

        let output_point = (0..output_log_size)
            .map(|_| prover_transcript.get_and_append_challenge(b"output point"))
            .collect_vec();

        let output_eval = last_layer_witness.evaluate(&output_point);
        (
            IOPProverState::prove_parallel(
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
            .collect_vec();
        IOPVerifierState::verify_parallel(
            &circuit,
            &[&output_point],
            &[output_eval],
            &proof,
            &mut verifier_transcript,
        )
        .expect("verification failed")
    };

    let all_inputs_witnesses = circuit_witness
        .wires_in_ref()
        .iter()
        .chain(circuit_witness.other_witnesses_ref().iter());
    let expected_values = all_inputs_witnesses
        .map(|witness| witness.truncate_point_and_evaluate(&gkr_input_claims.point))
        .collect_vec();
    for i in 0..gkr_input_claims.evaluations.len() {
        assert_eq!(expected_values[i], gkr_input_claims.evaluations[i]);
    }
}
