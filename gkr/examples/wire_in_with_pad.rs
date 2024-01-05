use frontend::structs::CircuitBuilder;
use gkr::{
    structs::{Circuit, CircuitWitness, IOPProverState, IOPVerifierState},
    utils::MultilinearExtensionFromVectors,
};
use goldilocks::Goldilocks;
use itertools::Itertools;
use multilinear_extensions::virtual_poly::build_eq_x_r_vec;
use transcript::Transcript;

fn main() {
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
    let (wire_in_idx, _) = circuit_builder.create_wire_in(5);
    let _ = circuit_builder.create_constant_in(3, 1);
    assert!(wire_in_idx == 0);
    circuit_builder.configure();
    let circuit = Circuit::new(&circuit_builder);
    let wires_in = vec![vec![
        Goldilocks::from(2),
        Goldilocks::from(3),
        Goldilocks::from(4),
        Goldilocks::from(5),
        Goldilocks::from(6),
    ]];

    // print!("circuit: {:?}", circuit);
    let mut witness = CircuitWitness::new(&circuit, vec![]);
    witness.add_instance(&circuit, &wires_in);

    // print!("witness: {:?}", witness);

    let mut prover_transcript = Transcript::<Goldilocks>::new(b"test");
    let point: Vec<Goldilocks> = (0..3)
        .map(|_| {
            prover_transcript
                .get_and_append_challenge(b"output point")
                .elements
        })
        .collect_vec();
    let eq_point = build_eq_x_r_vec(&point);
    let value = wires_in[0]
        .iter()
        .zip(eq_point.iter())
        .map(|(x, y)| *x * y)
        .sum::<Goldilocks>()
        + eq_point.iter().skip(5).sum::<Goldilocks>();

    let proof = IOPProverState::prove_parallel(
        &circuit,
        &witness,
        &[(point, value)],
        &[],
        &mut prover_transcript,
    );

    let mut verifier_transcript = Transcript::<Goldilocks>::new(b"test");
    let point: Vec<Goldilocks> = (0..3)
        .map(|_| {
            verifier_transcript
                .get_and_append_challenge(b"output point")
                .elements
        })
        .collect_vec();
    let gkr_final_claim = IOPVerifierState::verify_parallel(
        &circuit,
        &[],
        &[(point, value)],
        &[],
        &proof,
        0,
        &mut verifier_transcript,
    )
    .expect("verification failed");

    let expected_value = wires_in
        .as_slice()
        .mle(circuit.max_wires_in_num_vars, 0)
        .evaluate(&gkr_final_claim.point);
    assert_eq!(expected_value, gkr_final_claim.values[0]);

    println!("verification succeeded");
}
