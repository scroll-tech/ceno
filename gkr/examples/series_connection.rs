use frontend::structs::{CircuitBuilder, ConstantType};
use gkr::{
    structs::{Circuit, CircuitWitness, IOPProof, IOPProverState, IOPVerifierState},
    utils::MultilinearExtensionFromVectors,
};
use goldilocks::{Goldilocks, SmallField};
use itertools::Itertools;
use transcript::Transcript;
struct InputCircuitIOIndex {
    // input
    inputs_idx: usize,
    // output
    lookup_inputs_idx: usize,
}

fn construct_input<F: SmallField>(challenge: usize) -> (Circuit<F>, InputCircuitIOIndex) {
    let input_size = 5;
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (inputs_idx, inputs) = circuit_builder.create_wire_in(input_size);
    let (lookup_inputs_idx, lookup_inputs) = circuit_builder.create_wire_out(input_size);

    for (i, input) in inputs.iter().enumerate() {
        // denominator = (input + challenge)
        circuit_builder.add(lookup_inputs[i], *input, ConstantType::Field(F::ONE));
        circuit_builder.add_const(lookup_inputs[i], ConstantType::Challenge(challenge));
    }
    circuit_builder.configure();
    (
        Circuit::new(&circuit_builder),
        InputCircuitIOIndex {
            inputs_idx,
            lookup_inputs_idx,
        },
    )
}

#[allow(dead_code)]
struct TableCircuitIOIndex {
    // input
    x_idx: usize,
    other_x_pows_idx: usize,
    counts_idx: usize,
    // output
    lookup_tables_idx: usize,
}

#[allow(dead_code)]
fn construct_table<F: SmallField>(challenge: usize) -> (Circuit<F>, TableCircuitIOIndex) {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let one = ConstantType::Field(F::ONE);
    let neg_one = ConstantType::Field(-F::ONE);

    let table_size = 4;
    let (x_idx, x) = circuit_builder.create_wire_in(1);
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

    let (counts_idx, counts) = circuit_builder.create_wire_in(table_size);
    let (lookup_tables_idx, lookup_tables) = circuit_builder.create_wire_out(table_size * 2);
    for (i, table) in pow_of_xs.iter().enumerate() {
        // denominator = (table + challenge)
        circuit_builder.add(lookup_tables[i << 1], *table, ConstantType::Field(F::ONE));
        circuit_builder.add_const(lookup_tables[i << 1], ConstantType::Challenge(challenge));
        // numerator = counts[i]
        circuit_builder.add(
            lookup_tables[(i << 1) ^ 1],
            counts[i],
            ConstantType::Field(F::ONE),
        );
    }
    circuit_builder.configure();
    (
        Circuit::new(&circuit_builder),
        TableCircuitIOIndex {
            x_idx,
            other_x_pows_idx,
            counts_idx,
            lookup_tables_idx,
        },
    )
}

#[allow(dead_code)]
struct PadWithConstIOIndex {
    // input
    original_input_idx: usize,
}

fn construct_pad_with_const<F: SmallField>(constant: i64) -> (Circuit<F>, PadWithConstIOIndex) {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (original_input_idx, _) = circuit_builder.create_wire_in(5);
    let _ = circuit_builder.create_constant_in(3, constant);
    circuit_builder.configure();
    (
        Circuit::new(&circuit_builder),
        PadWithConstIOIndex { original_input_idx },
    )
}

#[allow(dead_code)]
struct InvSumIOIndex {
    input_idx: usize,
}

fn construct_inv_sum<F: SmallField>() -> (Circuit<F>, InvSumIOIndex) {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (input_idx, input) = circuit_builder.create_wire_in(2);
    let output = circuit_builder.create_cells(2);
    circuit_builder.mul2(output[0], input[0], input[1], ConstantType::Field(F::ONE));
    circuit_builder.add(output[1], input[0], ConstantType::Field(F::ONE));
    circuit_builder.add(output[1], input[1], ConstantType::Field(F::ONE));
    circuit_builder.configure();
    (Circuit::new(&circuit_builder), InvSumIOIndex { input_idx })
}

#[allow(dead_code)]
struct FracSumIOIndex {
    input_idx: usize,
}

fn construct_frac_sum<F: SmallField>() -> (Circuit<F>, FracSumIOIndex) {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    // (den1, num1, den2, num2)
    let (input_idx, input) = circuit_builder.create_wire_in(4);
    let output = circuit_builder.create_cells(2);
    circuit_builder.mul2(output[0], input[0], input[2], ConstantType::Field(F::ONE));
    circuit_builder.mul2(output[1], input[0], input[3], ConstantType::Field(F::ONE));
    circuit_builder.mul2(output[1], input[1], input[2], ConstantType::Field(F::ONE));
    circuit_builder.configure();
    (Circuit::new(&circuit_builder), FracSumIOIndex { input_idx })
}

fn main() {
    // ==================
    // Construct circuits
    // ==================

    // Construct circuit
    let challenge_no = 0;
    let (input_circuit, input_circuit_io_index) = construct_input::<Goldilocks>(challenge_no);
    let (pad_with_one_circuit, _) = construct_pad_with_const::<Goldilocks>(1);
    let (inv_sum_circuit, _) = construct_inv_sum::<Goldilocks>();
    let (frac_sum_circuit, _) = construct_frac_sum::<Goldilocks>();

    // ==================
    // Witness generation
    // ==================

    let mut prover_transcript = Transcript::new(b"test");
    let challenge = [prover_transcript
        .get_and_append_challenge(b"lookup challenge")
        .elements[0]];

    // Compute lookup input and output (lookup_input + beta)
    let mut input_circuit_witness = CircuitWitness::new(&input_circuit, challenge.to_vec());
    let mut input_circuit_wires_in = vec![vec![]; input_circuit.n_wires_in];
    input_circuit_wires_in[input_circuit_io_index.inputs_idx] = vec![
        Goldilocks::from(2u64),
        Goldilocks::from(2u64),
        Goldilocks::from(4u64),
        Goldilocks::from(16u64),
        Goldilocks::from(2u64),
    ];

    input_circuit_witness.add_instance(&input_circuit, &input_circuit_wires_in);

    println!("input_circuit: {:?}", input_circuit);
    println!("input_circuit_witness: {:?}", input_circuit_witness);

    // Pad (lookup_input + beta) with zeros
    let mut input_pad_with_zero_witness = CircuitWitness::new(&pad_with_one_circuit, vec![]);
    let input_pad_with_zero_wires_in =
        &input_circuit_witness.wires_out_ref()[input_circuit_io_index.lookup_inputs_idx];
    println!(
        "input_pad_with_zero_wires_in: {:?}",
        input_pad_with_zero_wires_in
    );
    input_pad_with_zero_witness.add_instance(
        &pad_with_one_circuit,
        &input_pad_with_zero_wires_in.to_vec(),
    );

    // Compute the sum(1 / (lookup_input + beta))
    let mut inv_sum_witness = CircuitWitness::new(&inv_sum_circuit, vec![]);
    let input_pad_with_zero_output = &input_pad_with_zero_witness.last_layer_witness_ref()[0];
    let lookup_input_inv_sum_wires_in = input_pad_with_zero_output.chunks(2);

    for wire_in in lookup_input_inv_sum_wires_in {
        inv_sum_witness.add_instance(&inv_sum_circuit, &[wire_in.to_vec()]);
    }

    let mut frac_sum_witnesses = vec![];
    let mut frac_sum_output = inv_sum_witness.last_layer_witness_ref().to_vec();
    while frac_sum_output.len() > 1 {
        println!("frac_sum_output: {:?}", frac_sum_output);
        let mut frac_sum_witness = CircuitWitness::new(&frac_sum_circuit, vec![]);
        let frac_sum_wires_in: Vec<Vec<Goldilocks>> = frac_sum_output
            .chunks(2)
            .map(|chunk| chunk.iter().flatten().cloned().collect())
            .collect();
        for wire_in in frac_sum_wires_in {
            frac_sum_witness.add_instance(&frac_sum_circuit, &[wire_in.to_vec()]);
        }
        frac_sum_output = frac_sum_witness.last_layer_witness_ref().to_vec();
        frac_sum_witnesses.push(frac_sum_witness);
    }
    println!("frac_sum_output: {:?}", frac_sum_output);

    // =================
    // Proofs generation
    // =================

    let mut lookup_circuit_proofs = vec![];

    // prove frac sum
    let mut output_point = vec![
        prover_transcript
            .get_and_append_challenge(b"output point")
            .elements[0],
    ];
    let output_witness = frac_sum_witnesses[frac_sum_witnesses.len() - 1].last_layer_witness_ref();
    let mut output_value = output_witness.mle(1, 0).evaluate(&output_point);
    for frac_sum_witness in frac_sum_witnesses.iter().rev() {
        println!("output_point: {:?}", output_point);
        println!("output_value: {:?}", output_value);
        let proof = IOPProverState::prove_parallel(
            &frac_sum_circuit,
            frac_sum_witness,
            &[(output_point, output_value)],
            &[],
            &mut prover_transcript,
        );
        let last_sumcheck_proof = proof.sumcheck_proofs.last().unwrap();
        output_point = last_sumcheck_proof.1.sumcheck_proofs[0].point.clone();
        output_value = last_sumcheck_proof.1.sumcheck_eval_values[0][0];
        lookup_circuit_proofs.push(proof);
    }

    // prove inv sum
    let proof = IOPProverState::prove_parallel(
        &inv_sum_circuit,
        &inv_sum_witness,
        &[(output_point, output_value)],
        &[],
        &mut prover_transcript,
    );

    let last_sumcheck_proof = proof.sumcheck_proofs.last().unwrap();
    output_point = last_sumcheck_proof.1.sumcheck_proofs[0].point.clone();
    output_value = last_sumcheck_proof.1.sumcheck_eval_values[0][0];
    lookup_circuit_proofs.push(proof);

    let proof = IOPProverState::prove_parallel(
        &pad_with_one_circuit,
        &input_pad_with_zero_witness,
        &[(output_point, output_value)],
        &[],
        &mut prover_transcript,
    );

    let last_sumcheck_proof = proof.sumcheck_proofs.last().unwrap();
    output_point = last_sumcheck_proof.1.sumcheck_proofs[0].point.clone();
    output_value = last_sumcheck_proof.1.sumcheck_eval_values[0][0];
    lookup_circuit_proofs.push(proof);

    let proof = IOPProverState::prove_parallel(
        &input_circuit,
        &input_circuit_witness,
        &vec![],
        &[(output_point, output_value)],
        &mut prover_transcript,
    );

    lookup_circuit_proofs.push(proof);

    // =============
    // Verify proofs
    // =============

    let mut verifier_transcript = Transcript::<Goldilocks>::new(b"test");
    let challenge = [verifier_transcript
        .get_and_append_challenge(b"lookup challenge")
        .elements[0]];

    // prove frac sum
    let mut output_point = vec![
        verifier_transcript
            .get_and_append_challenge(b"output point")
            .elements[0],
    ];
    let output_witness = frac_sum_witnesses[frac_sum_witnesses.len() - 1].last_layer_witness_ref();
    let mut output_value = output_witness.mle(1, 0).evaluate(&output_point);
    for (proof, frac_sum_witness) in lookup_circuit_proofs
        .iter()
        .take(frac_sum_witnesses.len())
        .zip(frac_sum_witnesses.iter().rev())
    {
        println!("output_point: {:?}", output_point);
        println!("output_value: {:?}", output_value);
        let claim = IOPVerifierState::verify_parallel(
            &frac_sum_circuit,
            &[],
            &[(output_point, output_value)],
            &[],
            &proof,
            frac_sum_witness.instance_num_vars(),
            &mut verifier_transcript,
        )
        .expect("verification failed: fraction summation");
        output_point = claim.point;
        output_value = claim.values[0];
    }

    // prove inv sum
    let claim = IOPVerifierState::verify_parallel(
        &inv_sum_circuit,
        &[],
        &[(output_point, output_value)],
        &[],
        &lookup_circuit_proofs[frac_sum_witnesses.len()],
        inv_sum_witness.instance_num_vars(),
        &mut verifier_transcript,
    )
    .expect("verification failed: inverse summation");
    output_point = claim.point;
    output_value = claim.values[0];

    let claim = IOPVerifierState::verify_parallel(
        &pad_with_one_circuit,
        &[],
        &[(output_point, output_value)],
        &[],
        &lookup_circuit_proofs[frac_sum_witnesses.len() + 1],
        input_pad_with_zero_witness.instance_num_vars(),
        &mut verifier_transcript,
    )
    .expect("verification failed: pad with one");
    output_point = claim.point;
    output_value = claim.values[0];

    let claim = IOPVerifierState::verify_parallel(
        &input_circuit,
        &challenge,
        &vec![],
        &[(output_point, output_value)],
        &lookup_circuit_proofs[frac_sum_witnesses.len() + 2],
        input_circuit_witness.instance_num_vars(),
        &mut verifier_transcript,
    )
    .expect("verification failed: input circuit");

    let expected_values = input_circuit_witness
        .wires_in_ref()
        .iter()
        .map(|witness| {
            witness
                .as_slice()
                .mle(
                    input_circuit.max_wires_in_num_vars,
                    input_circuit_witness.instance_num_vars(),
                )
                .evaluate(&claim.point)
        })
        .collect_vec();
    for i in 0..claim.values.len() {
        assert_eq!(expected_values[i], claim.values[i]);
    }
    println!("circuit series succeeded!");
}
