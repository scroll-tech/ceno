use std::mem;

use ff::Field;
use gkr::{
    structs::{Circuit, CircuitWitness, IOPProverState, IOPVerifierState},
    utils::MultilinearExtensionFromVectors,
};
use goldilocks::{Goldilocks, GoldilocksExt2, SmallField};
use itertools::Itertools;
use simple_frontend::structs::{ChallengeId, CircuitBuilder, MixedCell, WireId};
use transcript::Transcript;
struct InputCircuitIOIndex {
    // input
    inputs_idx: WireId,
    // output
    lookup_inputs_idx: WireId,
}

fn construct_input<F: SmallField>(
    challenge: usize,
    input_size: usize,
) -> (Circuit<F>, InputCircuitIOIndex) {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (inputs_idx, inputs) = circuit_builder.create_wire_in(input_size);
    let (lookup_inputs_idx, lookup_inputs) = circuit_builder.create_ext_wire_out(input_size);

    for (i, input) in inputs.iter().enumerate() {
        // denominator = (input + challenge)
        circuit_builder.rlc(&lookup_inputs[i], &[*input], challenge as ChallengeId);
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

fn construct_select<F: SmallField>(n_instances: usize, num: usize) -> Circuit<F> {
    assert_eq!(num, num.next_power_of_two());
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let _ = circuit_builder.create_constant_in(n_instances * num, 1);
    circuit_builder.configure();
    Circuit::new(&circuit_builder)
}

#[allow(dead_code)]
struct InvSumIOIndex {
    input_idx: WireId,
    sel_idx: WireId,
}

fn construct_inv_sum<F: SmallField>() -> (Circuit<F>, InvSumIOIndex) {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (input_idx, input) = circuit_builder.create_ext_wire_in(2);
    let (sel_idx, sel) = circuit_builder.create_wire_in(2);
    let output_den = circuit_builder.create_ext();
    let output_num = circuit_builder.create_ext();
    // selector denominator 1 or input[0] or input[0] * input[1]
    let den_mul = circuit_builder.create_ext();
    circuit_builder.mul2_ext(&den_mul, &input[0], &input[1], F::BaseField::ONE);
    let tmp = circuit_builder.create_ext();
    circuit_builder.sel_mixed_and_ext(
        &tmp,
        MixedCell::Constant(F::BaseField::ONE),
        &input[0],
        sel[0],
    );
    circuit_builder.sel_ext(&output_den, &tmp, &den_mul, sel[1]);

    // select the numerator 0 or 1 or input[0] + input[1]
    let den_add = circuit_builder.create_ext();
    circuit_builder.add_ext(&den_add, &input[0], &input[1]);
    circuit_builder.sel_mixed_and_ext(&output_num, sel[0].into(), &den_add, sel[1]);

    circuit_builder.configure();
    (
        Circuit::new(&circuit_builder),
        InvSumIOIndex { input_idx, sel_idx },
    )
}

#[allow(dead_code)]
struct FracSumIOIndexLeaf {
    input_den_idx: WireId,
    input_num_idx: WireId,
    sel_idx: WireId,
}

fn construct_frac_sum_leaf<F: SmallField>() -> (Circuit<F>, FracSumIOIndexLeaf) {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (input_den_idx, input_den) = circuit_builder.create_ext_wire_in(2);
    let (input_num_idx, input_num) = circuit_builder.create_wire_in(2);
    let (sel_idx, sel) = circuit_builder.create_wire_in(2);
    let output_den = circuit_builder.create_ext();
    let output_num = circuit_builder.create_ext();
    // selector denominator, 1 or input_den[0] or input_den[0] * input_den[1]
    let den_mul = circuit_builder.create_ext();
    circuit_builder.mul2_ext(&den_mul, &input_den[0], &input_den[1], F::BaseField::ONE);
    let tmp = circuit_builder.create_ext();
    circuit_builder.sel_mixed_and_ext(
        &tmp,
        MixedCell::Constant(F::BaseField::ONE),
        &input_den[0],
        sel[0],
    );
    circuit_builder.sel_ext(&output_den, &tmp, &den_mul, sel[1]);

    // select the numerator, 0 or input_num[0] or input_den[0] * input_num[1] + input_num[0] * input_den[1]
    let num = circuit_builder.create_ext();
    circuit_builder.mul_ext_base(&num, &input_den[0], input_num[1], F::BaseField::ONE);
    circuit_builder.mul_ext_base(&num, &input_den[1], input_num[0], F::BaseField::ONE);
    let tmp = circuit_builder.create_cell();
    circuit_builder.sel_mixed(
        tmp,
        MixedCell::Constant(F::BaseField::ZERO),
        input_num[0].into(),
        sel[0],
    );
    circuit_builder.sel_mixed_and_ext(&output_num, tmp.into(), &num, sel[1]);

    circuit_builder.configure();
    (
        Circuit::new(&circuit_builder),
        FracSumIOIndexLeaf {
            input_den_idx,
            input_num_idx,
            sel_idx,
        },
    )
}

struct FracSumIOIndex {
    input_den_idx: WireId,
    input_num_idx: WireId,
}

fn construct_frac_sum<F: SmallField>() -> (Circuit<F>, FracSumIOIndex) {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (input_den_idx, input_den) = circuit_builder.create_ext_wire_in(2);
    let (input_num_idx, input_num) = circuit_builder.create_ext_wire_in(2);
    let output_den = circuit_builder.create_ext();
    let output_num = circuit_builder.create_ext();
    // denominator
    circuit_builder.mul2_ext(&output_den, &input_den[0], &input_den[1], F::BaseField::ONE);

    // numerator
    let num = circuit_builder.create_ext();
    circuit_builder.mul2_ext(&output_num, &input_den[0], &input_num[1], F::BaseField::ONE);
    circuit_builder.mul2_ext(&output_num, &input_num[0], &input_den[1], F::BaseField::ONE);

    circuit_builder.configure();
    (
        Circuit::new(&circuit_builder),
        FracSumIOIndex {
            input_den_idx,
            input_num_idx,
        },
    )
}

fn main() {
    // ==================
    // Construct circuits
    // ==================

    // Construct circuit
    let challenge_no = 0;
    let input_size = 4;
    let instance_size = 4;
    let (input_circuit, input_circuit_io_index) =
        construct_input::<GoldilocksExt2>(challenge_no, input_size);
    let (inv_sum_circuit, inv_sum_io_index) = construct_inv_sum::<GoldilocksExt2>();
    let (frac_sum_circuit, _) = construct_frac_sum::<GoldilocksExt2>();

    // ==================
    // Witness generation
    // ==================

    let mut prover_transcript = Transcript::<GoldilocksExt2>::new(b"test");
    let challenge = [prover_transcript
        .get_and_append_challenge(b"lookup challenge")
        .elements];

    // Compute lookup input and output (lookup_input + beta)
    let mut input_circuit_witness =
        CircuitWitness::<Goldilocks>::new(&input_circuit, challenge.to_vec());
    let mut input_circuit_wires_in = vec![vec![]; input_circuit.n_wires_in];
    input_circuit_wires_in[input_circuit_io_index.inputs_idx as usize] = vec![
        Goldilocks::from(2u64),
        Goldilocks::from(2u64),
        Goldilocks::from(4u64),
        Goldilocks::from(16u64),
    ];

    for _ in 0..instance_size {
        input_circuit_witness.add_instance(&input_circuit, &input_circuit_wires_in);
    }

    println!("input_circuit: {:?}", input_circuit);
    println!("input_circuit_witness: {:?}", input_circuit_witness);

    // Pad (lookup_input + beta) with zeros, only compute the first 3 instances.
    let select_circuit = construct_select::<GoldilocksExt2>(3, input_size);
    let mut select_circuit_witness = CircuitWitness::new(&select_circuit, vec![]);
    println!("select_circuit_witness_wires_in: []");
    select_circuit_witness.add_instance(&select_circuit, &[]);

    // Compute the sum(1 / (lookup_input + beta))
    let mut inv_sum_witness = CircuitWitness::new(&inv_sum_circuit, vec![]);
    let select_output = &select_circuit_witness.last_layer_witness_ref()[0];
    let mut sels = select_output.chunks(2).map(|x| x.to_vec()).collect_vec();
    let mut inv_sum_inputs = input_circuit_witness.wires_out_ref()[0]
        .iter()
        .flatten()
        .cloned()
        .collect_vec()
        .chunks(2 * GoldilocksExt2::DEGREE)
        .map(|x| x.to_vec())
        .collect_vec();

    println!("inv_sum_inputs: {:?}", inv_sum_inputs);
    println!("sels: {:?}", sels);

    for i in 0..sels.len() {
        let mut wires_in = vec![vec![]; 2];
        wires_in[inv_sum_io_index.input_idx as usize] = mem::take(&mut inv_sum_inputs[i]);
        wires_in[inv_sum_io_index.sel_idx as usize] = mem::take(&mut sels[i]);
        inv_sum_witness.add_instance(&inv_sum_circuit, &wires_in);
    }

    let mut frac_sum_witnesses = vec![];
    let mut frac_sum_output = inv_sum_witness.wires_out_ref();
    while frac_sum_output.len() > 1 {
        println!("frac_sum_output: {:?}", frac_sum_output);
        let mut frac_sum_witness = CircuitWitness::new(&frac_sum_circuit, vec![]);
        let frac_sum_wires_in: Vec<Vec<Goldilocks>> = frac_sum_output;
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
            .elements,
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
        &select_circuit,
        &select_circuit_witness,
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

    let mut verifier_transcript = Transcript::<GoldilocksExt2>::new(b"test");
    let challenge = [verifier_transcript
        .get_and_append_challenge(b"lookup challenge")
        .elements];

    // prove frac sum
    let mut output_point = vec![
        verifier_transcript
            .get_and_append_challenge(b"output point")
            .elements,
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
        &select_circuit,
        &[],
        &[(output_point, output_value)],
        &[],
        &lookup_circuit_proofs[frac_sum_witnesses.len() + 1],
        select_circuit_witness.instance_num_vars(),
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
                    input_circuit.max_wires_in_num_vars.unwrap(),
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
