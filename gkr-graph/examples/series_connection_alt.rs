use ff::Field;
use gkr::{
    structs::{Circuit, PointAndEval},
    utils::MultilinearExtensionFromVectors,
};
use gkr_graph::{
    error::GKRGraphError,
    structs::{
        CircuitGraphAuxInfo, CircuitGraphBuilder, IOPProverState, IOPVerifierState, NodeOutputType,
        PredType, TargetEvaluations,
    },
};
use goldilocks::{Goldilocks, GoldilocksExt2, SmallField};
use simple_frontend::structs::{ChallengeConst, CircuitBuilder, ConstantType};
use std::sync::Arc;
use transcript::Transcript;

fn construct_input<F: SmallField>(challenge: usize) -> Arc<Circuit<F>> {
    let input_size = 5;
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, inputs) = circuit_builder.create_wire_in(input_size);
    let (_, lookup_inputs) = circuit_builder.create_wire_out(input_size);

    for (i, input) in inputs.iter().enumerate() {
        // denominator = (input + challenge)
        circuit_builder.add(lookup_inputs[i], *input, F::BaseField::ONE);

        let challenge_cost = ChallengeConst {
            challenge: challenge as u8,
            exp: 1,
        };
        circuit_builder
            .add_const_type(lookup_inputs[i], ConstantType::Challenge(challenge_cost, 0));
    }
    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

fn construct_pad_with_const<F: SmallField>(constant: i64) -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, _) = circuit_builder.create_wire_in(5);
    let _ = circuit_builder.create_constant_in(3, constant);
    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

fn construct_inv_sum<F: SmallField>() -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, input) = circuit_builder.create_wire_in(2);
    let output = circuit_builder.create_cells(2);
    circuit_builder.mul2(output[0], input[0], input[1], F::BaseField::ONE);
    circuit_builder.add(output[1], input[0], F::BaseField::ONE);
    circuit_builder.add(output[1], input[1], F::BaseField::ONE);
    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

fn construct_frac_sum<F: SmallField>() -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    // (den1, num1, den2, num2)
    let (_, input) = circuit_builder.create_wire_in(4);
    let output = circuit_builder.create_cells(2);
    circuit_builder.mul2(output[0], input[0], input[2], F::BaseField::ONE);
    circuit_builder.mul2(output[1], input[0], input[3], F::BaseField::ONE);
    circuit_builder.mul2(output[1], input[1], input[2], F::BaseField::ONE);
    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

fn main() -> Result<(), GKRGraphError> {
    // ==================
    // Construct circuits
    // ==================

    let challenge_no = 0;
    let input_circuit = construct_input::<GoldilocksExt2>(challenge_no);
    let pad_with_one_circuit = construct_pad_with_const::<GoldilocksExt2>(1);
    let inv_sum_circuit = construct_inv_sum::<GoldilocksExt2>();
    let frac_sum_circuit = construct_frac_sum::<GoldilocksExt2>();

    // ==================
    // Witness generation (only source)
    // ==================

    let input_circuit_wires_in = vec![
        Goldilocks::from(2u64),
        Goldilocks::from(2u64),
        Goldilocks::from(4u64),
        Goldilocks::from(16u64),
        Goldilocks::from(2u64),
        Goldilocks::from(0),
        Goldilocks::from(0),
        Goldilocks::from(0),
    ];

    // ==================
    // Graph construction
    // ==================

    let mut graph_builder = CircuitGraphBuilder::<GoldilocksExt2>::new();
    let mut prover_transcript = Transcript::<GoldilocksExt2>::new(b"test");
    let challenge = vec![
        prover_transcript
            .get_and_append_challenge(b"lookup challenge")
            .elements,
    ];

    let input = {
        graph_builder.add_node_with_witness(
            "input",
            &input_circuit,
            vec![PredType::Source],
            challenge,
            // input_circuit_wires_in.clone()
            vec![vec![input_circuit_wires_in.clone()]],
        )?
    };
    let pad_with_one = graph_builder.add_node_with_witness(
        "pad_with_one",
        &pad_with_one_circuit,
        vec![PredType::PredWire(NodeOutputType::WireOut(input, 0))],
        vec![],
        vec![vec![]],
    )?;
    let mut input_size = input_circuit_wires_in.len();
    let inv_sum = graph_builder.add_node_with_witness(
        "inv_sum",
        &inv_sum_circuit,
        vec![PredType::PredWire(NodeOutputType::OutputLayer(
            pad_with_one,
        ))],
        vec![],
        vec![vec![]; input_size / 2],
    )?;
    input_size >>= 1;
    let mut frac_sum_input = inv_sum;
    while input_size > 1 {
        frac_sum_input = graph_builder.add_node_with_witness(
            "frac_sum",
            &frac_sum_circuit,
            vec![PredType::PredWire(NodeOutputType::OutputLayer(
                frac_sum_input,
            ))],
            vec![],
            vec![vec![]; input_size / 2],
        )?;
        input_size >>= 1;
    }

    let (graph, circuit_witness) = graph_builder.finalize();
    let aux_info = CircuitGraphAuxInfo {
        instance_num_vars: circuit_witness
            .node_witnesses
            .iter()
            .map(|witness| witness.instance_num_vars())
            .collect(),
    };

    // =================
    // Proofs generation
    // =================
    let output_point = vec![
        prover_transcript
            .get_and_append_challenge(b"output point")
            .elements,
    ];
    let output_eval = circuit_witness
        .node_witnesses
        .last()
        .unwrap()
        .last_layer_witness_ref()
        .mle(1, 0)
        .evaluate(&output_point);
    let proof = IOPProverState::prove(
        &graph,
        &circuit_witness,
        &TargetEvaluations(vec![PointAndEval::new(output_point, output_eval)]),
        &mut prover_transcript,
    )?;

    // =============
    // Verify proofs
    // =============

    let mut verifier_transcript = Transcript::<GoldilocksExt2>::new(b"test");
    let challenge = [verifier_transcript
        .get_and_append_challenge(b"lookup challenge")
        .elements];

    let output_point = vec![
        verifier_transcript
            .get_and_append_challenge(b"output point")
            .elements,
    ];

    IOPVerifierState::verify(
        &graph,
        &challenge,
        &TargetEvaluations(vec![PointAndEval::new(output_point, output_eval)]),
        &proof,
        &aux_info,
        &mut verifier_transcript,
    )?;

    Ok(())
}
