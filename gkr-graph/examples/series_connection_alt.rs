use ff::Field;
use ff_ext::ExtensionField;
use gkr::{
    structs::{Circuit, PointAndEval},
    util::ceil_log2,
};
use gkr_graph::{
    error::GKRGraphError,
    structs::{
        CircuitGraphAuxInfo, CircuitGraphBuilder, IOPProverState, IOPVerifierState, NodeOutputType,
        PredType, TargetEvaluations,
    },
};
use goldilocks::{Goldilocks, GoldilocksExt2};
use multilinear_extensions::mle::DenseMultilinearExtension;
use simple_frontend::structs::{ChallengeId, CircuitBuilder, MixedCell};
use std::sync::Arc;
use transcript::Transcript;

fn construct_input<E: ExtensionField>(
    input_size: usize,
    challenge: ChallengeId,
) -> Arc<Circuit<E>> {
    let mut circuit_builder = CircuitBuilder::<E>::default();
    let (_, inputs) = circuit_builder.create_witness_in(input_size);
    let (_, lookup_inputs) = circuit_builder.create_ext_witness_out(input_size);

    for (i, input) in inputs.iter().enumerate() {
        // denominator = (input + challenge)
        circuit_builder.rlc(&lookup_inputs[i], &[*input], challenge);
    }
    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Construct a selector for n_instances and each instance contains `num`
/// items. `num` must be a power of 2.
pub(crate) fn construct_prefix_selector<E: ExtensionField>(
    n_instances: usize,
    num: usize,
) -> Arc<Circuit<E>> {
    assert_eq!(num, num.next_power_of_two());
    let mut circuit_builder = CircuitBuilder::<E>::default();
    let _ = circuit_builder.create_constant_in(n_instances * num, 1);
    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Construct a circuit to compute the inverse sum of two extension field
/// elements.
/// Wire in 0: 2 extension field elements.
/// Wire in 1: 2-bit selector.
/// output layer: the denominator and the numerator.
pub(crate) fn construct_inv_sum<E: ExtensionField>() -> Arc<Circuit<E>> {
    let mut circuit_builder = CircuitBuilder::<E>::default();
    let (_input_id, input) = circuit_builder.create_ext_witness_in(2);
    let (_cond_id, cond) = circuit_builder.create_witness_in(2);
    let (_, output) = circuit_builder.create_ext_witness_out(2);
    // selector denominator 1 or input[0] or input[0] * input[1]
    let den_mul = circuit_builder.create_ext_cell();
    circuit_builder.mul2_ext(&den_mul, &input[0], &input[1], E::BaseField::ONE);
    let tmp = circuit_builder.create_ext_cell();
    circuit_builder.sel_mixed_and_ext(
        &tmp,
        &MixedCell::Constant(E::BaseField::ONE),
        &input[0],
        cond[0],
    );
    circuit_builder.sel_ext(&output[0], &tmp, &den_mul, cond[1]);

    // select the numerator 0 or 1 or input[0] + input[1]
    let den_add = circuit_builder.create_ext_cell();
    circuit_builder.add_ext(&den_add, &input[0], E::BaseField::ONE);
    circuit_builder.add_ext(&den_add, &input[0], E::BaseField::ONE);
    circuit_builder.sel_mixed_and_ext(&output[1], &cond[0].into(), &den_add, cond[1]);

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

/// Construct a circuit to compute the sum of two fractions. The
/// denominators and numerators are on the extension field
/// Wire in 0: denominators, 2 extension field elements.
/// Wire in 1: numerators, 2 extensuin field elements.
/// Wire out 0: the denominator.
/// Wire out 1: the numerator.
pub(crate) fn construct_frac_sum_inner<E: ExtensionField>() -> Arc<Circuit<E>> {
    let mut circuit_builder = CircuitBuilder::<E>::default();
    let (_, input) = circuit_builder.create_ext_witness_in(4);
    let (_, output) = circuit_builder.create_ext_witness_out(2);
    // denominator
    circuit_builder.mul2_ext(
        &output[0], // output_den
        &input[0],  // input_den[0]
        &input[2],  // input_den[1]
        E::BaseField::ONE,
    );

    // numerator
    circuit_builder.mul2_ext(
        &output[1], // output_num
        &input[0],  // input_den[0]
        &input[3],  // input_num[1]
        E::BaseField::ONE,
    );
    circuit_builder.mul2_ext(
        &output[1], // output_num
        &input[2],  // input_den[1]
        &input[1],  // input_num[0]
        E::BaseField::ONE,
    );

    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

fn main() -> Result<(), GKRGraphError> {
    // ==================
    // Construct circuits
    // ==================

    let challenge_no = 0;
    let input_size = 4;
    let input_circuit = construct_input::<GoldilocksExt2>(input_size, challenge_no);
    let prefix_selector = construct_prefix_selector::<GoldilocksExt2>(1, input_size);
    let inv_sum_circuit = construct_inv_sum::<GoldilocksExt2>();
    let frac_sum_circuit = construct_frac_sum_inner::<GoldilocksExt2>();

    // ==================
    // Witness generation (only source)
    // ==================

    let input_circuit_wires_in = vec![
        Goldilocks::from(2u64),
        Goldilocks::from(2u64),
        Goldilocks::from(4u64),
        Goldilocks::from(16u64),
    ];

    // ==================
    // Graph construction
    // ==================

    let mut prover_graph_builder = CircuitGraphBuilder::<GoldilocksExt2>::default();
    let mut verifier_graph_builder = CircuitGraphBuilder::<GoldilocksExt2>::default();
    let mut prover_transcript = Transcript::<GoldilocksExt2>::new(b"test");
    let challenge = vec![
        prover_transcript
            .get_and_append_challenge(b"lookup challenge")
            .elements,
    ];

    let mut add_node_and_witness = |label: &'static str,
                                    circuit: &Arc<Circuit<_>>,
                                    preds: Vec<PredType>,
                                    challenges: Vec<_>,
                                    sources: Vec<DenseMultilinearExtension<_>>,
                                    num_instances: usize|
     -> Result<usize, GKRGraphError> {
        let prover_node_id = prover_graph_builder.add_node_with_witness(
            label,
            circuit,
            preds.clone(),
            challenges,
            sources,
            num_instances,
        )?;
        let verifier_node_id = verifier_graph_builder.add_node(label, circuit, preds)?;
        assert_eq!(prover_node_id, verifier_node_id);
        Ok(prover_node_id)
    };

    let input = add_node_and_witness(
        "input",
        &input_circuit,
        vec![PredType::Source],
        challenge,
        vec![DenseMultilinearExtension::from_evaluations_vec(
            ceil_log2(input_circuit_wires_in.len()),
            input_circuit_wires_in.clone(),
        )],
        1,
    )?;
    let selector = add_node_and_witness("selector", &prefix_selector, vec![], vec![], vec![], 1)?;

    let mut round_input_size = input_size.next_power_of_two();
    let inv_sum = add_node_and_witness(
        "inv_sum",
        &inv_sum_circuit,
        vec![
            PredType::PredWire(NodeOutputType::WireOut(input, 0)),
            PredType::PredWire(NodeOutputType::OutputLayer(selector)),
        ],
        vec![],
        vec![DenseMultilinearExtension::default(); 2],
        round_input_size >> 1,
    )?;
    round_input_size >>= 1;
    let mut frac_sum_input = NodeOutputType::WireOut(inv_sum, 0);
    while round_input_size > 1 {
        frac_sum_input = NodeOutputType::WireOut(
            add_node_and_witness(
                "frac_sum",
                &frac_sum_circuit,
                vec![PredType::PredWire(frac_sum_input)],
                vec![],
                vec![DenseMultilinearExtension::default(); 1],
                round_input_size >> 1,
            )?,
            0,
        );
        round_input_size >>= 1;
    }

    let (prover_graph, circuit_witness) = prover_graph_builder.finalize_graph_and_witness();
    let verifier_graph = verifier_graph_builder.finalize_graph();
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
        prover_transcript
            .get_and_append_challenge(b"output point")
            .elements,
    ];
    let output_eval = circuit_witness
        .node_witnesses
        .last()
        .unwrap()
        .output_layer_witness_ref()
        .evaluate(&output_point);
    let proof = IOPProverState::prove(
        &prover_graph,
        &circuit_witness,
        &TargetEvaluations(vec![PointAndEval::new(output_point, output_eval)]),
        &mut prover_transcript,
        1,
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
        verifier_transcript
            .get_and_append_challenge(b"output point")
            .elements,
    ];

    IOPVerifierState::verify(
        &verifier_graph,
        &challenge,
        &TargetEvaluations(vec![PointAndEval::new(output_point, output_eval)]),
        proof,
        &aux_info,
        &mut verifier_transcript,
    )?;

    Ok(())
}
