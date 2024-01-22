use ff::Field;
use gkr::{
    structs::{Circuit, LayerWitness, PointAndEval},
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
use simple_frontend::structs::{ChallengeId, CircuitBuilder, MixedCell, WitnessId};
use std::sync::Arc;
use transcript::Transcript;

fn construct_input<F: SmallField>(input_size: usize, challenge: ChallengeId) -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, inputs) = circuit_builder.create_witness_in(input_size);
    let (_, lookup_inputs) = circuit_builder.create_ext_witness_out(input_size);

    for (i, input) in inputs.iter().enumerate() {
        // denominator = (input + challenge)
        circuit_builder.rlc(&lookup_inputs[i], &[*input], challenge);
    }
    circuit_builder.configure();
    Arc::new(Circuit::new(&circuit_builder))
}

#[derive(Clone, Debug)]
pub(crate) struct PrefixSelectorCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
}

#[derive(Clone, Debug)]
pub(crate) struct LeafFracSumCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) input_den_id: WitnessId,
    pub(crate) input_num_id: WitnessId,
    pub(crate) cond_id: WitnessId,
}

#[derive(Clone, Debug)]
pub(crate) struct LeafFracSumNoSelectorCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) input_den_id: WitnessId,
    pub(crate) input_num_id: WitnessId,
}

#[derive(Clone, Debug)]
pub(crate) struct LeafCircuit<F: SmallField> {
    pub(crate) circuit: Arc<Circuit<F>>,
    pub(crate) input_id: WitnessId,
    pub(crate) cond_id: WitnessId,
}

/// Construct a selector for n_instances and each instance contains `num`
/// items. `num` must be a power of 2.
pub(crate) fn construct_prefix_selector<F: SmallField>(
    n_instances: usize,
    num: usize,
) -> PrefixSelectorCircuit<F> {
    assert_eq!(num, num.next_power_of_two());
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let _ = circuit_builder.create_constant_in(n_instances * num, 1);
    circuit_builder.configure();
    PrefixSelectorCircuit {
        circuit: Arc::new(Circuit::new(&circuit_builder)),
    }
}

/// Construct a circuit to compute the inverse sum of two extension field
/// elements.
/// Wire in 0: 2 extension field elements.
/// Wire in 1: 2-bit selector.
/// output layer: the denominator and the numerator.
pub(crate) fn construct_inv_sum<F: SmallField>() -> LeafCircuit<F> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (input_id, input) = circuit_builder.create_ext_witness_in(2);
    let (cond_id, cond) = circuit_builder.create_witness_in(2);
    let (_, output) = circuit_builder.create_ext_witness_out(2);
    // selector denominator 1 or input[0] or input[0] * input[1]
    let den_mul = circuit_builder.create_ext_cell();
    circuit_builder.mul2_ext(&den_mul, &input[0], &input[1], F::BaseField::ONE);
    let tmp = circuit_builder.create_ext_cell();
    circuit_builder.sel_mixed_and_ext(
        &tmp,
        &MixedCell::Constant(F::BaseField::ONE),
        &input[0],
        cond[0],
    );
    circuit_builder.sel_ext(&output[0], &tmp, &den_mul, cond[1]);

    // select the numerator 0 or 1 or input[0] + input[1]
    let den_add = circuit_builder.create_ext_cell();
    circuit_builder.add_ext(&den_add, &input[0], F::BaseField::ONE);
    circuit_builder.add_ext(&den_add, &input[0], F::BaseField::ONE);
    circuit_builder.sel_mixed_and_ext(&output[1], &cond[0].into(), &den_add, cond[1]);

    circuit_builder.configure();
    LeafCircuit {
        circuit: Arc::new(Circuit::new(&circuit_builder)),
        input_id,
        cond_id,
    }
}

/// Construct a circuit to compute the sum of two fractions. The
/// denominators and numerators are on the extension field
/// Wire in 0: denominators, 2 extension field elements.
/// Wire in 1: numerators, 2 extensuin field elements.
/// Wire out 0: the denominator.
/// Wire out 1: the numerator.
pub(crate) fn construct_frac_sum_inner<F: SmallField>() -> Arc<Circuit<F>> {
    let mut circuit_builder = CircuitBuilder::<F>::new();
    let (_, input) = circuit_builder.create_ext_witness_in(4);
    let (_, output) = circuit_builder.create_ext_witness_out(2);
    // denominator
    circuit_builder.mul2_ext(
        &output[0], // output_den
        &input[0],  // input_den[0]
        &input[2],  // input_den[1]
        F::BaseField::ONE,
    );

    // numerator
    circuit_builder.mul2_ext(
        &output[1], // output_num
        &input[0],  // input_den[0]
        &input[3],  // input_num[1]
        F::BaseField::ONE,
    );
    circuit_builder.mul2_ext(
        &output[1], // output_num
        &input[2],  // input_den[1]
        &input[1],  // input_num[0]
        F::BaseField::ONE,
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
            vec![LayerWitness {
                instances: vec![input_circuit_wires_in.clone()],
            }],
            1,
        )?
    };
    let selector = graph_builder.add_node_with_witness(
        "selector",
        &prefix_selector.circuit,
        vec![],
        vec![],
        vec![],
        1,
    )?;

    let mut round_input_size = input_size.next_power_of_two();
    let inv_sum = graph_builder.add_node_with_witness(
        "inv_sum",
        &inv_sum_circuit.circuit,
        vec![
            PredType::PredWire(NodeOutputType::WireOut(input, 0)),
            PredType::PredWire(NodeOutputType::OutputLayer(selector)),
        ],
        vec![],
        vec![],
        round_input_size >> 1,
    )?;
    round_input_size >>= 1;
    let mut frac_sum_input = NodeOutputType::WireOut(inv_sum, 0);
    while round_input_size > 1 {
        frac_sum_input = NodeOutputType::WireOut(
            graph_builder.add_node_with_witness(
                "frac_sum",
                &frac_sum_circuit,
                vec![PredType::PredWire(frac_sum_input)],
                vec![],
                vec![],
                round_input_size >> 1,
            )?,
            0,
        );
        round_input_size >>= 1;
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
        prover_transcript
            .get_and_append_challenge(b"output point")
            .elements,
    ];
    let output_eval = circuit_witness
        .node_witnesses
        .last()
        .unwrap()
        .output_layer_witness_ref()
        .instances
        .as_slice()
        .original_mle()
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
        verifier_transcript
            .get_and_append_challenge(b"output point")
            .elements,
    ];

    IOPVerifierState::verify(
        &graph,
        &challenge,
        &TargetEvaluations(vec![PointAndEval::new(output_point, output_eval)]),
        proof,
        &aux_info,
        &mut verifier_transcript,
    )?;

    Ok(())
}
