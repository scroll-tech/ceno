use std::{marker::PhantomData, sync::Arc};

use chip::Chip;
use evaluation::EvalExpression;
use ff_ext::ExtensionField;
use gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness, layer::LayerWitness};
use itertools::Itertools;
use multilinear_extensions::{
    mle::{ArcMultilinearExtension, IntoMLE},
    op_mle,
    utils::eval_by_expr_constant,
};
use sumcheck::macros::{entered_span, exit_span};
use transcript::Transcript;
use utils::infer_layer_witness;
use witness::RowMajorMatrix;

pub mod chip;
pub mod error;
pub mod evaluation;
pub mod gkr;
pub mod precompiles;
pub mod utils;

pub type Phase1WitnessGroup<'a, E> = Vec<ArcMultilinearExtension<'a, E>>;

pub trait ProtocolBuilder<E: ExtensionField>: Sized {
    type Params;

    fn init(params: Self::Params) -> Self;

    /// Build the protocol for GKR IOP.
    fn build(params: Self::Params) -> (Self, Chip<E>) {
        let chip_spec = Self::init(params);
        let chip = chip_spec.build_gkr_chip();

        (chip_spec, chip)
    }

    /// Create the GKR layers in the reverse order. For each layer, specify the
    /// polynomial expressions, evaluation expressions of outputs and evaluation
    /// positions of the inputs.
    fn build_gkr_chip(&self) -> Chip<E>;

    fn n_committed(&self) -> usize;
    fn n_fixed(&self) -> usize;
    fn n_challenges(&self) -> usize;
    fn n_nonzero_out_evals(&self) -> usize;
    fn n_evaluations(&self) -> usize {
        self.n_committed() + self.n_fixed() + self.n_nonzero_out_evals()
    }

    fn n_layers(&self) -> usize;
}

pub trait ProtocolWitnessGenerator<'a, E>
where
    E: ExtensionField,
{
    type Trace;

    /// The vectors to be committed in the phase1.
    fn phase1_witness_group(&self, phase1: Self::Trace) -> RowMajorMatrix<E::BaseField>;

    /// GKR witness.
    fn gkr_witness(
        &self,
        circuit: &GKRCircuit<E>,
        phase1_witness_group: &RowMajorMatrix<E::BaseField>,
        fixed: &[Vec<E::BaseField>],
        challenges: &[E],
    ) -> (GKRCircuitWitness<'a, E>, GKRCircuitOutput<E>) {
        // layer order from output to input
        let size = phase1_witness_group.num_instances();
        let mut layer_wits = Vec::<LayerWitness<E>>::with_capacity(circuit.layers.len() + 1);
        let phase1_witness_group = phase1_witness_group
            .to_mles()
            .into_iter()
            .map(Arc::new)
            .collect_vec();

        let mut witness_mle_flatten = vec![None; circuit.n_evaluations];

        // initialize a vector to store the final outputs of the GKR circuit.
        // these outputs correspond to the evaluations at the last layer of the circuit.
        // we preallocate the vector with exact capacity for efficiency, avoiding reallocations.
        // the number of expected outputs is given by `circuit.n_evaluations`.
        let mut gkr_out_well_order = Vec::with_capacity(circuit.n_out_evals);

        // set input to witness_mle_flatten via first layer in_eval_expr
        if let Some(first_layer) = circuit.layers.last() {
            let it = first_layer.in_eval_expr.iter();
            it.enumerate().for_each(|(index, witin)| {
                if index < phase1_witness_group.len() {
                    witness_mle_flatten[*witin] = Some(phase1_witness_group[index].clone());
                } else {
                    witness_mle_flatten[*witin] = Some(
                        fixed[index - phase1_witness_group.len()]
                            .iter()
                            .cycle()
                            .cloned()
                            .take(size)
                            .collect_vec()
                            .into_mle()
                            .into(),
                    )
                }
            });
        }

        // generate all layer witness from input to output
        for (i, layer) in circuit.layers.iter().rev().enumerate() {
            tracing::info!("generating input {i} layer with layer name {}", layer.name);
            let span = entered_span!("per_layer_gen_witness", profiling_2 = true);
            // process in_evals to prepare layer witness
            // This should assume the input of the first layer is the phase1 witness of the circuit.
            let current_layer_wits = layer
                .in_eval_expr
                .iter()
                .map(|witin| {
                    witness_mle_flatten[*witin]
                        .clone()
                        .expect("witness must exist")
                })
                .collect_vec();

            // infer current layer output
            let current_layer_output: Vec<
                Arc<multilinear_extensions::mle::MultilinearExtension<'_, E>>,
            > = infer_layer_witness(layer, &current_layer_wits, challenges);
            layer_wits.push(LayerWitness::new(current_layer_wits, vec![]));

            // process out to prepare output witness
            layer
                .out_eq_and_eval_exprs
                .iter()
                .flat_map(|(_, out_eval)| out_eval)
                .zip_eq(&current_layer_output)
                .for_each(|(out_eval, out_mle)| match out_eval {
                    EvalExpression::Single(out) => {
                        witness_mle_flatten[*out] = Some(out_mle.clone());
                        // last layer we record gkr circuit output
                        if i == circuit.layers.len() - 1 {
                            gkr_out_well_order.push((*out, out_mle.clone()));
                        }
                    }
                    EvalExpression::Linear(out, a, b) => {
                        let a_inv = eval_by_expr_constant(challenges, a).inverse();
                        let b = eval_by_expr_constant(challenges, b);
                        let new_wit = op_mle!(|out_mle| out_mle
                            .iter()
                            .map(|x| a_inv * (-b + *x))
                            .collect_vec()
                            .into_mle()
                            .into());
                        witness_mle_flatten[*out] = Some(new_wit);
                    }
                    EvalExpression::Zero => { // zero expression
                        // do nothing on zero expression
                    }
                    other => unimplemented!("{:?}", other),
                });
            exit_span!(span);
        }

        layer_wits.reverse();

        // process and sort by out_id
        gkr_out_well_order.sort_by_key(|(i, _)| *i);
        let gkr_out_well_order = gkr_out_well_order
            .into_iter()
            .map(|(_, val)| val)
            .collect_vec();

        (
            GKRCircuitWitness { layers: layer_wits },
            GKRCircuitOutput(LayerWitness(gkr_out_well_order)),
        )
    }
}

// TODO: the following trait consists of `commit_phase1`, `commit_phase2`,
// `gkr_phase` and `opening_phase`.
pub struct ProtocolProver<E: ExtensionField, Trans: Transcript<E>, PCS>(
    PhantomData<(E, Trans, PCS)>,
);

// TODO: the following trait consists of `commit_phase1`, `commit_phase2`,
// `gkr_phase` and `opening_phase`.
pub struct ProtocolVerifier<E: ExtensionField, Trans: Transcript<E>, PCS>(
    PhantomData<(E, Trans, PCS)>,
);
