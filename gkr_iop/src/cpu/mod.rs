use std::{collections::HashMap, sync::Arc};

use crate::{
    LayerWitness,
    evaluation::EvalExpression,
    gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness},
    hal::{MultilinearPolynomial, ProtocolWitnessGeneratorProver, ProverBackend, ProverDevice},
    infer_layer_witness,
};
use ff_ext::ExtensionField;
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme, SecurityLevel};
use multilinear_extensions::{
    mle::{IntoMLE, MultilinearExtension},
    op_mle,
    utils::eval_by_expr_constant,
};
use p3::field::TwoAdicField;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use sumcheck::macros::{entered_span, exit_span};
use witness::RowMajorMatrix;

pub struct CpuBackend<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub param: PCS::Param,
    _marker: std::marker::PhantomData<E>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> Default for CpuBackend<E, PCS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> CpuBackend<E, PCS> {
    pub fn new() -> Self {
        let param =
            PCS::setup(E::BaseField::TWO_ADICITY, SecurityLevel::Conjecture100bits).unwrap();
        Self {
            param,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, E: ExtensionField> MultilinearPolynomial<E> for MultilinearExtension<'a, E> {
    fn num_vars(&self) -> usize {
        self.num_vars()
    }

    fn eval(&self, point: Point<E>) -> E {
        self.evaluate(&point)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ProverBackend for CpuBackend<E, PCS> {
    type E = E;
    type Pcs = PCS;
    type MultilinearPoly<'a> = MultilinearExtension<'a, E>;
    type Matrix = RowMajorMatrix<E::BaseField>;
    type PcsData = PCS::CommitmentWithWitness;
}

/// CPU prover for CPU backend
pub struct CpuProver<PB: ProverBackend> {
    pub backend: PB,
    pub pp: Option<<<PB as ProverBackend>::Pcs as PolynomialCommitmentScheme<PB::E>>::ProverParam>,
    pub largest_poly_size: Option<usize>,
}

impl<PB: ProverBackend> CpuProver<PB> {
    pub fn new(backend: PB) -> Self {
        Self {
            backend,
            pp: None,
            largest_poly_size: None,
        }
    }
}

impl<E, PCS> ProverDevice<CpuBackend<E, PCS>> for CpuProver<CpuBackend<E, PCS>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>
    ProtocolWitnessGeneratorProver<CpuBackend<E, PCS>> for CpuProver<CpuBackend<E, PCS>>
{
    fn gkr_witness<'a>(
        circuit: &GKRCircuit<E>,
        phase1_witness_group: &RowMajorMatrix<E::BaseField>,
        fixed: &[Vec<E::BaseField>],
        challenges: &[E],
    ) -> (
        GKRCircuitWitness<'a, CpuBackend<E, PCS>>,
        GKRCircuitOutput<'a, CpuBackend<E, PCS>>,
    ) {
        // layer order from output to input
        let num_instances = phase1_witness_group.num_instances();
        let mut layer_wits =
            Vec::<LayerWitness<CpuBackend<E, PCS>>>::with_capacity(circuit.layers.len() + 1);
        let phase1_witness_group = phase1_witness_group
            .to_mles()
            .into_iter()
            .map(Arc::new)
            .collect_vec();

        let mut witness_mle_flatten = vec![None; circuit.n_evaluations];

        // set input to witness_mle_flatten via first layer in_eval_expr
        if let Some(first_layer) = circuit.layers.last() {
            // process witin
            first_layer
                .in_eval_expr
                .iter()
                .take(phase1_witness_group.len())
                .enumerate()
                .for_each(|(index, witin)| {
                    witness_mle_flatten[*witin] = Some(phase1_witness_group[index].clone());
                });

            // process fixed (and probably short) mle
            // XXX currently fixed poly not support in layers > 1
            first_layer
                .in_eval_expr
                .par_iter()
                .enumerate()
                .skip(phase1_witness_group.len())
                .map(|(index, witin)| {
                    (
                        *witin,
                        Some(
                            fixed[index - phase1_witness_group.len()]
                                .iter()
                                .cycle()
                                .cloned()
                                .take(num_instances)
                                .collect_vec()
                                .into_mle()
                                .into(),
                        ),
                    )
                })
                .collect::<HashMap<_, _>>()
                .into_iter()
                .for_each(|(witin, optional_mle)| witness_mle_flatten[witin] = optional_mle);
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

        // initialize a vector to store the final outputs of the GKR circuit.
        let mut gkr_out_well_order = vec![Arc::default(); circuit.n_nonzero_out_evals];
        circuit
            .final_out_evals
            .iter()
            .for_each(|out| gkr_out_well_order[*out] = witness_mle_flatten[*out].clone().unwrap());

        (
            GKRCircuitWitness { layers: layer_wits },
            GKRCircuitOutput(LayerWitness(gkr_out_well_order)),
        )
    }
}
