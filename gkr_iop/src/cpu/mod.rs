use std::{collections::HashMap, iter, sync::Arc};

use crate::{
    LayerWitness,
    evaluation::EvalExpression,
    gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness, layer::Layer},
    hal::{MultilinearPolynomial, ProtocolWitnessGeneratorProver, ProverBackend, ProverDevice},
    selector::select_from_expression_result,
};
use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use mpcs::{PolynomialCommitmentScheme, SecurityLevel, SecurityLevel::Conjecture100bits};
use multilinear_extensions::{
    mle::{ArcMultilinearExtension, IntoMLE, MultilinearExtension, Point},
    op_mle,
    utils::eval_by_expr_constant,
    wit_infer_by_expr,
};
use p3::field::TwoAdicField;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use sumcheck::macros::{entered_span, exit_span};
use witness::RowMajorMatrix;

pub struct CpuBackend<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pp: <PCS as PolynomialCommitmentScheme<E>>::ProverParam,
    pub vp: <PCS as PolynomialCommitmentScheme<E>>::VerifierParam,
    pub max_poly_size_log2: usize,
    _marker: std::marker::PhantomData<E>,
}

pub const DEFAULT_MAX_NUM_VARIABLES: usize = 24;

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> Default for CpuBackend<E, PCS> {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_NUM_VARIABLES, Conjecture100bits)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> CpuBackend<E, PCS> {
    pub fn new(max_poly_size_log2: usize, security_level: SecurityLevel) -> Self {
        let param = PCS::setup(E::BaseField::TWO_ADICITY, security_level).unwrap();
        let (pp, vp) = PCS::trim(param, 1 << max_poly_size_log2).unwrap();
        Self {
            pp,
            vp,
            max_poly_size_log2,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn box_leak_static(self) -> &'static mut CpuBackend<E, PCS> {
        Box::leak(Box::new(self))
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

    fn get_pp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::ProverParam {
        &self.pp
    }

    fn get_vp(&self) -> &<Self::Pcs as PolynomialCommitmentScheme<Self::E>>::VerifierParam {
        &self.vp
    }
}

/// CPU prover for CPU backend
pub struct CpuProver<PB: ProverBackend + 'static> {
    pub backend: &'static PB,
}

impl<PB: ProverBackend> CpuProver<PB> {
    pub fn new(backend: &'static PB) -> Self {
        Self { backend }
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
        phase1_witness_group_rmm: &RowMajorMatrix<E::BaseField>,
        fixed: &RowMajorMatrix<E::BaseField>,
        challenges: &[E],
    ) -> (
        GKRCircuitWitness<'a, CpuBackend<E, PCS>>,
        GKRCircuitOutput<'a, CpuBackend<E, PCS>>,
    ) {
        // layer order from output to input
        let num_instances_with_rotation = phase1_witness_group_rmm.num_instances();
        let mut layer_wits =
            Vec::<LayerWitness<CpuBackend<E, PCS>>>::with_capacity(circuit.layers.len() + 1);
        let phase1_witness_group = phase1_witness_group_rmm
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
                                .take(num_instances_with_rotation)
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
            let num_instances = num_instances_with_rotation >> layer.rotation_cyclic_group_log2;
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
            > = layer_witness(layer, &current_layer_wits, challenges, num_instances);
            layer_wits.push(LayerWitness::new(current_layer_wits, vec![]));

            // process out to prepare output witness
            layer
                .out_sel_and_eval_exprs
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
        let mut gkr_out_well_order = vec![Arc::default(); circuit.final_out_evals.len()];
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

pub fn layer_witness<'a, E>(
    layer: &Layer<E>,
    layer_wits: &[ArcMultilinearExtension<'a, E>],
    challenges: &[E],
    num_instances: usize,
) -> Vec<ArcMultilinearExtension<'a, E>>
where
    E: ExtensionField,
{
    let out_evals: Vec<_> = layer
        .out_sel_and_eval_exprs
        .iter()
        .flat_map(|(sel_type, out_eval)| izip!(iter::repeat(sel_type), out_eval.iter()))
        .collect();
    layer
        .exprs
        .par_iter()
        .zip_eq(layer.expr_names.par_iter())
        .zip_eq(out_evals.par_iter())
        .map(|((expr, expr_name), (sel_type, out_eval))| {
            let out_mle = select_from_expression_result(
                sel_type,
                wit_infer_by_expr(&[], layer_wits, &[], &[], challenges, expr),
                num_instances,
            );
            if let EvalExpression::Zero = out_eval {
                // sanity check: zero mle
                if cfg!(debug_assertions) {
                    assert!(
                        out_mle.evaluations().is_zero(),
                        "layer name: {}, expr name: \"{expr_name}\" got non_zero mle",
                        layer.name
                    );
                }
            };
            out_mle
        })
        .collect::<Vec<_>>()
}
