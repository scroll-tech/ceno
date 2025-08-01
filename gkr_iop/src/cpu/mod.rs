use crate::{
    LayerWitness,
    evaluation::EvalExpression,
    gkr::{GKRCircuit, GKRCircuitOutput, GKRCircuitWitness, layer::Layer},
    hal::{MultilinearPolynomial, ProtocolWitnessGeneratorProver, ProverBackend, ProverDevice},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use mpcs::{PolynomialCommitmentScheme, SecurityLevel, SecurityLevel::Conjecture100bits};
use multilinear_extensions::{
    mle::{ArcMultilinearExtension, MultilinearExtension, Point},
    wit_infer_by_monomial_expr,
};
use p3::field::TwoAdicField;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::{iter, rc::Rc, sync::Arc};
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
    pub backend: Rc<PB>,
}

impl<PB: ProverBackend> CpuProver<PB> {
    pub fn new(backend: Rc<PB>) -> Self {
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
    fn gkr_witness<'a, 'b>(
        circuit: &GKRCircuit<E>,
        phase1_witness_group: &[ArcMultilinearExtension<'b, E>],
        structural_witness: &[ArcMultilinearExtension<'b, E>],
        fixed: &[ArcMultilinearExtension<'b, E>],
        pub_io: &[ArcMultilinearExtension<'b, E>],
        challenges: &[E],
    ) -> (
        GKRCircuitWitness<'a, CpuBackend<E, PCS>>,
        GKRCircuitOutput<'a, CpuBackend<E, PCS>>,
    )
    where
        'b: 'a,
    {
        // layer order from output to input
        let mut layer_wits =
            Vec::<LayerWitness<CpuBackend<E, PCS>>>::with_capacity(circuit.layers.len() + 1);

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

            // TODO process fixed (and probably short) mle
            assert_eq!(
                first_layer.in_eval_expr.len(),
                phase1_witness_group.len(),
                "TODO process fixed (and probably short) mle"
            );
            // XXX currently fixed poly not support in layers > 1

            // first_layer
            //     .in_eval_expr
            //     .par_iter()
            //     .enumerate()
            //     .skip(phase1_witness_group.len())
            //     .map(|(index, witin)| {
            //         (
            //             *witin,
            //             Some(
            //                 fixed[index - phase1_witness_group.len()]
            //                     .iter()
            //                     .cycle()
            //                     .cloned()
            //                     .take(num_instances_with_rotation)
            //                     .collect_vec()
            //                     .into_mle()
            //                     .into(),
            //             ),
            //         )
            //     })
            //     .collect::<HashMap<_, _>>()
            //     .into_iter()
            //     .for_each(|(witin, optional_mle)| witness_mle_flatten[witin] = optional_mle);
        }

        // generate all layer witness from input to output
        for (i, layer) in circuit.layers.iter().rev().enumerate() {
            tracing::debug!("generating input {i} layer with layer name {}", layer.name);
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
                .chain(if i == 0 {
                    // only supply structural witness for first layer
                    // TODO figure out how to support > 1 GKR layers
                    Either::Left(structural_witness.iter().cloned())
                } else {
                    Either::Right(iter::empty())
                })
                .chain(fixed.iter().cloned())
                .collect_vec();

            // infer current layer output
            let current_layer_output: Vec<
                Arc<multilinear_extensions::mle::MultilinearExtension<'_, E>>,
            > = layer_witness(layer, &current_layer_wits, pub_io, challenges);
            layer_wits.push(LayerWitness::new(current_layer_wits, vec![]));

            // process out to prepare output witness
            layer
                .out_sel_and_eval_exprs
                .iter()
                .flat_map(|(_, out_eval)| out_eval)
                .zip_eq(&current_layer_output)
                .for_each(|(out_eval, out_mle)| match out_eval {
                    // note: Linear (x - b)/a has been done and encode in expression
                    EvalExpression::Single(out) | EvalExpression::Linear(out, _, _) => {
                        witness_mle_flatten[*out] = Some(out_mle.clone());
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
    pub_io_evals: &[ArcMultilinearExtension<'a, E>],
    challenges: &[E],
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
        .exprs_with_selector_out_eval_monomial_form
        .par_iter()
        .zip_eq(layer.expr_names.par_iter())
        .zip_eq(out_evals.par_iter())
        .map(|((expr, expr_name), (_, out_eval))| {
            if cfg!(debug_assertions) {
                if let EvalExpression::Zero = out_eval {
                    assert!(
                        wit_infer_by_monomial_expr(expr, layer_wits, pub_io_evals, challenges)
                            .evaluations()
                            .is_zero(),
                        "layer name: {}, expr name: \"{expr_name}\" got non_zero mle",
                        layer.name
                    );
                }
            };
            match out_eval {
                EvalExpression::Linear(_, _, _) | EvalExpression::Single(_) => {
                    wit_infer_by_monomial_expr(expr, layer_wits, pub_io_evals, challenges)
                }
                EvalExpression::Zero => MultilinearExtension::default().into(),
                EvalExpression::Partition(_, _) => unimplemented!(),
            }
        })
        .collect::<Vec<_>>()
}
