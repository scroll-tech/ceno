use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use multilinear_extensions::{
    ChallengeId, Expression, ToExpr, WitnessId,
    macros::{entered_span, exit_span},
    mle::Point,
    monomialize_expr_to_wit_terms,
    utils::{eval_by_expr, eval_by_expr_with_instance},
    virtual_poly::VPAuxInfo,
};
use p3::field::{FieldAlgebra, dot_product};
use std::{marker::PhantomData, ops::Neg};
use sumcheck::{
    structs::{IOPProof, IOPVerifierState, SumCheckSubClaim, VerifierError},
    util::get_challenge_pows,
};
use transcript::Transcript;

use super::{Layer, LayerWitness, linear_layer::LayerClaims, sumcheck_layer::LayerProof};
use crate::{
    error::BackendError,
    evaluation::EvalExpression,
    gkr::{
        booleanhypercube::BooleanHypercube,
        layer::{
            ROTATION_OPENING_COUNT, hal::ZerocheckLayerProver, sumcheck_layer::SumcheckLayerProof,
        },
    },
    hal::{ProverBackend, ProverDevice},
    selector::SelectorType,
    utils::rotation_selector_eval,
};

pub(crate) struct RotationPoints<E: ExtensionField> {
    pub left: Point<E>,
    pub right: Point<E>,
    pub origin: Point<E>,
}

pub(crate) struct RotationClaims<E: ExtensionField> {
    left_evals: Vec<E>,
    right_evals: Vec<E>,
    target_evals: Vec<E>,
    rotation_points: RotationPoints<E>,
}

pub trait ZerocheckLayer<E: ExtensionField> {
    // static expression on circuit setup
    fn build_static_expression(&mut self);

    #[allow(clippy::too_many_arguments)]
    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        out_points: &[Point<PB::E>],
        pub_io_evals: &[PB::E],
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
        num_instances: usize,
    ) -> (LayerProof<PB::E>, Point<PB::E>);

    #[allow(clippy::too_many_arguments)]
    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        eval_and_dedup_points: Vec<(Vec<E>, Option<Point<E>>)>,
        pub_io_evals: &[E],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
        num_instances: usize,
    ) -> Result<LayerClaims<E>, BackendError>;
}

impl<E: ExtensionField> ZerocheckLayer<E> for Layer<E> {
    fn build_static_expression(&mut self) {
        let span = entered_span!("gen_expr", profiling_4 = true);
        // build rotation expression
        let num_rotations = self.rotation_exprs.1.len();
        let rotation_expr = if num_rotations > 0 {
            let alpha_pows_expr = (2..)
                .take(num_rotations)
                .map(|id| Expression::Challenge(id as ChallengeId, 1, E::ONE, E::ZERO))
                .collect_vec();
            let rotation_expr = (0..)
                .tuples()
                .take(num_rotations)
                .zip_eq(&alpha_pows_expr)
                .map(|((rotate_wit_id, target_wit_id), alpha)| {
                    alpha * (Expression::WitIn(rotate_wit_id) - Expression::WitIn(target_wit_id))
                })
                .sum::<Expression<E>>();
            let rotation_selector_expr = Expression::<E>::WitIn((num_rotations * 2) as WitnessId);
            Some(rotation_selector_expr * rotation_expr)
        } else {
            None
        };

        // generate static expression
        let out_evals: Vec<_> = self
            .out_sel_and_eval_exprs
            .iter()
            .flat_map(|(sel_type, out_eval)| izip!(std::iter::repeat(sel_type), out_eval.iter()))
            .collect();
        self.exprs_with_selector_out_eval_monomial_form = self
            .exprs
            .iter()
            .zip_eq(out_evals.iter())
            .map(|(expr, (sel_type, out_eval))| {
                let sel_expr = sel_type.selector_expr();
                let expr = match out_eval {
                    EvalExpression::Linear(_, a, b) => {
                        assert_eq!(
                            a.as_ref().clone(),
                            E::BaseField::ONE.expr(),
                            "need to extend expression to support a.inverse()"
                        );
                        // sel * exp - b
                        sel_expr.clone() * expr + b.as_ref().neg().clone()
                    }
                    EvalExpression::Single(_) => sel_expr.clone() * expr,
                    EvalExpression::Zero => Expression::ZERO,
                    EvalExpression::Partition(_, _) => unimplemented!(),
                };

                monomialize_expr_to_wit_terms(
                    &expr,
                    self.n_witin as WitnessId,
                    self.n_fixed as WitnessId,
                    self.n_instance,
                )
            })
            .collect::<Vec<_>>();

        // build main sumcheck expression
        let alpha_pows_expr = (2..)
            .take(self.exprs.len() + num_rotations * ROTATION_OPENING_COUNT)
            .map(|id| Expression::Challenge(id as ChallengeId, 1, E::ONE, E::ZERO))
            .collect_vec();
        let zero_expr =
            extend_exprs_with_rotation(self, &alpha_pows_expr, self.n_witin as WitnessId)
                .into_iter()
                .sum::<Expression<E>>();

        self.rotation_sumcheck_expression = rotation_expr.clone();
        self.rotation_sumcheck_expression_monomial_terms =
            self.rotation_sumcheck_expression.as_ref().map(|expr| {
                monomialize_expr_to_wit_terms(
                    expr,
                    self.n_witin as WitnessId,
                    self.n_fixed as WitnessId,
                    self.n_instance,
                )
            });

        self.main_sumcheck_expression = Some(zero_expr);
        self.main_sumcheck_expression_monomial_terms =
            self.main_sumcheck_expression.as_ref().map(|expr| {
                monomialize_expr_to_wit_terms(
                    expr,
                    self.n_witin as WitnessId,
                    self.n_fixed as WitnessId,
                    self.n_instance,
                )
            });
        exit_span!(span);
    }

    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        out_points: &[Point<PB::E>],
        pub_io_evals: &[PB::E],
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
        num_instances: usize,
    ) -> (LayerProof<PB::E>, Point<PB::E>) {
        <PD as ZerocheckLayerProver<PB>>::prove(
            self,
            num_threads,
            max_num_variables,
            wit,
            out_points,
            pub_io_evals,
            challenges,
            transcript,
            num_instances,
        )
    }

    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        mut eval_and_dedup_points: Vec<(Vec<E>, Option<Point<E>>)>,
        pub_io_evals: &[E],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
        num_instances: usize,
    ) -> Result<LayerClaims<E>, BackendError> {
        assert_eq!(
            self.out_sel_and_eval_exprs.len(),
            eval_and_dedup_points.len(),
            "out eval length {} != with eval_and_dedup_points {}",
            self.out_sel_and_eval_exprs.len(),
            eval_and_dedup_points.len(),
        );
        let LayerProof {
            main:
                SumcheckLayerProof {
                    proof: IOPProof { proofs },
                    evals: mut main_evals,
                },
            rotation: rotation_proof,
        } = proof;

        if let Some(rotation_proof) = rotation_proof {
            // verify rotation proof
            let rt = eval_and_dedup_points
                .first()
                .and_then(|(_, rt)| rt.as_ref())
                .expect("rotation proof should have at least one point");
            let RotationClaims {
                left_evals,
                right_evals,
                target_evals,
                rotation_points:
                    RotationPoints {
                        left: left_point,
                        right: right_point,
                        origin: origin_point,
                    },
            } = verify_rotation(
                max_num_variables,
                self.rotation_exprs.1.len(),
                self.rotation_sumcheck_expression.as_ref().unwrap(),
                rotation_proof,
                self.rotation_cyclic_subgroup_size,
                self.rotation_cyclic_group_log2,
                rt,
                challenges,
                transcript,
            )?;
            eval_and_dedup_points.push((left_evals, Some(left_point)));
            eval_and_dedup_points.push((right_evals, Some(right_point)));
            eval_and_dedup_points.push((target_evals, Some(origin_point)));
        }

        let rotation_exprs_len = self.rotation_exprs.1.len();
        let main_sumcheck_challenges = chain!(
            challenges.iter().copied(),
            get_challenge_pows(
                self.exprs.len() + rotation_exprs_len * ROTATION_OPENING_COUNT,
                transcript,
            )
        )
        .collect_vec();

        let sigma = dot_product(
            main_sumcheck_challenges.iter().skip(2).copied(), // skip first 2 global challenges
            eval_and_dedup_points
                .iter()
                .flat_map(|(sigmas, _)| sigmas)
                .copied(),
        );

        let SumCheckSubClaim {
            point: in_point,
            expected_evaluation,
        } = IOPVerifierState::verify(
            sigma,
            &IOPProof { proofs },
            &VPAuxInfo {
                max_degree: self.max_expr_degree + 1, // +1 due to eq
                max_num_variables,
                phantom: PhantomData,
            },
            transcript,
        );
        let in_point = in_point.into_iter().map(|c| c.elements).collect_vec();

        // eval eq and set to respective witin
        izip!(&self.out_sel_and_eval_exprs, &eval_and_dedup_points).for_each(
            |((sel_type, _), (_, out_point))| {
                sel_type.evaluate(
                    &mut main_evals,
                    out_point.as_ref().unwrap(),
                    &in_point,
                    num_instances,
                    self.n_witin,
                );
            },
        );

        let got_claim = eval_by_expr_with_instance(
            &[],
            &main_evals,
            &[],
            pub_io_evals,
            &main_sumcheck_challenges,
            self.main_sumcheck_expression.as_ref().unwrap(),
        )
        .map_either(E::from, |v| v)
        .into_inner();

        if got_claim != expected_evaluation {
            return Err(BackendError::LayerVerificationFailed(
                self.name.clone().into(),
                VerifierError::ClaimNotMatch(
                    format!("{}", expected_evaluation).into(),
                    format!("{}", got_claim).into(),
                ),
            ));
        }

        Ok(LayerClaims {
            in_point,
            evals: main_evals,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_rotation<E: ExtensionField>(
    max_num_variables: usize,
    num_rotations: usize,
    rotation_sumcheck_expression: &Expression<E>,
    rotation_proof: SumcheckLayerProof<E>,
    rotation_cyclic_subgroup_size: usize,
    rotation_cyclic_group_log2: usize,
    rt: &Point<E>,
    challenges: &[E],
    transcript: &mut impl Transcript<E>,
) -> Result<RotationClaims<E>, BackendError> {
    let SumcheckLayerProof { proof, evals } = rotation_proof;
    assert_eq!(num_rotations * 3, evals.len());
    let rotation_challenges = chain!(
        challenges.iter().copied(),
        get_challenge_pows(num_rotations, transcript)
    )
    .collect_vec();

    let sigma = E::ZERO;

    let SumCheckSubClaim {
        point: in_point,
        expected_evaluation,
    } = IOPVerifierState::verify(
        sigma,
        &proof,
        &VPAuxInfo {
            max_degree: 2, // selector * (rotated - target)
            max_num_variables,
            phantom: PhantomData,
        },
        transcript,
    );
    let origin_point = in_point.into_iter().map(|c| c.elements).collect_vec();

    // compute the selector evaluation
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    let selector_eval = rotation_selector_eval(
        &bh,
        rt,
        &origin_point,
        rotation_cyclic_subgroup_size,
        rotation_cyclic_group_log2,
    );

    // check the final evaluations.
    let mut left_evals = Vec::with_capacity(evals.len() / 3);
    let mut right_evals = Vec::with_capacity(evals.len() / 3);
    let mut target_evals = Vec::with_capacity(evals.len() / 3);

    let got_claim = eval_by_expr(
        &evals
            .chunks_exact(3)
            .flat_map(|evals| {
                let [left_eval, right_eval, target_eval] = evals else {
                    unreachable!()
                };
                left_evals.push(*left_eval);
                right_evals.push(*right_eval);
                target_evals.push(*target_eval);
                [
                    (E::ONE - origin_point[rotation_cyclic_group_log2 - 1]) * *left_eval
                        + origin_point[rotation_cyclic_group_log2 - 1] * *right_eval,
                    *target_eval,
                ]
            })
            .chain(std::iter::once(selector_eval))
            .collect_vec(),
        &[],
        &rotation_challenges,
        rotation_sumcheck_expression,
    );

    if got_claim != expected_evaluation {
        return Err(BackendError::LayerVerificationFailed(
            "rotation verify failed".to_string().into(),
            VerifierError::ClaimNotMatch(
                format!("{}", expected_evaluation).into(),
                format!("{}", got_claim).into(),
            ),
        ));
    }

    let (left_point, right_point) =
        BooleanHypercube::new(rotation_cyclic_group_log2).get_rotation_points(&origin_point);

    Ok(RotationClaims {
        left_evals,
        right_evals,
        target_evals,
        rotation_points: RotationPoints {
            left: left_point,
            right: right_point,
            origin: origin_point,
        },
    })
}

pub fn extend_exprs_with_rotation<E: ExtensionField>(
    layer: &Layer<E>,
    alpha_pows: &[Expression<E>],
    offset_eq_id: WitnessId,
) -> Vec<Expression<E>> {
    let mut alpha_pows_iter = alpha_pows.iter();
    let mut expr_iter = layer.exprs.iter();
    let mut zero_check_exprs = Vec::with_capacity(layer.out_sel_and_eval_exprs.len());

    let match_expr = |sel_expr: &Expression<E>| match sel_expr {
        Expression::StructuralWitIn(id, ..) => Expression::WitIn(offset_eq_id + *id),
        invalid => panic!("invalid eq format {:?}", invalid),
    };

    for (sel_type, out_evals) in layer.out_sel_and_eval_exprs.iter() {
        let group_length = out_evals.len();
        let zero_check_expr = expr_iter
            .by_ref()
            .take(group_length)
            .cloned()
            .zip_eq(alpha_pows_iter.by_ref().take(group_length))
            .map(|(expr, alpha)| alpha * expr)
            .sum::<Expression<E>>();
        let expr = match sel_type {
            SelectorType::None => zero_check_expr,
            SelectorType::Whole(sel)
            | SelectorType::Prefix(_, sel)
            | SelectorType::OrderedSparse32 {
                expression: sel, ..
            } => match_expr(sel) * zero_check_expr,
        };
        zero_check_exprs.push(expr);
    }

    // prepare rotation expr
    let (rotation_eq, rotation_exprs) = &layer.rotation_exprs;
    if rotation_eq.is_none() {
        return zero_check_exprs;
    }

    let left_rotation_expr: Expression<E> = izip!(
        rotation_exprs.iter(),
        alpha_pows_iter.by_ref().take(rotation_exprs.len())
    )
    .map(|((rotate_expr, _), alpha)| {
        assert!(matches!(rotate_expr, Expression::WitIn(_)));
        alpha * rotate_expr
    })
    .sum();
    let right_rotation_expr: Expression<E> = izip!(
        rotation_exprs.iter(),
        alpha_pows_iter.by_ref().take(rotation_exprs.len())
    )
    .map(|((rotate_expr, _), alpha)| {
        assert!(matches!(rotate_expr, Expression::WitIn(_)));
        alpha * rotate_expr
    })
    .sum();
    let rotation_expr: Expression<E> = izip!(
        rotation_exprs.iter(),
        alpha_pows_iter.by_ref().take(rotation_exprs.len())
    )
    .map(|((_, expr), alpha)| {
        assert!(matches!(expr, Expression::WitIn(_)));
        alpha * expr
    })
    .sum();

    // push rotation expr to zerocheck expr
    if let Some(
        [
            rotation_left_eq_expr,
            rotation_right_eq_expr,
            rotation_eq_expr,
        ],
    ) = rotation_eq.as_ref()
    {
        let (rotation_left_eq_expr, rotation_right_eq_expr, rotation_eq_expr) = match (
            rotation_left_eq_expr,
            rotation_right_eq_expr,
            rotation_eq_expr,
        ) {
            (
                Expression::StructuralWitIn(left_eq_id, ..),
                Expression::StructuralWitIn(right_eq_id, ..),
                Expression::StructuralWitIn(eq_id, ..),
            ) => (
                Expression::WitIn(offset_eq_id + *left_eq_id),
                Expression::WitIn(offset_eq_id + *right_eq_id),
                Expression::WitIn(offset_eq_id + *eq_id),
            ),
            invalid => panic!("invalid eq format {:?}", invalid),
        };
        // add rotation left expr
        zero_check_exprs.push(rotation_left_eq_expr * left_rotation_expr);
        // add rotation right expr
        zero_check_exprs.push(rotation_right_eq_expr * right_rotation_expr);
        // add target expr
        zero_check_exprs.push(rotation_eq_expr * rotation_expr);
    }
    assert!(expr_iter.next().is_none() && alpha_pows_iter.next().is_none());

    zero_check_exprs
}
