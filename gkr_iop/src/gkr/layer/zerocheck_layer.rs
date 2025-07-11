use std::marker::PhantomData;

use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    Expression, WitnessId,
    mle::Point,
    utils::eval_by_expr,
    virtual_poly::{VPAuxInfo, eq_eval},
};
use p3_field::dot_product;
use sumcheck::{
    structs::{IOPProof, IOPVerifierState, SumCheckSubClaim, VerifierError},
    util::get_challenge_pows,
};
use transcript::Transcript;

use crate::{
    error::BackendError,
    gkr::{
        booleanhypercube::BooleanHypercube,
        layer::{
            ROTATION_OPENING_COUNT, hal::ZerocheckLayerProver, sumcheck_layer::SumcheckLayerProof,
        },
    },
    hal::{ProverBackend, ProverDevice},
    utils::{extend_exprs_with_rotation, rotation_selector_eval},
};

use super::{Layer, LayerWitness, linear_layer::LayerClaims, sumcheck_layer::LayerProof};

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
    #[allow(clippy::too_many_arguments)]
    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        out_points: &[Point<PB::E>],
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
    ) -> (LayerProof<PB::E>, Point<PB::E>);

    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        eval_and_dedup_points: Vec<(Vec<E>, Option<Point<E>>)>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError>;
}

impl<E: ExtensionField> ZerocheckLayer<E> for Layer<E> {
    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        out_points: &[Point<PB::E>],
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
    ) -> (LayerProof<PB::E>, Point<PB::E>) {
        <PD as ZerocheckLayerProver<PB>>::prove(
            self,
            num_threads,
            max_num_variables,
            wit,
            out_points,
            challenges,
            transcript,
        )
    }

    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        mut eval_and_dedup_points: Vec<(Vec<E>, Option<Point<E>>)>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError> {
        assert_eq!(
            self.out_eq_and_eval_exprs.len(),
            eval_and_dedup_points.len(),
            "out eval length {} != with eval_and_dedup_points {}",
            self.out_eq_and_eval_exprs.len(),
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
                rotation_proof,
                self.rotation_cyclic_subgroup_size,
                self.rotation_cyclic_group_log2,
                rt,
                transcript,
            )?;
            eval_and_dedup_points.push((left_evals, Some(left_point)));
            eval_and_dedup_points.push((right_evals, Some(right_point)));
            eval_and_dedup_points.push((target_evals, Some(origin_point)));
        }

        let rotation_exprs_len = self.rotation_exprs.1.len();
        let alpha_pows = get_challenge_pows(
            self.exprs.len() + rotation_exprs_len * ROTATION_OPENING_COUNT,
            transcript,
        );

        let sigma = dot_product(
            alpha_pows.iter().copied(),
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
        eval_and_dedup_points
            .iter()
            .map(|(_, out_point)| eq_eval(out_point.as_ref().unwrap(), &in_point))
            .zip(&self.out_eq_and_eval_exprs)
            .for_each(|(eval, (eq_expr, _))| match eq_expr {
                Some(Expression::WitIn(id)) => {
                    #[cfg(debug_assertions)]
                    assert_eq!(main_evals[*id as usize], eval, "eq compute wrong");
                    main_evals[*id as usize] = eval;
                }
                _ => unreachable!(),
            });

        let zero_check_exprs = extend_exprs_with_rotation(
            self,
            &alpha_pows
                .iter()
                .cloned()
                .map(|r| Expression::Constant(Either::Right(r)))
                .collect_vec(),
            self.n_witin as WitnessId,
        );

        let zero_check_expr = zero_check_exprs.into_iter().sum::<Expression<E>>();
        let got_claim = eval_by_expr(&main_evals, &[], challenges, &zero_check_expr);

        if got_claim != expected_evaluation {
            return Err(BackendError::LayerVerificationFailed(
                self.name.clone(),
                VerifierError::ClaimNotMatch(
                    format!("{}", expected_evaluation),
                    format!("{}", got_claim),
                ),
            ));
        }

        Ok(LayerClaims {
            in_point,
            evals: main_evals,
        })
    }
}

fn verify_rotation<E: ExtensionField>(
    max_num_variables: usize,
    rotation_proof: SumcheckLayerProof<E>,
    rotation_cyclic_subgroup_size: usize,
    rotation_cyclic_group_log2: usize,
    rt: &Point<E>,
    transcript: &mut impl Transcript<E>,
) -> Result<RotationClaims<E>, BackendError> {
    let SumcheckLayerProof { proof, evals } = rotation_proof;
    let rotation_expr_len = evals.len() / 3;
    let rotation_alpha_pows = get_challenge_pows(rotation_expr_len, transcript)
        .into_iter()
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
    let got_claim = selector_eval
        * evals
            .chunks_exact(3)
            .zip_eq(rotation_alpha_pows.iter())
            .map(|(evals, alpha)| {
                let [left_eval, right_eval, target_eval] = evals else {
                    unreachable!()
                };
                left_evals.push(*left_eval);
                right_evals.push(*right_eval);
                target_evals.push(*target_eval);
                *alpha
                    * ((E::ONE - origin_point[rotation_cyclic_group_log2 - 1]) * *left_eval
                        + origin_point[rotation_cyclic_group_log2 - 1] * *right_eval
                        - *target_eval)
            })
            .sum::<E>();

    if got_claim != expected_evaluation {
        return Err(BackendError::LayerVerificationFailed(
            "rotation verify failed".to_string(),
            VerifierError::ClaimNotMatch(
                format!("{}", expected_evaluation),
                format!("{}", got_claim),
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
