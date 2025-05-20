use std::marker::PhantomData;

use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    Expression,
    mle::{MultilinearExtension, Point},
    utils::eval_by_expr_with_instance,
    virtual_poly::{VPAuxInfo, build_eq_x_r_vec, eq_eval},
    virtual_polys::VirtualPolynomialsBuilder,
};
use p3_field::dot_product;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverState, IOPVerifierState, SumCheckSubClaim, VerifierError},
    util::get_challenge_pows,
};
use transcript::Transcript;

use crate::error::BackendError;

use super::{Layer, LayerWitness, linear_layer::LayerClaims, sumcheck_layer::SumcheckLayerProof};

pub trait ZerocheckLayer<E: ExtensionField> {
    #[allow(clippy::too_many_arguments)]
    fn prove(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<E>,
        out_points: &[Point<E>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckLayerProof<E>;

    fn verify(
        &self,
        max_num_variables: usize,
        proof: SumcheckLayerProof<E>,
        sigmas: Vec<E>,
        out_points: &[Point<E>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>>;
}

impl<E: ExtensionField> ZerocheckLayer<E> for Layer<E> {
    fn prove(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<E>,
        out_points: &[Point<E>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckLayerProof<E> {
        assert!(
            out_points.iter().all_equal(),
            "output points not all equals len() {}",
            out_points.len()
        );
        assert_eq!(self.exprs.len(), out_points.len());

        let span = entered_span!("build_out_points_eq");
        let mut eqs = out_points
            .par_iter()
            .take(1)
            .map(|point| {
                MultilinearExtension::from_evaluations_ext_vec(
                    point.len(),
                    build_eq_x_r_vec(&point),
                )
            })
            .collect::<Vec<_>>();
        exit_span!(span);

        let builder = VirtualPolynomialsBuilder::new_with_mles(
            num_threads,
            max_num_variables,
            wit.bases
                .iter()
                .map(|mle| Either::Left(mle.as_ref()))
                // extend eqs to the end of wit
                .chain(eqs.iter_mut().map(|eq| Either::Right(eq)))
                .collect_vec(),
        );
        let alpha_pows = get_challenge_pows(self.exprs.len(), transcript)
            .into_iter()
            .map(|r| Expression::Constant(Either::Right(r)))
            .collect_vec();
        let zerocheck_expr = self
            .exprs
            .iter()
            .zip_eq(alpha_pows)
            .map(|(expr, alpha)| alpha * expr)
            .sum::<Expression<E>>();
        let (proof, prover_state) = IOPProverState::prove(
            builder.to_virtual_polys(&[self.eqs[0].clone() * zerocheck_expr], challenges),
            transcript,
        );
        SumcheckLayerProof {
            proof,
            evals: prover_state.get_mle_flatten_final_evaluations(),
        }
    }

    fn verify(
        &self,
        max_num_variables: usize,
        proof: SumcheckLayerProof<E>,
        sigmas: Vec<E>,
        out_points: &[Point<E>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>> {
        assert_eq!(sigmas.len(), out_points.len());
        let SumcheckLayerProof {
            proof: IOPProof { proofs, .. },
            mut evals,
        } = proof;

        let alpha_pows = get_challenge_pows(self.exprs.len(), transcript);

        let sigma: E = dot_product(alpha_pows.iter().cloned(), sigmas.iter().cloned());

        let SumCheckSubClaim {
            point: in_point,
            expected_evaluation,
        } = IOPVerifierState::verify(
            sigma,
            &IOPProof {
                point: vec![], // final claimed point will be derived from sumcheck protocol
                proofs,
            },
            &VPAuxInfo {
                max_degree: self.exprs[0].degree(),
                max_num_variables,
                phantom: PhantomData,
            },
            transcript,
        );
        let in_point = in_point.into_iter().map(|c| c.elements).collect_vec();

        // eval eq and set to respective witin
        out_points
            .iter()
            .map(|out_point| eq_eval(out_point, &in_point))
            .zip(&self.eqs)
            .for_each(|(eval, eq_expr)| match eq_expr {
                Expression::WitIn(witin_id) => evals[*witin_id as usize] = eval,
                _ => unreachable!(),
            });

        // check the final evaluations.
        let got_claim = self
            .exprs
            .iter()
            .zip_eq(&self.eqs)
            .zip_eq(alpha_pows)
            .map(|((expr, eq_expr), alpha)| {
                alpha
                    * eval_by_expr_with_instance(
                        &[],
                        &evals,
                        &[],
                        &[],
                        challenges,
                        &(expr * eq_expr),
                    )
                    .right()
                    .unwrap()
            })
            .sum::<E>();

        if got_claim != expected_evaluation {
            return Err(BackendError::LayerVerificationFailed(
                "sumcheck verify failed".to_string(),
                VerifierError::ClaimNotMatch(
                    self.exprs[0].clone(),
                    expected_evaluation,
                    got_claim,
                    self.expr_names[0].clone(),
                ),
            ));
        }

        Ok(LayerClaims { in_point, evals })
    }
}
