use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use subprotocols::{
    error::VerifierError,
    expression::Point,
    sumcheck::{SumcheckClaims, SumcheckProof, SumcheckProverOutput},
    utils::{evaluate_mle_ext, evaluate_mle_inplace},
};
use transcript::Transcript;

use crate::error::BackendError;

use super::{Layer, LayerWitness};

pub trait LinearLayer<E: ExtensionField> {
    fn prove(
        &self,
        wit: LayerWitness<E>,
        out_point: &Point<E>,
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckProverOutput<E>;

    fn verify(
        &self,
        proof: SumcheckProof<E>,
        sigmas: &[E],
        out_point: &Point<E>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<SumcheckClaims<E>, BackendError<E>>;
}

impl<E: ExtensionField> LinearLayer<E> for Layer {
    fn prove(
        &self,
        wit: LayerWitness<E>,
        out_point: &Point<E>,
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckProverOutput<E> {
        let base_mle_evals = wit
            .bases
            .iter()
            .map(|base| evaluate_mle_ext(base, out_point))
            .collect_vec();

        transcript.append_field_element_exts(&base_mle_evals);

        let ext_mle_evals = wit
            .exts
            .into_iter()
            .map(|mut ext| evaluate_mle_inplace(&mut ext, out_point))
            .collect_vec();

        transcript.append_field_element_exts(&ext_mle_evals);

        SumcheckProverOutput {
            proof: SumcheckProof {
                univariate_polys: vec![],
                ext_mle_evals,
                base_mle_evals,
            },
            point: out_point.clone(),
        }
    }

    fn verify(
        &self,
        proof: SumcheckProof<E>,
        sigmas: &[E],
        out_point: &Point<E>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<SumcheckClaims<E>, BackendError<E>> {
        let SumcheckProof {
            univariate_polys: _,
            ext_mle_evals,
            base_mle_evals,
        } = proof;

        transcript.append_field_element_exts(&ext_mle_evals);
        transcript.append_field_element_exts(&base_mle_evals);

        for (sigma, expr) in izip!(sigmas, &self.exprs) {
            let got = expr.evaluate(
                &ext_mle_evals,
                &base_mle_evals,
                &[out_point],
                &[],
                challenges,
            );
            if *sigma != got {
                return Err(BackendError::LayerVerificationFailed(
                    self.name.clone(),
                    VerifierError::<E>::ClaimNotMatch(expr.clone(), *sigma, got),
                ));
            }
        }

        Ok(SumcheckClaims {
            base_mle_evals,
            ext_mle_evals,
            in_point: out_point.clone(),
        })
    }
}
