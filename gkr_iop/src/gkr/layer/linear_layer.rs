use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{mle::Point, utils::eval_by_expr_with_instance};
use sumcheck::structs::{IOPProof, VerifierError};
use transcript::Transcript;

use crate::error::BackendError;

use super::{Layer, LayerWitness, sumcheck_layer::SumcheckLayerProof};

pub struct LayerClaims<E: ExtensionField> {
    pub in_point: Point<E>,
    pub evals: Vec<E>,
}
pub trait LinearLayer<E: ExtensionField> {
    fn prove(
        &self,
        wit: LayerWitness<E>,
        out_point: &Point<E>,
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckLayerProof<E>;

    fn verify(
        &self,
        proof: SumcheckLayerProof<E>,
        sigmas: &[E],
        out_point: &Point<E>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>>;
}

impl<E: ExtensionField> LinearLayer<E> for Layer<E> {
    fn prove(
        &self,
        wit: LayerWitness<E>,
        out_point: &Point<E>,
        transcript: &mut impl Transcript<E>,
    ) -> SumcheckLayerProof<E> {
        let evals = wit
            .bases
            .iter()
            .map(|base| base.evaluate(out_point))
            .collect_vec();

        transcript.append_field_element_exts(&evals);

        SumcheckLayerProof {
            evals,
            rotation_proof: None,
            proof: IOPProof { proofs: vec![] },
        }
    }

    fn verify(
        &self,
        proof: SumcheckLayerProof<E>,
        sigmas: &[E],
        out_point: &Point<E>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>> {
        let SumcheckLayerProof { evals, .. } = proof;
        transcript.append_field_element_exts(&evals);

        for ((sigma, expr), expr_name) in sigmas.iter().zip_eq(&self.exprs).zip_eq(&self.expr_names)
        {
            let got = eval_by_expr_with_instance(&[], &evals, &[], &[], challenges, expr)
                .right()
                .unwrap();
            if *sigma != got {
                return Err(BackendError::LayerVerificationFailed(
                    self.name.clone(),
                    VerifierError::<E>::ClaimNotMatch(expr.clone(), *sigma, got, expr_name.clone()),
                ));
            }
        }

        Ok(LayerClaims {
            evals,
            in_point: out_point.clone(),
        })
    }
}
