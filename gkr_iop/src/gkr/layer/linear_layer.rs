use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{mle::Point, utils::eval_by_expr_with_instance};
use sumcheck::structs::{IOPProof, VerifierError};
use transcript::Transcript;

use crate::{error::BackendError, gkr::layer::sumcheck_layer::SumcheckLayerProof};

use super::{Layer, LayerWitness, sumcheck_layer::LayerProof};

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
    ) -> LayerProof<E>;

    fn verify(
        &self,
        proof: LayerProof<E>,
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
    ) -> LayerProof<E> {
        let evals = wit
            .wits
            .iter()
            .map(|base| base.evaluate(out_point))
            .collect_vec();

        transcript.append_field_element_exts(&evals);

        LayerProof {
            main: SumcheckLayerProof {
                proof: IOPProof { proofs: vec![] },
                evals,
            },
            rotation: None,
        }
    }

    fn verify(
        &self,
        proof: LayerProof<E>,
        sigmas: &[E],
        out_point: &Point<E>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>> {
        let LayerProof {
            main: SumcheckLayerProof { evals, .. },
            ..
        } = proof;

        transcript.append_field_element_exts(&evals);

        for (sigma, expr) in sigmas.iter().zip_eq(&self.exprs) {
            let got = eval_by_expr_with_instance(&[], &evals, &[], &[], challenges, expr)
                .right()
                .unwrap();
            if *sigma != got {
                return Err(BackendError::LayerVerificationFailed(
                    self.name.clone(),
                    VerifierError::<E>::ClaimNotMatch(*sigma, got),
                ));
            }
        }

        Ok(LayerClaims {
            evals,
            in_point: out_point.clone(),
        })
    }
}
