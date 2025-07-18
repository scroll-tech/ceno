use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{mle::Point, utils::eval_by_expr_with_instance};
use sumcheck::structs::VerifierError;
use transcript::Transcript;

use crate::{
    error::BackendError,
    gkr::layer::{hal::LinearLayerProver, sumcheck_layer::SumcheckLayerProof},
    hal::{ProverBackend, ProverDevice},
};

use super::{Layer, LayerWitness, sumcheck_layer::LayerProof};

pub struct LayerClaims<E: ExtensionField> {
    pub in_point: Point<E>,
    pub evals: Vec<E>,
}
pub trait LinearLayer<E: ExtensionField> {
    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        wit: LayerWitness<PB>,
        out_point: &Point<PB::E>,
        transcript: &mut impl Transcript<PB::E>,
    ) -> LayerProof<PB::E>;

    fn verify(
        &self,
        proof: LayerProof<E>,
        sigmas: &[E],
        out_point: &Point<E>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError>;
}

impl<E: ExtensionField> LinearLayer<E> for Layer<E> {
    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        wit: LayerWitness<PB>,
        out_point: &Point<PB::E>,
        transcript: &mut impl Transcript<PB::E>,
    ) -> LayerProof<PB::E> {
        <PD as LinearLayerProver<PB>>::prove(self, wit, out_point, transcript)
    }

    fn verify(
        &self,
        proof: LayerProof<E>,
        sigmas: &[E],
        out_point: &Point<E>,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError> {
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
                    VerifierError::ClaimNotMatch(format!("{}", *sigma), format!("{}", got)),
                ));
            }
        }

        Ok(LayerClaims {
            evals,
            in_point: out_point.clone(),
        })
    }
}
