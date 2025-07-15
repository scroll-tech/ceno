use std::marker::PhantomData;

use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{utils::eval_by_expr_with_instance, virtual_poly::VPAuxInfo};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sumcheck::structs::{IOPProof, IOPVerifierState, SumCheckSubClaim, VerifierError};
use transcript::Transcript;

use crate::{
    error::BackendError,
    gkr::layer::hal::SumcheckLayerProver,
    hal::{ProverBackend, ProverDevice},
};

use super::{Layer, LayerWitness, linear_layer::LayerClaims};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct LayerProof<E: ExtensionField> {
    pub rotation: Option<SumcheckLayerProof<E>>,
    pub main: SumcheckLayerProof<E>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct SumcheckLayerProof<E: ExtensionField> {
    pub proof: IOPProof<E>,
    pub evals: Vec<E>,
}

pub trait SumcheckLayer<E: ExtensionField> {
    #[allow(clippy::too_many_arguments)]
    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
    ) -> LayerProof<PB::E>;

    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        sigma: &E,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>>;
}

impl<E: ExtensionField> SumcheckLayer<E> for Layer<E> {
    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
    ) -> LayerProof<PB::E> {
        <PD as SumcheckLayerProver<PB>>::prove(
            self,
            num_threads,
            max_num_variables,
            wit,
            challenges,
            transcript,
        )
    }

    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        sigma: &E,
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<LayerClaims<E>, BackendError<E>> {
        let LayerProof {
            main:
                SumcheckLayerProof {
                    proof: IOPProof { proofs, .. },
                    evals,
                },
            ..
        } = proof;

        let SumCheckSubClaim {
            point: in_point,
            expected_evaluation,
        } = IOPVerifierState::verify(
            *sigma,
            &IOPProof { proofs },
            &VPAuxInfo {
                max_degree: self.exprs[0].degree(),
                max_num_variables,
                phantom: PhantomData,
            },
            transcript,
        );

        // Check the final evaluations.
        let got_claim =
            eval_by_expr_with_instance(&[], &evals, &[], &[], challenges, &self.exprs[0])
                .right()
                .unwrap();

        if got_claim != expected_evaluation {
            return Err(BackendError::LayerVerificationFailed(
                "sumcheck verify failed".to_string(),
                VerifierError::ClaimNotMatch(expected_evaluation, got_claim),
            ));
        }

        Ok(LayerClaims {
            in_point: in_point.into_iter().map(|c| c.elements).collect_vec(),
            evals,
        })
    }
}
