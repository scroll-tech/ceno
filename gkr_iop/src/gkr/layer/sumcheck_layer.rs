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
    ) -> Result<LayerClaims<E>, BackendError>;
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
    ) -> Result<LayerClaims<E>, BackendError> {
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
                "sumcheck verify failed".to_string().into(),
                VerifierError::ClaimNotMatch(
                    format!("{}", expected_evaluation).into(),
                    format!("{}", got_claim).into(),
                ),
            ));
        }

        Ok(LayerClaims {
            in_point: in_point.into_iter().map(|c| c.elements).collect_vec(),
            evals,
        })
    }
}

// _debug: hintable
// pub struct LayerProofInput {
//     pub has_rotation: usize,
//     pub rotation: SumcheckLayerProofInput,
//     pub main: SumcheckLayerProofInput,
// }
#[derive(DslVariable, Clone)]
pub struct LayerProofVariable<C: Config> {
    pub has_rotation: Usize<C::N>,
    pub rotation: SumcheckLayerProofVariable<C>,
    pub main: SumcheckLayerProofVariable<C>,
}
impl<E: ExtensionField> VecAutoHintable for LayerProof<E> {}
impl<E: ExtensionField> Hintable<InnerConfig> for LayerProof<E> {
    type HintVariable = LayerProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let has_rotation = Usize::Var(usize::read(builder));
        let rotation = SumcheckLayerProofInput::read(builder);
        let main = SumcheckLayerProofInput::read(builder);

        Self::HintVariable {
            has_rotation,
            rotation,
            main,
        }
    }
    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.has_rotation));
        stream.extend(self.rotation.write());
        stream.extend(self.main.write());
        stream
    }
}

// _debug: hintable
// #[derive(Default)]
// pub struct SumcheckLayerProofInput {
//     pub proof: IOPProverMessageVec,
//     pub evals: Vec<E>,
// }
#[derive(DslVariable, Clone)]
pub struct SumcheckLayerProofVariable<C: Config> {
    pub proof: IOPProverMessageVecVariable<C>,
    pub evals: Array<C, Ext<C::F, C::EF>>,
    pub evals_len_div_3: Var<C::N>,
}
impl<E: ExtensionField> VecAutoHintable for SumcheckLayerProof<E> {}
impl<E: ExtensionField> Hintable<InnerConfig> for SumcheckLayerProof<E> {
    type HintVariable = SumcheckLayerProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let proof = IOPProverMessageVec::read(builder);
        let evals = Vec::<E>::read(builder);
        let evals_len_div_3 = usize::read(builder);

        Self::HintVariable {
            proof,
            evals,
            evals_len_div_3,
        }
    }
    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.proof.write());
        stream.extend(self.evals.write());
        let evals_len_div_3 = self.evals.len() / 3;
        stream.extend(<usize as Hintable<InnerConfig>>::write(&evals_len_div_3));
        stream
    }
}