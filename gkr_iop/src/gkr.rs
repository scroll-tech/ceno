use core::fmt;

use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use layer::{Layer, LayerWitness, sumcheck_layer::LayerProof};
use multilinear_extensions::mle::{Point, PointAndEval};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sumcheck::macros::{entered_span, exit_span};
use transcript::Transcript;

use crate::{
    error::BackendError,
    hal::{ProverBackend, ProverDevice},
    selector::SelectorContext,
};

pub mod booleanhypercube;
pub mod layer;
pub mod layer_constraint_system;
pub mod mock;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub struct GKRCircuit<E: ExtensionField> {
    pub layers: Vec<Layer<E>>,
    pub final_out_evals: Vec<usize>,

    pub n_challenges: usize,
    pub n_evaluations: usize,
}

#[derive(Clone, Debug)]
pub struct GKRCircuitWitness<'a, PB: ProverBackend> {
    pub layers: Vec<LayerWitness<'a, PB>>,
}

#[derive(Clone, Debug)]
pub struct GKRCircuitOutput<'a, PB: ProverBackend>(pub LayerWitness<'a, PB>);

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize, Evaluation: Serialize",
    deserialize = "E::BaseField: DeserializeOwned, Evaluation: DeserializeOwned"
))]
pub struct GKRProverOutput<E: ExtensionField, Evaluation> {
    pub gkr_proof: GKRProof<E>,
    pub opening_evaluations: Vec<Evaluation>,
    pub rt: Vec<Point<E>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct GKRProof<E: ExtensionField>(pub Vec<LayerProof<E>>);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct Evaluation<E: ExtensionField> {
    pub value: E,
    pub point: Point<E>,
    pub poly: usize,
}

pub struct GKRClaims<Evaluation>(pub Vec<Evaluation>);

impl<E: ExtensionField> GKRCircuit<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        circuit_wit: GKRCircuitWitness<PB>,
        out_evals: &[PointAndEval<E>],
        pub_io_evals: &[E],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
        selector_ctxs: &[SelectorContext],
    ) -> Result<GKRProverOutput<E, Evaluation<E>>, BackendError> {
        let mut running_evals = out_evals.to_vec();
        // running evals is a global referable within chip
        running_evals.resize(self.n_evaluations, PointAndEval::default());
        let mut challenges = challenges.to_vec();
        let span = entered_span!("layer_proof", profiling_2 = true);
        let (sumcheck_proofs, rt): (Vec<_>, Vec<_>) = izip!(&self.layers, circuit_wit.layers)
            .enumerate()
            .map(|(i, (layer, layer_wit))| {
                tracing::debug!("prove layer {i} layer with layer name {}", layer.name);
                let span = entered_span!("per_layer_proof", profiling_3 = true);
                let res = layer.prove::<_, PB, PD>(
                    num_threads,
                    max_num_variables,
                    layer_wit,
                    &mut running_evals,
                    pub_io_evals,
                    &mut challenges,
                    transcript,
                    selector_ctxs,
                );
                exit_span!(span);
                res
            })
            .unzip();
        exit_span!(span);

        let opening_evaluations = self.opening_evaluations(&running_evals);

        Ok(GKRProverOutput {
            gkr_proof: GKRProof(sumcheck_proofs),
            opening_evaluations,
            rt,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        max_num_variables: usize,
        gkr_proof: GKRProof<E>,
        out_evals: &[PointAndEval<E>],
        pub_io_evals: &[E],
        raw_pi: &[Vec<E::BaseField>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
        selector_ctxs: &[SelectorContext],
    ) -> Result<(GKRClaims<Evaluation<E>>, Point<E>), BackendError>
    where
        E: ExtensionField,
    {
        let GKRProof(sumcheck_proofs) = gkr_proof;

        let mut challenges = challenges.to_vec();
        let mut evaluations = out_evals.to_vec();
        evaluations.resize(self.n_evaluations, PointAndEval::default());
        let rt = izip!(&self.layers, sumcheck_proofs).enumerate().try_fold(
            vec![],
            |_, (i, (layer, layer_proof))| {
                tracing::debug!("verifier layer {i} layer with layer name {}", layer.name);
                let rt = layer.verify(
                    max_num_variables,
                    layer_proof,
                    &mut evaluations,
                    pub_io_evals,
                    raw_pi,
                    &mut challenges,
                    transcript,
                    selector_ctxs,
                )?;
                Ok(rt)
            },
        )?;
        Ok((GKRClaims(self.opening_evaluations(&evaluations)), rt))
    }

    /// Output opening evaluations. First witin and then fixed.
    fn opening_evaluations(&self, evaluations: &[PointAndEval<E>]) -> Vec<Evaluation<E>> {
        let input_layer = self.layers.last().unwrap();
        input_layer
            .in_eval_expr
            .iter()
            .enumerate()
            .map(|(poly, eval)| {
                let PointAndEval { point, eval: value } = evaluations[*eval].clone();
                Evaluation { value, point, poly }
            })
            .collect_vec()
    }
}

impl<E: ExtensionField> fmt::Display for GKRProof<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // overall size
        let overall_size = bincode::serialized_size(&self).expect("serialization error");

        write!(f, "overall_size {:.2}mb.", byte_to_mb(overall_size),)
    }
}

fn byte_to_mb(byte_size: u64) -> f64 {
    byte_size as f64 / (1024.0 * 1024.0)
}
