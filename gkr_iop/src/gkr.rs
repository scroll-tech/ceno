use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use layer::{Layer, LayerWitness, sumcheck_layer::SumcheckLayerProof};
use multilinear_extensions::mle::{Point, PointAndEval};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sumcheck::macros::{entered_span, exit_span};
use transcript::Transcript;

use crate::{error::BackendError, evaluation::EvalExpression};

pub mod layer;
pub mod mock;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub struct GKRCircuit<E: ExtensionField> {
    pub layers: Vec<Layer<E>>,

    pub n_challenges: usize,
    pub n_evaluations: usize,
    pub openings: Vec<(usize, EvalExpression<E>)>,
}

#[derive(Clone, Debug, Default)]
pub struct GKRCircuitWitness<'a, E: ExtensionField> {
    pub layers: Vec<LayerWitness<'a, E>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize, Evaluation: Serialize",
    deserialize = "E::BaseField: DeserializeOwned, Evaluation: DeserializeOwned"
))]
pub struct GKRProverOutput<E: ExtensionField, Evaluation> {
    pub gkr_proof: GKRProof<E>,
    pub opening_evaluations: Vec<Evaluation>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct GKRProof<E: ExtensionField>(pub Vec<SumcheckLayerProof<E>>);

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
    pub fn prove(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        circuit_wit: GKRCircuitWitness<E>,
        out_evals: &[PointAndEval<E>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<GKRProverOutput<E, Evaluation<E>>, BackendError<E>> {
        let mut running_evals = out_evals.to_vec();
        // running evals is a global referable within chip
        running_evals.resize(self.n_evaluations, PointAndEval::default());
        let mut challenges = challenges.to_vec();
        let span = entered_span!("layer_proof", profiling_2 = true);
        let sumcheck_proofs = izip!(&self.layers, circuit_wit.layers)
            .enumerate()
            .map(|(i, (layer, layer_wit))| {
                tracing::info!("prove layer {i} layer with layer name {}", layer.name);
                let span = entered_span!("per_layer_proof", profiling_3 = true);
                let res = layer.prove(
                    num_threads,
                    max_num_variables,
                    layer_wit,
                    &mut running_evals,
                    &mut challenges,
                    transcript,
                );
                exit_span!(span);
                res
            })
            .collect_vec();
        exit_span!(span);

        let opening_evaluations = self.opening_evaluations(&running_evals, &challenges);

        Ok(GKRProverOutput {
            gkr_proof: GKRProof(sumcheck_proofs),
            opening_evaluations,
        })
    }

    pub fn verify(
        &self,
        max_num_variables: usize,
        gkr_proof: GKRProof<E>,
        out_evals: &[PointAndEval<E>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<GKRClaims<Evaluation<E>>, BackendError<E>>
    where
        E: ExtensionField,
    {
        let GKRProof(sumcheck_proofs) = gkr_proof;

        let mut challenges = challenges.to_vec();
        let mut evaluations = out_evals.to_vec();
        evaluations.resize(self.n_evaluations, PointAndEval::default());
        for (i, (layer, layer_proof)) in izip!(&self.layers, sumcheck_proofs).enumerate() {
            tracing::info!("verifier layer {i} layer with layer name {}", layer.name);
            layer.verify(
                max_num_variables,
                layer_proof,
                &mut evaluations,
                &mut challenges,
                transcript,
            )?;
        }

        Ok(GKRClaims(
            self.opening_evaluations(&evaluations, &challenges),
        ))
    }

    fn opening_evaluations(
        &self,
        evaluations: &[PointAndEval<E>],
        challenges: &[E],
    ) -> Vec<Evaluation<E>> {
        chain!(&self.openings, &self.openings)
            .map(|(poly, eval)| {
                let poly = *poly;
                let PointAndEval { point, eval: value } = eval.evaluate(evaluations, challenges);
                Evaluation { value, point, poly }
            })
            .collect_vec()
    }
}
