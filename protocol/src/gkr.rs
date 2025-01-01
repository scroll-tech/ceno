use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use layer::{Layer, LayerWitness};
use subprotocols::{expression::Point, sumcheck::SumcheckProof};
use transcript::Transcript;

use crate::{
    error::BackendError,
    evaluation::{EvalExpression, PointAndEval},
};

pub mod layer;
pub mod mock;

#[derive(Clone, Debug)]
pub struct GKRCircuit<'a> {
    pub layers: &'a [Layer],

    pub n_challenges: usize,
    pub n_evaluations: usize,
    pub base_openings: &'a [(usize, EvalExpression)],
    pub ext_openings: &'a [(usize, EvalExpression)],
}

#[derive(Clone, Debug)]
pub struct GKRCircuitWitness<E: ExtensionField> {
    pub layers: Vec<LayerWitness<E>>,
}

pub struct GKRProverOutput<E: ExtensionField, Evaluation> {
    pub gkr_proof: GKRProof<E>,
    pub opening_evaluations: Vec<Evaluation>,
}

pub struct GKRProof<E: ExtensionField>(pub Vec<SumcheckProof<E>>);

pub struct Evaluation<E: ExtensionField> {
    pub value: E,
    pub point: Point<E>,
    pub poly: usize,
}

pub struct GKRClaims<Evaluation>(pub Vec<Evaluation>);

impl GKRCircuit<'_> {
    pub fn prove<E>(
        &self,
        circuit_wit: GKRCircuitWitness<E>,
        out_evals: &[PointAndEval<E>],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<GKRProverOutput<E, Evaluation<E>>, BackendError<E>>
    where
        E: ExtensionField,
    {
        let mut evaluations = out_evals.to_vec();
        evaluations.resize(self.n_evaluations, PointAndEval::default());
        let mut challenges = challenges.to_vec();
        let sumcheck_proofs = izip!(self.layers, circuit_wit.layers)
            .map(|(layer, layer_wit)| {
                layer.prove(layer_wit, &mut evaluations, &mut challenges, transcript)
            })
            .collect_vec();

        let opening_evaluations = self.opening_evaluations(&evaluations, &challenges);

        Ok(GKRProverOutput {
            gkr_proof: GKRProof(sumcheck_proofs),
            opening_evaluations,
        })
    }

    pub fn verify<E>(
        &self,
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
        for (layer, layer_proof) in izip!(self.layers, sumcheck_proofs) {
            layer.verify(layer_proof, &mut evaluations, &mut challenges, transcript)?;
        }

        Ok(GKRClaims(
            self.opening_evaluations(&evaluations, &challenges),
        ))
    }

    fn opening_evaluations<E: ExtensionField>(
        &self,
        evaluations: &[PointAndEval<E>],
        challenges: &[E],
    ) -> Vec<Evaluation<E>> {
        chain!(self.base_openings, self.ext_openings)
            .map(|(poly, eval)| {
                let poly = *poly;
                let PointAndEval { point, eval: value } = eval.evaluate(evaluations, challenges);
                Evaluation { value, point, poly }
            })
            .collect_vec()
    }
}
