use ark_std::log2;
use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use linear_layer::{LayerClaims, LinearLayer};
use multilinear_extensions::{
    Expression,
    mle::{MultilinearExtension, Point, PointAndEval},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sumcheck_layer::{SumcheckLayer, SumcheckLayerProof};
use transcript::Transcript;
use zerocheck_layer::ZerocheckLayer;

use crate::{error::BackendError, evaluation::EvalExpression};

pub mod linear_layer;
pub mod sumcheck_layer;
pub mod zerocheck_layer;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerType {
    Sumcheck,
    Zerocheck,
    Linear,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct Layer<E: ExtensionField> {
    pub name: String,
    pub ty: LayerType,
    /// Challenges generated at the beginning of the layer protocol.
    pub challenges: Vec<Expression<E>>,
    /// Expressions to prove in this layer. For zerocheck and linear layers,
    /// each expression corresponds to an output. While in sumcheck, there
    /// is only 1 expression, which corresponds to the sum of all outputs.
    /// This design is for the convenience when building the following
    /// expression: `e_0 + beta * e_1
    ///    = \sum_x (r^0 eq_0(X) \cdot expr_0(x) + r^1 eq_1(X) \cdot expr_1(x) + ...)`.
    /// where `vec![e_0, beta * e_1]` will be the output evaluation expressions.
    pub exprs: Vec<Expression<E>>,
    /// eq expression for zero checks. Length should match with `exprs`
    pub eqs: Vec<Expression<E>>,
    /// Positions to place the evaluations of the base inputs of this layer.
    pub in_eval_expr: Vec<EvalExpression<E>>,
    /// The expressions of the evaluations from the succeeding layers, which are
    /// connected to the outputs of this layer.
    pub outs: Vec<EvalExpression<E>>,

    // For debugging purposes
    pub expr_names: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct LayerWitness<'a, E: ExtensionField> {
    pub bases: Vec<MultilinearExtension<'a, E>>,
    pub num_vars: usize,
}

impl<E: ExtensionField> Layer<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        ty: LayerType,
        exprs: Vec<Expression<E>>,
        eqs: Vec<Expression<E>>,
        challenges: Vec<Expression<E>>,
        in_eval_expr: Vec<EvalExpression<E>>,
        outs: Vec<EvalExpression<E>>,
        expr_names: Vec<String>,
    ) -> Self {
        let mut expr_names = expr_names;
        if expr_names.len() < exprs.len() {
            expr_names.extend(vec![
                "unavailable".to_string();
                exprs.len() - expr_names.len()
            ]);
        }
        Self {
            name,
            ty,
            challenges,
            exprs,
            eqs,
            in_eval_expr,
            outs,
            expr_names,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove<T: Transcript<E>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<E>,
        claims: &mut [PointAndEval<E>],
        challenges: &mut Vec<E>,
        transcript: &mut T,
    ) -> SumcheckLayerProof<E> {
        self.update_challenges(challenges, transcript);
        let (_, out_points) = self.extract_claim_and_point(claims, challenges);

        let sumcheck_layer_proof = match self.ty {
            LayerType::Sumcheck => <Layer<E> as SumcheckLayer<E>>::prove(
                self,
                num_threads,
                max_num_variables,
                wit,
                challenges,
                transcript,
            ),
            LayerType::Zerocheck => <Layer<E> as ZerocheckLayer<E>>::prove(
                self,
                num_threads,
                max_num_variables,
                wit,
                &out_points,
                challenges,
                transcript,
            ),
            LayerType::Linear => {
                assert!(out_points.iter().all_equal());
                <Layer<E> as LinearLayer<E>>::prove(self, wit, &out_points[0], transcript)
            }
        };

        self.update_claims(
            claims,
            &sumcheck_layer_proof.evals,
            &sumcheck_layer_proof.proof.point,
        );

        sumcheck_layer_proof
    }

    pub fn verify<Trans: Transcript<E>>(
        &self,
        max_num_variables: usize,
        proof: SumcheckLayerProof<E>,
        claims: &mut [PointAndEval<E>],
        challenges: &mut Vec<E>,
        transcript: &mut Trans,
    ) -> Result<(), BackendError<E>> {
        self.update_challenges(challenges, transcript);
        let (sigmas, points) = self.extract_claim_and_point(claims, challenges);

        let LayerClaims { in_point, evals } = match self.ty {
            LayerType::Sumcheck => <Layer<_> as SumcheckLayer<E>>::verify(
                self,
                max_num_variables,
                proof,
                &sigmas.iter().cloned().sum(),
                challenges,
                transcript,
            )?,
            LayerType::Zerocheck => <Layer<_> as ZerocheckLayer<E>>::verify(
                self,
                max_num_variables,
                proof,
                sigmas,
                &points,
                challenges,
                transcript,
            )?,
            LayerType::Linear => {
                assert!(points.iter().all(|point| point == &points[0]));
                <Layer<_> as LinearLayer<E>>::verify(
                    self, proof, &sigmas, &points[0], challenges, transcript,
                )?
            }
        };

        self.update_claims(claims, &evals, &in_point);

        Ok(())
    }

    fn extract_claim_and_point(
        &self,
        claims: &[PointAndEval<E>],
        challenges: &[E],
    ) -> (Vec<E>, Vec<Point<E>>) {
        self.outs
            .iter()
            .map(|out| {
                let PointAndEval { point, eval } = out.evaluate(claims, challenges);
                (eval, point)
            })
            .unzip()
    }

    // generate layer challenge, if have, and set to respective challenge_id index
    // optional resize raw challenges vector to adapt new challenge
    fn update_challenges(&self, challenges: &mut Vec<E>, transcript: &mut impl Transcript<E>) {
        for challenge in &self.challenges {
            let value = transcript.sample_and_append_challenge(b"layer challenge");
            match challenge {
                Expression::Challenge(challange_id, ..) => {
                    let challange_id = *challange_id as usize;
                    if challenges.len() <= challange_id as usize {
                        challenges.resize(challange_id + 1, E::default());
                    }
                    challenges[challange_id] = value.elements;
                }
                _ => unreachable!(),
            }
        }
    }

    fn update_claims(&self, claims: &mut [PointAndEval<E>], evals: &[E], point: &Point<E>) {
        for (value, pos) in izip!(chain![evals], chain![&self.in_eval_expr]) {
            *(pos.entry_mut(claims)) = PointAndEval {
                point: point.clone(),
                eval: *value,
            };
        }
    }
}

impl<'a, E: ExtensionField> LayerWitness<'a, E> {
    pub fn new(bases: Vec<MultilinearExtension<'a, E>>) -> Self {
        assert!(!bases.is_empty() || !bases.is_empty());
        let num_vars = if bases.is_empty() {
            log2(bases[0].evaluations().len())
        } else {
            log2(bases[0].evaluations().len())
        } as usize;
        assert!(bases.iter().all(|b| b.evaluations().len() == 1 << num_vars));
        Self { bases, num_vars }
    }
}
