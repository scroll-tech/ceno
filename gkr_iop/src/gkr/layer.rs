use ark_std::log2;
use ff_ext::ExtensionField;
use itertools::{chain, izip};
use linear_layer::LinearLayer;
use subprotocols::{
    expression::{Constant, Expression, Point},
    sumcheck::{SumcheckClaims, SumcheckProof, SumcheckProverOutput},
};
use sumcheck_layer::SumcheckLayer;
use transcript::Transcript;
use zerocheck_layer::ZerocheckLayer;

use crate::{
    error::BackendError,
    evaluation::{EvalExpression, PointAndEval},
    utils::SliceVector,
};

pub mod linear_layer;
pub mod sumcheck_layer;
pub mod zerocheck_layer;

#[derive(Clone, Debug)]
pub enum LayerType {
    Sumcheck,
    Zerocheck,
    Linear,
}

#[derive(Clone, Debug)]
pub struct Layer {
    pub name: String,
    pub ty: LayerType,
    /// Challenges generated at the beginning of the layer protocol.
    pub challenges: Vec<Constant>,
    /// Expressions to prove in this layer. For zerocheck and linear layers, each
    /// expression corresponds to an output. While in sumcheck, there is only 1
    /// expression, which corresponds to the sum of all outputs. This design is
    /// for the convenience when building the following expression:
    ///     `e_0 + beta * e_1 = sum_x (eq(p_0, x) + beta * eq(p_1, x)) expr(x)`.
    /// where `vec![e_0, beta * e_1]` will be the output evaluation expressions.
    pub exprs: Vec<Expression>,
    /// Positions to place the evaluations of the base inputs of this layer.
    pub in_bases: Vec<EvalExpression>,
    /// Positions to place the evaluations of the ext inputs of this layer.
    pub in_exts: Vec<EvalExpression>,
    /// The expressions of the evaluations from the succeeding layers, which are
    /// connected to the outputs of this layer.
    pub outs: Vec<EvalExpression>,
}

#[derive(Clone, Debug)]
pub struct LayerWitness<E: ExtensionField> {
    pub bases: Vec<Vec<E::BaseField>>,
    pub exts: Vec<Vec<E>>,
    pub num_vars: usize,
}

impl Layer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        ty: LayerType,
        exprs: Vec<Expression>,
        challenges: Vec<Constant>,
        in_bases: Vec<EvalExpression>,
        in_exts: Vec<EvalExpression>,
        outs: Vec<EvalExpression>,
    ) -> Self {
        Self {
            name,
            ty,
            challenges,
            exprs,
            in_bases,
            in_exts,
            outs,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove<E: ExtensionField, Trans: Transcript<E>>(
        &self,
        wit: LayerWitness<E>,
        claims: &mut [PointAndEval<E>],
        challenges: &mut Vec<E>,
        transcript: &mut Trans,
    ) -> SumcheckProof<E> {
        self.update_challenges(challenges, transcript);
        #[allow(unused)]
        let (sigmas, out_points) = self.sigmas_and_points(claims, challenges);

        let SumcheckProverOutput {
            point: in_point,
            proof,
        } = match self.ty {
            LayerType::Sumcheck => <Layer as SumcheckLayer<E>>::prove(
                self,
                wit,
                &out_points.slice_vector(),
                challenges,
                transcript,
            ),
            LayerType::Zerocheck => <Layer as ZerocheckLayer<E>>::prove(
                self,
                wit,
                &out_points.slice_vector(),
                challenges,
                transcript,
            ),
            LayerType::Linear => {
                assert!(out_points.iter().all(|point| point == &out_points[0]));
                <Layer as LinearLayer<E>>::prove(self, wit, &out_points[0], transcript)
            }
        };

        self.update_claims(
            claims,
            &proof.base_mle_evals,
            &proof.ext_mle_evals,
            &in_point,
        );

        proof
    }

    pub fn verify<E: ExtensionField, Trans: Transcript<E>>(
        &self,
        proof: SumcheckProof<E>,
        claims: &mut [PointAndEval<E>],
        challenges: &mut Vec<E>,
        transcript: &mut Trans,
    ) -> Result<(), BackendError<E>> {
        self.update_challenges(challenges, transcript);
        let (sigmas, points) = self.sigmas_and_points(claims, challenges);

        let SumcheckClaims {
            in_point,
            base_mle_evals,
            ext_mle_evals,
        } = match self.ty {
            LayerType::Sumcheck => <Layer as SumcheckLayer<E>>::verify(
                self,
                proof,
                &sigmas.iter().sum(),
                points.slice_vector(),
                challenges,
                transcript,
            )?,
            LayerType::Zerocheck => <Layer as ZerocheckLayer<E>>::verify(
                self,
                proof,
                sigmas,
                points.slice_vector(),
                challenges,
                transcript,
            )?,
            LayerType::Linear => {
                assert!(points.iter().all(|point| point == &points[0]));
                <Layer as LinearLayer<E>>::verify(
                    self, proof, &sigmas, &points[0], challenges, transcript,
                )?
            }
        };

        self.update_claims(claims, &base_mle_evals, &ext_mle_evals, &in_point);

        Ok(())
    }

    fn sigmas_and_points<E: ExtensionField>(
        &self,
        claims: &[PointAndEval<E>],
        challenges: &[E],
    ) -> (Vec<E>, Vec<Point<E>>) {
        self.outs
            .iter()
            .map(|out| {
                let tmp = out.evaluate(claims, challenges);
                (tmp.eval, tmp.point)
            })
            .unzip()
    }

    fn update_challenges<E: ExtensionField>(
        &self,
        challenges: &mut Vec<E>,
        transcript: &mut impl Transcript<E>,
    ) {
        for challenge in &self.challenges {
            let value = transcript.get_and_append_challenge(b"linear layer challenge");
            match challenge {
                Constant::Challenge(i) => {
                    if challenges.len() <= *i {
                        challenges.resize(*i + 1, E::ZERO);
                    }
                    challenges[*i] = value.elements;
                }
                _ => unreachable!(),
            }
        }
    }

    fn update_claims<E: ExtensionField>(
        &self,
        claims: &mut [PointAndEval<E>],
        base_mle_evals: &[E],
        ext_mle_evals: &[E],
        point: &Point<E>,
    ) {
        for (value, pos) in izip!(chain![base_mle_evals, ext_mle_evals], chain![
            &self.in_bases,
            &self.in_exts
        ]) {
            *(pos.entry_mut(claims)) = PointAndEval {
                point: point.clone(),
                eval: *value,
            };
        }
    }
}

impl<E: ExtensionField> LayerWitness<E> {
    pub fn new(bases: Vec<Vec<E::BaseField>>, exts: Vec<Vec<E>>) -> Self {
        assert!(!bases.is_empty() || !exts.is_empty());
        let num_vars = if bases.is_empty() {
            log2(exts[0].len())
        } else {
            log2(bases[0].len())
        } as usize;
        assert!(bases.iter().all(|b| b.len() == 1 << num_vars));
        assert!(exts.iter().all(|e| e.len() == 1 << num_vars));
        Self {
            bases,
            exts,
            num_vars,
        }
    }
}
