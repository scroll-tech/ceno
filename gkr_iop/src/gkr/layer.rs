use std::vec::IntoIter;

use ark_std::log2;
use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use linear_layer::{LayerClaims, LinearLayer};
use multilinear_extensions::{
    Expression,
    mle::{ArcMultilinearExtension, Point, PointAndEval},
};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sumcheck_layer::LayerProof;
use transcript::Transcript;
use zerocheck_layer::ZerocheckLayer;

use crate::{error::BackendError, evaluation::EvalExpression};

pub mod linear_layer;
pub mod sumcheck_layer;
pub mod zerocheck_layer;

pub type ExprEvalType<E> = Vec<(Option<Expression<E>>, Vec<EvalExpression<E>>)>;
pub type RotateExprs<E> = (
    Option<[Expression<E>; ROTATION_OPENING_COUNT]>,
    Vec<(Expression<E>, Expression<E>)>,
);

// rotation contribute
// left + right + target, overall 3
const ROTATION_OPENING_COUNT: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerType {
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
    pub max_expr_degree: usize,
    /// Challenges generated at the beginning of the layer protocol.
    pub challenges: Vec<Expression<E>>,
    /// Expressions to prove in this layer. For zerocheck and linear layers,
    /// each expression corresponds to an output. While in sumcheck, there
    /// is only 1 expression, which corresponds to the sum of all outputs.
    /// This design is for the convenience when building the following
    /// expression: `r^0 e_0 + r^1 * e_1 + ...
    ///    = \sum_x (r^0 eq_0(X) \cdot expr_0(x) + r^1 eq_1(X) \cdot expr_1(x) + ...)`.
    /// where `vec![e_0, e_1, ...]` will be the output evaluation expressions.
    pub exprs: Vec<Expression<E>>,

    /// Positions to place the evaluations of the base inputs of this layer.
    pub in_eval_expr: Vec<usize>,
    /// The expressions of the evaluations from the succeeding layers, which are
    /// connected to the outputs of this layer.
    /// It format indicated as different output group
    /// first tuple value is optional eq
    pub out_eq_and_eval_exprs: ExprEvalType<E>,

    // format: ([eq0, eq1, eq2], Vec<(rotatition_expr, expr)>) such that rotation_expr - expr == 0
    // there got 3 different eq for (left, right, target) during rotation argument
    // refer https://hackmd.io/HAAj1JTQQiKfu0SIwOJDRw?view#Rotation
    pub rotation_exprs: RotateExprs<E>,
    pub rotation_cyclic_group_log2: usize,
    pub rotation_cyclic_subgroup_size: usize,

    // For debugging purposes
    pub expr_names: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct LayerWitness<'a, E: ExtensionField>(pub Vec<ArcMultilinearExtension<'a, E>>);

impl<E: ExtensionField> Layer<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        ty: LayerType,
        // exprs concat zero/non-zero expression.
        exprs: Vec<Expression<E>>,
        challenges: Vec<Expression<E>>,
        in_eval_expr: Vec<usize>,
        // first tuple value is eq
        out_eq_and_eval_exprs: ExprEvalType<E>,
        ((rotation_eq, rotation_exprs), rotation_cyclic_group_log2, rotation_cyclic_subgroup_size): (
            RotateExprs<E>,
            usize,
            usize,
        ),
        expr_names: Vec<String>,
    ) -> Self {
        assert!(
            expr_names.len() == exprs.len(),
            "there are expr without name"
        );
        let max_expr_degree = exprs.iter().map(|expr| expr.degree()).max().unwrap_or(1);

        Self {
            name,
            ty,
            max_expr_degree,
            challenges,
            exprs,
            in_eval_expr,
            out_eq_and_eval_exprs,
            rotation_exprs: (rotation_eq, rotation_exprs),
            rotation_cyclic_group_log2,
            rotation_cyclic_subgroup_size,
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
    ) -> LayerProof<E> {
        self.update_challenges(challenges, transcript);
        let mut eval_and_dedup_points = self.extract_claim_and_point(claims, challenges);

        let (sumcheck_layer_proof, point) = match self.ty {
            LayerType::Zerocheck => {
                let out_points = eval_and_dedup_points
                    .into_iter()
                    .map(|(_, point)| point.expect("point must exist"))
                    .collect_vec();
                <Layer<E> as ZerocheckLayer<E>>::prove(
                    self,
                    num_threads,
                    max_num_variables,
                    wit,
                    &out_points,
                    challenges,
                    transcript,
                )
            }
            LayerType::Linear => {
                assert_eq!(eval_and_dedup_points.len(), 1);
                let (_, point) = eval_and_dedup_points.remove(0);
                let point = point.clone().unwrap();
                (
                    <Layer<E> as LinearLayer<E>>::prove(self, wit, &point, transcript),
                    point,
                )
            }
        };

        self.update_claims(claims, &sumcheck_layer_proof.main.evals, &point);

        sumcheck_layer_proof
    }

    pub fn verify<Trans: Transcript<E>>(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        claims: &mut [PointAndEval<E>],
        challenges: &mut Vec<E>,
        transcript: &mut Trans,
    ) -> Result<(), BackendError<E>> {
        self.update_challenges(challenges, transcript);
        let mut eval_and_dedup_points = self.extract_claim_and_point(claims, challenges);

        let LayerClaims { in_point, evals } = match self.ty {
            LayerType::Zerocheck => <Layer<_> as ZerocheckLayer<E>>::verify(
                self,
                max_num_variables,
                proof,
                eval_and_dedup_points,
                challenges,
                transcript,
            )?,
            LayerType::Linear => {
                assert_eq!(eval_and_dedup_points.len(), 1);
                let (sigmas, point) = eval_and_dedup_points.remove(0);
                <Layer<_> as LinearLayer<E>>::verify(
                    self,
                    proof,
                    &sigmas,
                    point.as_ref().unwrap(),
                    challenges,
                    transcript,
                )?
            }
        };

        self.update_claims(claims, &evals, &in_point);

        Ok(())
    }

    // extract claim and dudup point
    fn extract_claim_and_point(
        &self,
        claims: &[PointAndEval<E>],
        challenges: &[E],
    ) -> Vec<(Vec<E>, Option<Point<E>>)> {
        self.out_eq_and_eval_exprs
            .iter()
            .map(|(_, out_evals)| {
                let evals = out_evals
                    .iter()
                    .map(|out_eval| {
                        let PointAndEval { eval, .. } = out_eval.evaluate(claims, challenges);
                        eval
                    })
                    .collect_vec();
                // within same group, all the point should be the same
                // so we assume only take first point as representative
                let point = out_evals.first().map(|out_eval| {
                    let PointAndEval { point, .. } = out_eval.evaluate(claims, challenges);
                    point
                });
                (evals, point)
            })
            .collect_vec()
    }

    // generate layer challenge, if have, and set to respective challenge_id index
    // optional resize raw challenges vector to adapt new challenge
    fn update_challenges(&self, challenges: &mut Vec<E>, transcript: &mut impl Transcript<E>) {
        for challenge in &self.challenges {
            let value = transcript.sample_and_append_challenge(b"layer challenge");
            match challenge {
                Expression::Challenge(challenge_id, ..) => {
                    let challenge_id = *challenge_id as usize;
                    if challenges.len() <= challenge_id {
                        challenges.resize(challenge_id + 1, E::default());
                    }
                    challenges[challenge_id] = value.elements;
                }
                _ => unreachable!(),
            }
        }
    }

    fn update_claims(&self, claims: &mut [PointAndEval<E>], evals: &[E], point: &Point<E>) {
        for (value, pos) in izip!(chain![evals], chain![&self.in_eval_expr]) {
            claims[*pos] = PointAndEval {
                point: point.clone(),
                eval: *value,
            };
        }
    }
}

impl<'a, E: ExtensionField> LayerWitness<'a, E> {
    pub fn new(
        wits: Vec<ArcMultilinearExtension<'a, E>>,
        fixed: Vec<ArcMultilinearExtension<'a, E>>,
    ) -> Self {
        let mut wits_and_fixed = wits;
        wits_and_fixed.extend(fixed);
        assert!(!wits_and_fixed.is_empty());
        let num_vars = log2(wits_and_fixed[0].evaluations().len()) as usize;
        assert!(
            wits_and_fixed
                .iter()
                .all(|b| b.evaluations().len() == 1 << num_vars)
        );
        Self(wits_and_fixed)
    }

    pub fn num_vars(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            self.0[0].num_vars()
        }
    }
}

impl<'a, E: ExtensionField> IntoIterator for LayerWitness<'a, E> {
    type Item = ArcMultilinearExtension<'a, E>;
    type IntoIter = IntoIter<ArcMultilinearExtension<'a, E>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, E: ExtensionField> LayerWitness<'a, E> {
    pub fn iter(&self) -> impl Iterator<Item = &ArcMultilinearExtension<'a, E>> {
        self.0.iter()
    }
}

impl<'a, E: ExtensionField> IntoParallelIterator for LayerWitness<'a, E> {
    type Iter = rayon::vec::IntoIter<ArcMultilinearExtension<'a, E>>;
    type Item = ArcMultilinearExtension<'a, E>;

    fn into_par_iter(self) -> Self::Iter {
        self.0.into_par_iter()
    }
}

impl<'a, E: ExtensionField> IntoParallelIterator for &'a LayerWitness<'a, E> {
    type Iter = rayon::slice::Iter<'a, ArcMultilinearExtension<'a, E>>;
    type Item = &'a ArcMultilinearExtension<'a, E>;

    fn into_par_iter(self) -> Self::Iter {
        self.0.par_iter()
    }
}
