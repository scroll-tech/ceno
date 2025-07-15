use std::sync::Arc;

use ff_ext::ExtensionField;
use itertools::iproduct;
use multilinear_extensions::{
    Expression,
    mle::{ArcMultilinearExtension, IntoMLE, MultilinearExtension, Point},
    virtual_poly::{build_eq_x_r_vec, eq_eval},
};
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    gkr::booleanhypercube::{CYCLIC_POW2_5, u5_to_binary_vec},
    utils::eq_eval_less_or_equal_than,
};

/// Selector selects part of the witnesses in the sumcheck protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub enum SelectorType<E: ExtensionField> {
    None,
    Whole(Expression<E>),
    /// Select a prefix as the instances, padded with a field element.
    Prefix(E::BaseField, Expression<E>),
    /// Select a prefix as the instances, for each instance select the 1st or the last round, padded with a field element.
    KeccakRound(usize, E::BaseField, Expression<E>),
}

impl<E: ExtensionField> SelectorType<E> {
    /// Compute true and false mle eq(1; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (eq() - sel(y; b[5..]))
    pub fn compute(
        &self,
        out_point: &Point<E>,
        num_instances: usize,
    ) -> Option<MultilinearExtension<'_, E>> {
        match self {
            SelectorType::None => None,
            SelectorType::Whole(_expr) => Some(build_eq_x_r_vec(out_point).into_mle()),
            SelectorType::Prefix(_, _expr) => {
                let mut sel = build_eq_x_r_vec(out_point);
                if num_instances < sel.len() {
                    sel.splice(
                        num_instances..sel.len(),
                        std::iter::repeat_n(E::ZERO, sel.len() - num_instances),
                    );
                }
                Some(sel.into_mle())
            }
            SelectorType::KeccakRound(round, _, _expr) => {
                // input(y) - pad = \sum_b ( sel(y; b[5..]) * (record(b) - 1) )
                let eq = build_eq_x_r_vec(out_point);
                let selected_id = CYCLIC_POW2_5[*round];
                let sel: Vec<_> = iproduct!(0..32, eq.iter().enumerate())
                    .par_bridge()
                    .map(|(low_id, (hgh_id, s))| {
                        if low_id == selected_id && hgh_id < num_instances {
                            *s
                        } else {
                            E::ZERO
                        }
                    })
                    .collect();

                Some(sel.into_mle())
            }
        }
    }

    /// Evaluate true and false mle eq(CYCLIC_POW2_5[round]; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (1 - sel(y; b[5..]))
    pub fn evaluate(
        &self,
        evals: &mut Vec<E>,
        out_point: &Point<E>,
        in_point: &Point<E>,
        num_instances: usize,
        offset_eq_id: usize,
    ) {
        let (expr, eval) = match self {
            SelectorType::None => return,
            SelectorType::Whole(expr) => {
                assert_eq!(out_point.len(), in_point.len());
                (expr, eq_eval(out_point, in_point))
            }
            SelectorType::Prefix(_, expr) => {
                assert!(num_instances <= out_point.len());
                (
                    expr,
                    eq_eval_less_or_equal_than(num_instances - 1, out_point, in_point),
                )
            }
            SelectorType::KeccakRound(round, _, expr) => {
                assert!(out_point.len() + 5 == in_point.len());
                let eq_low = eq_eval(
                    &u5_to_binary_vec::<E>(CYCLIC_POW2_5[*round]),
                    &in_point[..5],
                );
                let sel = eq_eval_less_or_equal_than(num_instances - 1, out_point, &in_point[5..]);
                (expr, eq_low * sel)
            }
        };
        let Expression::StructuralWitIn(wit_id, _, _, _) = expr else {
            panic!("Wrong selector expression format");
        };
        let wit_id = *wit_id as usize + offset_eq_id;
        if wit_id >= evals.len() {
            evals.resize(wit_id + 1, E::ZERO);
        }
        evals[wit_id] = eval;
    }
}

pub(crate) fn select_from_expression_result<'a, E: ExtensionField>(
    sel_type: &SelectorType<E>,
    out_mle: ArcMultilinearExtension<'a, E>,
    num_instances: usize,
) -> ArcMultilinearExtension<'a, E> {
    match sel_type {
        SelectorType::None => out_mle.evaluations.sum().into_mle().into(),
        SelectorType::Whole(_) => out_mle,
        SelectorType::Prefix(pad, _) => {
            let evals = Arc::try_unwrap(out_mle).unwrap().evaluations_to_owned();
            evals
                .select_prefix(num_instances, pad)
                .sub_constant(pad)
                .into_mle()
                .into()
        }
        SelectorType::KeccakRound(round, pad, _) => {
            let evals = Arc::try_unwrap(out_mle).unwrap().evaluations_to_owned();
            evals
                .pick_stride_offset(32, CYCLIC_POW2_5[*round] as usize)
                .select_prefix(num_instances, pad)
                .sub_constant(pad)
                .into_mle()
                .into()
        }
    }
}
