use super::{Expression, StructuralWitIn, WitIn};
use crate::{Fixed, Instance, WitnessId, combine_cumulative_either, monomial::Term};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;

impl WitIn {
    pub fn assign<E: ExtensionField>(&self, instance: &mut [E::BaseField], value: E::BaseField) {
        instance[self.id as usize] = value;
    }
}

impl StructuralWitIn {
    pub fn assign<E: ExtensionField>(&self, instance: &mut [E::BaseField], value: E::BaseField) {
        instance[self.id as usize] = value;
    }
}

pub fn eval_by_expr_constant<E: ExtensionField>(
    instance: &[Either<E::BaseField, E>],
    challenges: &[E],
    expr: &Expression<E>,
) -> Either<E::BaseField, E> {
    expr.evaluate_with_instance(
        &|_| unimplemented!(),
        &|_| unimplemented!(),
        &|_, _| unimplemented!(),
        &|i| instance[i.0],
        &|scalar| scalar,
        &|challenge_id, pow, scalar, offset| {
            // TODO cache challenge power to be acquired once for each power
            let challenge = challenges[challenge_id as usize];
            Either::Right(challenge.exp_u64(pow as u64) * scalar + offset)
        },
        &|a, b| combine_cumulative_either!(a, b, |a, b| a + b),
        &|a, b| combine_cumulative_either!(a, b, |a, b| a * b),
        &|x, a, b| {
            let ax = combine_cumulative_either!(a, x, |c1, c2| c1 * c2);
            // ax + b
            combine_cumulative_either!(ax, b, |c1, c2| c1 + c2)
        },
    )
}

pub fn eval_by_expr<E: ExtensionField>(
    witnesses: &[E],
    structural_witnesses: &[E],
    challenges: &[E],
    expr: &Expression<E>,
) -> E {
    eval_by_expr_with_fixed(&[], witnesses, structural_witnesses, challenges, expr)
}

/// Evaluates the expression using fixed values, witnesses, structural witnesses, and challenges.
/// We allow shorter fixed vectors, which are of the length 2^k and repeated cyclically. `fixed_len_minus_one` is the
/// length of the fixed vector minus one, which is used to wrap around the indices.
pub fn eval_by_expr_with_fixed<E: ExtensionField>(
    fixed: &[E],
    witnesses: &[E],
    structural_witnesses: &[E],
    challenges: &[E],
    expr: &Expression<E>,
) -> E {
    expr.evaluate::<E>(
        &|f| fixed[f.0],
        &|witness_id| witnesses[witness_id as usize],
        &|witness_id, _| structural_witnesses[witness_id as usize],
        &|scalar| {
            scalar
                .map_either(|scalar| E::from(scalar), |scalar| scalar)
                .into_inner()
        },
        &|challenge_id, pow, scalar, offset| {
            // TODO cache challenge power to be acquired once for each power
            let challenge = challenges[challenge_id as usize];
            challenge.exp_u64(pow as u64) * scalar + offset
        },
        &|a, b| a + b,
        &|a, b| a * b,
        &|x, a, b| a * x + b,
    )
}

pub fn eval_by_expr_with_instance<E: ExtensionField>(
    fixed: &[E],
    witnesses: &[E],
    structural_witnesses: &[E],
    instance: &[E],
    challenges: &[E],
    expr: &Expression<E>,
) -> Either<E::BaseField, E> {
    expr.evaluate_with_instance::<Either<_, _>>(
        &|f| Either::Right(fixed[f.0]),
        &|witness_id| Either::Right(witnesses[witness_id as usize]),
        &|witness_id, _| Either::Right(structural_witnesses[witness_id as usize]),
        &|i| Either::Right(instance[i.0]),
        &|scalar| scalar,
        &|challenge_id, pow, scalar, offset| {
            // TODO cache challenge power to be acquired once for each power
            let challenge = challenges[challenge_id as usize];
            Either::Right(challenge.exp_u64(pow as u64) * scalar + offset)
        },
        &|a, b| combine_cumulative_either!(a, b, |a, b| a + b),
        &|a, b| combine_cumulative_either!(a, b, |a, b| a * b),
        &|x, a, b| {
            let ax = combine_cumulative_either!(a, x, |c1, c2| c1 * c2);
            // ax + b
            combine_cumulative_either!(ax, b, |c1, c2| c1 + c2)
        },
    )
}

/// convert complex expression into monomial form to WitIn
/// orders WitIn ++ StructuralWitIn ++ Fixed
pub fn monomialize_expr_to_wit_terms<E: ExtensionField>(
    expr: &Expression<E>,
    num_witin: WitnessId,
    num_structural_witin: WitnessId,
    num_fixed: WitnessId,
) -> Vec<Term<Expression<E>, Expression<E>>> {
    let witid_offset = 0 as WitnessId;
    let structural_witin_offset = witid_offset + num_witin;
    let fixed_offset = structural_witin_offset + num_structural_witin;
    let instance_offset = fixed_offset + num_fixed;

    let monomial_terms_expr = expr.get_monomial_terms();
    monomial_terms_expr
        .into_iter()
        .map(
            |Term {
                 scalar,
                 mut product,
             }| {
                product.iter_mut().for_each(|t| match t {
                    Expression::WitIn(_) => (),
                    Expression::StructuralWitIn(structural_wit_id, _) => {
                        *t = Expression::WitIn(structural_witin_offset + *structural_wit_id);
                    }
                    Expression::Fixed(Fixed(fixed_id)) => {
                        *t = Expression::WitIn(fixed_offset + (*fixed_id as u16));
                    }
                    Expression::Instance(Instance(instance_id)) => {
                        *t = Expression::WitIn(instance_offset + (*instance_id as u16));
                    }
                    e => panic!("unknown monomial terms {:?}", e),
                });
                Term { scalar, product }
            },
        )
        .collect_vec()
}
