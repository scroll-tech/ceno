use ff_ext::ExtensionField;
use itertools::{Itertools, chain, iproduct};
use serde::{Deserialize, Serialize};

use super::Expression;
use Expression::*;
use p3::field::FieldAlgebra;
use std::{fmt::Display, iter::Sum};

impl<E: ExtensionField> Expression<E> {
    pub fn get_monomial_terms(&self) -> Vec<Term<Expression<E>, Expression<E>>> {
        Self::combine(self.distribute())
            .into_iter()
            // filter coeff = 0 monimial terms
            .filter(|Term { scalar, .. }| match scalar {
                // filter term with scalar != zero
                Constant(scalar) => scalar
                    .map_either(
                        |scalar| scalar != E::BaseField::ZERO,
                        |scalar| scalar != E::ZERO,
                    )
                    .into_inner(),
                _ => true,
            })
            .collect_vec()
    }

    fn distribute(&self) -> Vec<Term<Expression<E>, Expression<E>>> {
        match self {
            // only contribute to scalar terms
            Constant(_) | Challenge(..) | InstanceScalar(_) => {
                vec![Term {
                    scalar: self.clone(),
                    product: vec![],
                }]
            }

            Fixed(_) | Instance(_) | WitIn(_) | StructuralWitIn(..) => {
                vec![Term {
                    scalar: Expression::ONE,
                    product: vec![self.clone()],
                }]
            }

            Sum(a, b) => chain!(a.distribute(), b.distribute()).collect(),

            Product(a, b) => iproduct!(a.distribute(), b.distribute())
                .map(|(a, b)| Term {
                    scalar: &a.scalar * &b.scalar,
                    product: chain!(&a.product, &b.product).cloned().collect(),
                })
                .collect(),

            ScaledSum(x, a, b) => chain!(
                b.distribute(),
                iproduct!(x.distribute(), a.distribute()).map(|(x, a)| Term {
                    scalar: &x.scalar * &a.scalar,
                    product: chain!(&x.product, &a.product).cloned().collect(),
                })
            )
            .collect(),
        }
    }

    fn combine(
        mut terms: Vec<Term<Expression<E>, Expression<E>>>,
    ) -> Vec<Term<Expression<E>, Expression<E>>> {
        for Term { product, .. } in &mut terms {
            product.sort();
        }
        terms
            .into_iter()
            .map(|Term { scalar, product }| (product, scalar))
            .into_group_map()
            .into_iter()
            .map(|(product, scalar)| Term {
                scalar: scalar.into_iter().sum(),
                product,
            })
            .collect()
    }
}

impl<E: ExtensionField> Sum<Term<Expression<E>, Expression<E>>> for Expression<E> {
    fn sum<I: Iterator<Item = Term<Expression<E>, Expression<E>>>>(iter: I) -> Self {
        iter.map(|term| term.scalar * term.product.into_iter().product::<Expression<_>>())
            .sum()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Term<S, P> {
    pub scalar: S,
    pub product: Vec<P>,
}

impl<E: ExtensionField> Display for Term<Expression<E>, Expression<E>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // join the product terms with " * "
        let product_str = self
            .product
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(" * ");
        // format as: scalar * (a * b * c)
        write!(f, "{} * ({})", self.scalar, product_str)
    }
}

#[cfg(test)]
mod tests {
    use crate::expression::{Fixed as FixedS, utils::eval_by_expr_with_fixed};

    use super::*;
    use either::Either;
    use ff_ext::{FieldInto, FromUniformBytes, GoldilocksExt2 as E};
    use p3::{field::FieldAlgebra, goldilocks::Goldilocks as F};
    use rand::thread_rng;

    #[test]
    fn test_to_monomial_form() {
        use Expression::*;

        let eval = make_eval();

        let a = || Fixed(FixedS(0));
        let b = || Fixed(FixedS(1));
        let c = || Fixed(FixedS(2));
        let x1 = || WitIn(0);
        let x2 = || WitIn(1);
        let x3 = || WitIn(2);
        let x4 = || WitIn(3);
        let x5 = || WitIn(4);
        let x6 = || WitIn(5);
        let x7 = || WitIn(6);

        let n1 = || Constant(Either::Left(103u64.into_f()));
        let n2 = || Constant(Either::Left(101u64.into_f()));
        let m = || Constant(Either::Left(-F::from_canonical_u64(599)));
        let r = || Challenge(0, 1, E::ONE, E::ZERO);

        let test_exprs: &[Expression<E>] = &[
            a() * x1() * x2(),
            a(),
            x1(),
            n1(),
            r(),
            a() + b() + x1() + x2() + n1() + m() + r(),
            a() * x1() * n1() * r(),
            x1() * x2() * x3(),
            (x1() + x2() + a()) * b() * (x2() + x3()) + c(),
            (r() * x1() + n1() + x3()) * m() * x2(),
            (b() + x2() + m() * x3()) * (x1() + x2() + c()),
            a() * r() * x1(),
            x1() * (n1() * (x2() * x3() + x4() * x5())) + n2() * x2() * x4() + x1() * x6() * x7(),
        ];

        for factored in test_exprs {
            let monomials = factored
                .get_monomial_terms()
                .into_iter()
                .sum::<Expression<E>>();
            assert!(monomials.is_monomial_form());

            // Check that the two forms are equivalent (Schwartz-Zippel test).
            let factored = eval(factored);
            let monomials = eval(&monomials);
            assert_eq!(monomials, factored);
        }
    }

    /// Create an evaluator of expressions. Fixed, witness, and challenge values are pseudo-random.
    fn make_eval() -> impl Fn(&Expression<E>) -> E {
        // Create a deterministic RNG from a seed.
        let mut rng = thread_rng();
        let fixed = vec![
            E::random(&mut rng),
            E::random(&mut rng),
            E::random(&mut rng),
        ];
        let witnesses = vec![
            E::random(&mut rng),
            E::random(&mut rng),
            E::random(&mut rng),
            E::random(&mut rng),
            E::random(&mut rng),
            E::random(&mut rng),
            E::random(&mut rng),
        ];
        let challenges = vec![
            E::random(&mut rng),
            E::random(&mut rng),
            E::random(&mut rng),
        ];
        move |expr: &Expression<E>| {
            eval_by_expr_with_fixed(&fixed, &witnesses, &[], &challenges, expr)
        }
    }
}
