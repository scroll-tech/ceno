use ff_ext::ExtensionField;
use itertools::{Itertools, chain, iproduct};

use super::Expression;
use Expression::*;
use std::iter::Sum;

impl<E: ExtensionField> Expression<E> {
    pub fn get_monomial_terms(&self) -> Vec<Term<E>> {
        Self::combine(self.distribute())
    }

    fn distribute(&self) -> Vec<Term<E>> {
        match self {
            Constant(_) => {
                vec![Term {
                    scalar: self.clone(),
                    product: vec![],
                }]
            }

            Fixed(_) | WitIn(_) | StructuralWitIn(..) | Instance(_) | Challenge(..) => {
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

    fn combine(mut terms: Vec<Term<E>>) -> Vec<Term<E>> {
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

impl<E: ExtensionField> Sum<Term<E>> for Expression<E> {
    fn sum<I: Iterator<Item = Term<E>>>(iter: I) -> Self {
        iter.map(|term| term.scalar * term.product.into_iter().product::<Expression<_>>())
            .sum()
    }
}

#[derive(Clone, Debug)]
pub struct Term<E: ExtensionField> {
    pub scalar: Expression<E>,
    pub product: Vec<Expression<E>>,
}

#[cfg(test)]
mod tests {
    use crate::expression::{Fixed as FixedS, utils::eval_by_expr_with_fixed};

    use super::*;
    use either::Either;
    use ff_ext::{FieldInto, FromUniformBytes, GoldilocksExt2 as E};
    use p3::{field::PrimeCharacteristicRing, goldilocks::Goldilocks as F};
    use rand::thread_rng;

    #[test]
    fn test_to_monomial_form() {
        use Expression::*;

        let eval = make_eval();

        let a = || Fixed(FixedS(0));
        let b = || Fixed(FixedS(1));
        let c = || Fixed(FixedS(2));
        let x = || WitIn(0);
        let y = || WitIn(1);
        let z = || WitIn(2);
        let n = || Constant(Either::Left(104u64.into_f()));
        let m = || Constant(Either::Left(-F::from_u64(599)));
        let r = || Challenge(0, 1, E::ONE, E::ZERO);

        let test_exprs: &[Expression<E>] = &[
            a() * x() * x(),
            a(),
            x(),
            n(),
            r(),
            a() + b() + x() + y() + n() + m() + r(),
            a() * x() * n() * r(),
            x() * y() * z(),
            (x() + y() + a()) * b() * (y() + z()) + c(),
            (r() * x() + n() + z()) * m() * y(),
            (b() + y() + m() * z()) * (x() + y() + c()),
            a() * r() * x(),
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
