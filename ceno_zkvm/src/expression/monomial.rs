use ff_ext::ExtensionField;
use itertools::{Itertools, chain, iproduct};

use super::Expression;
use Expression::*;
use std::iter::Sum;

impl<E: ExtensionField> Expression<E> {
    pub(super) fn to_monomial_form_inner(&self) -> Self {
        Self::combine(self.distribute()).into_iter().sum()
    }

    fn distribute(&self) -> Vec<Term<E>> {
        match self {
            Constant(_) => {
                vec![Term {
                    coeff: self.clone(),
                    vars: vec![],
                }]
            }

            Fixed(_) | WitIn(_) | StructuralWitIn(..) | Instance(_) | Challenge(..) => {
                vec![Term {
                    coeff: Expression::ONE,
                    vars: vec![self.clone()],
                }]
            }

            Sum(a, b) => chain!(a.distribute(), b.distribute()).collect(),

            Product(a, b) => iproduct!(a.distribute(), b.distribute())
                .map(|(a, b)| Term {
                    coeff: &a.coeff * &b.coeff,
                    vars: chain!(&a.vars, &b.vars).cloned().collect(),
                })
                .collect(),

            ScaledSum(x, a, b) => chain!(
                b.distribute(),
                iproduct!(x.distribute(), a.distribute()).map(|(x, a)| Term {
                    coeff: &x.coeff * &a.coeff,
                    vars: chain!(&x.vars, &a.vars).cloned().collect(),
                })
            )
            .collect(),
        }
    }

    fn combine(mut terms: Vec<Term<E>>) -> Vec<Term<E>> {
        for Term { vars, .. } in &mut terms {
            vars.sort();
        }
        terms
            .into_iter()
            .map(|Term { coeff, vars }| (vars, coeff))
            .into_group_map()
            .into_iter()
            .map(|(vars, coeffs)| Term {
                coeff: coeffs.into_iter().sum(),
                vars,
            })
            .collect()
    }
}

impl<E: ExtensionField> Sum<Term<E>> for Expression<E> {
    fn sum<I: Iterator<Item = Term<E>>>(iter: I) -> Self {
        iter.map(|term| term.coeff * term.vars.into_iter().product::<Expression<_>>())
            .sum()
    }
}

#[derive(Clone, Debug)]
struct Term<E: ExtensionField> {
    coeff: Expression<E>,
    vars: Vec<Expression<E>>,
}

#[cfg(test)]
mod tests {
    use crate::{expression::Fixed as FixedS, scheme::utils::eval_by_expr_with_fixed};

    use super::*;
    use ff::Field;
    use goldilocks::{Goldilocks as F, GoldilocksExt2 as E};
    use rand_chacha::{ChaChaRng, rand_core::SeedableRng};

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
        let n = || Constant(104.into());
        let m = || Constant(-F::from(599));
        let r = || Challenge(0, 1, E::from(1), E::from(0));

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
            let monomials = factored.to_monomial_form_inner();
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
        let mut rng = ChaChaRng::from_seed([12u8; 32]);
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
