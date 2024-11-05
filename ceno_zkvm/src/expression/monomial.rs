use ff_ext::ExtensionField;

use super::Expression;
use Expression::*;

impl<E: ExtensionField> Expression<E> {
    pub(super) fn to_monomial_form_inner(&self) -> Self {
        Self::sum_terms(Self::combine(self.distribute()))
    }

    fn distribute(&self) -> Vec<Term<E>> {
        match self {
            Constant(_) => {
                vec![Term {
                    coeff: self.clone(),
                    vars: vec![],
                }]
            }

            Fixed(_) | WitIn(_) | Instance(_) | Challenge(..) => {
                vec![Term {
                    coeff: Expression::ONE,
                    vars: vec![self.clone()],
                }]
            }

            Sum(a, b) => {
                let mut res = a.distribute();
                res.extend(b.distribute());
                res
            }

            Product(a, b) => {
                let a = a.distribute();
                let b = b.distribute();
                let mut res = vec![];
                for a in a {
                    for b in &b {
                        res.push(Term {
                            coeff: &a.coeff * &b.coeff,
                            vars: a.vars.iter().chain(b.vars.iter()).cloned().collect(),
                        });
                    }
                }
                res
            }

            ScaledSum(x, a, b) => {
                let x = x.distribute();
                let a = a.distribute();
                let mut res = b.distribute();
                for x in x {
                    for a in &a {
                        res.push(Term {
                            coeff: &x.coeff * &a.coeff,
                            vars: x.vars.iter().chain(a.vars.iter()).cloned().collect(),
                        });
                    }
                }
                res
            }
        }
    }

    fn combine(terms: Vec<Term<E>>) -> Vec<Term<E>> {
        let mut res: Vec<Term<E>> = vec![];
        for mut term in terms {
            term.vars.sort();

            if let Some(res_term) = res.iter_mut().find(|res_term| res_term.vars == term.vars) {
                res_term.coeff = res_term.coeff.clone() + term.coeff.clone();
            } else {
                res.push(term);
            }
        }
        res
    }

    fn sum_terms(terms: Vec<Term<E>>) -> Self {
        terms
            .into_iter()
            .map(|term| term.vars.into_iter().fold(term.coeff, |a, b| a * b))
            .reduce(|a, b| a + b)
            .unwrap_or(Expression::ZERO)
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
        move |expr: &Expression<E>| eval_by_expr_with_fixed(&fixed, &witnesses, &challenges, expr)
    }
}
