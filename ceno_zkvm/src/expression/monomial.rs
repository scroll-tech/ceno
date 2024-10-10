use ff_ext::ExtensionField;
use goldilocks::SmallField;
use std::cmp::Ordering;

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
                            coeff: a.coeff.clone() * b.coeff.clone(),
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
                            coeff: x.coeff.clone() * a.coeff.clone(),
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

// Define a lexicographic order for expressions. It compares the types first, then the arguments left-to-right.
impl<E: ExtensionField> Ord for Expression<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        use Ordering::*;

        match (self, other) {
            (Fixed(a), Fixed(b)) => a.cmp(b),
            (WitIn(a), WitIn(b)) => a.cmp(b),
            (Instance(a), Instance(b)) => a.cmp(b),
            (Challenge(a, b, c, d), Challenge(e, f, g, h)) => {
                let cmp = a.cmp(e);
                if cmp == Equal {
                    let cmp = b.cmp(f);
                    if cmp == Equal {
                        let cmp = cmp_ext(c, g);
                        if cmp == Equal { cmp_ext(d, h) } else { cmp }
                    } else {
                        cmp
                    }
                } else {
                    cmp
                }
            }
            (Fixed(_), _) => Less,
            (Instance(_), Fixed(_)) => Greater,
            (Instance(_), _) => Less,
            (WitIn(_), Fixed(_)) => Greater,
            (WitIn(_), Instance(_)) => Greater,
            (WitIn(_), _) => Less,
            (Challenge(..), Fixed(_)) => Greater,
            (Challenge(..), Instance(_)) => Greater,
            (Challenge(..), WitIn(_)) => Greater,
            _ => unreachable!(),
        }
    }
}

impl<E: ExtensionField> PartialOrd for Expression<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(dead_code)]
fn cmp_field<F: SmallField>(a: &F, b: &F) -> Ordering {
    a.to_canonical_u64().cmp(&b.to_canonical_u64())
}

fn cmp_ext<E: ExtensionField>(a: &E, b: &E) -> Ordering {
    let a = a.as_bases().iter().map(|f| f.to_canonical_u64());
    let b = b.as_bases().iter().map(|f| f.to_canonical_u64());
    a.cmp(b)
}

#[cfg(test)]
mod tests {
    use crate::{expression::Fixed as FixedS, scheme::utils::eval_by_expr_with_fixed};

    use super::*;
    use ff::Field;
    use goldilocks::{Goldilocks as F, GoldilocksExt2 as E};
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

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
            let factored = eval(&factored);
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
