use ff_ext::ExtensionField;
use goldilocks::SmallField;
use std::cmp::Ordering;

use super::Expression;

impl<E: ExtensionField> Expression<E> {
    pub(super) fn to_monomial_form_inner(&self) -> Self {
        Self::sum(Self::dedup(self.distribute()))
    }

    fn distribute(&self) -> Vec<Term<E>> {
        use Expression::*;
        match self {
            Constant(_) => {
                vec![Term {
                    coeff: self.clone(),
                    vars: vec![],
                }]
            }

            Fixed(_) | WitIn(_) | Challenge(..) => {
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

    fn dedup(terms: Vec<Term<E>>) -> Vec<Term<E>> {
        let mut res: Vec<Term<E>> = vec![];
        for mut term in terms {
            term.vars.sort();

            let mut found = false;
            for res_term in res.iter_mut() {
                if res_term.vars == term.vars {
                    res_term.coeff = res_term.coeff.clone() + term.coeff.clone();
                    found = true;
                    break;
                }
            }
            if !found {
                res.push(term);
            }
        }
        res
    }

    fn sum(terms: Vec<Term<E>>) -> Self {
        terms
            .into_iter()
            .map(|term| term.vars.into_iter().fold(term.coeff, |acc, var| acc * var))
            .reduce(|acc, term| acc + term)
            .unwrap_or(Expression::ZERO)
    }
}

#[derive(Clone, Debug)]
struct Term<E: ExtensionField> {
    coeff: Expression<E>,
    vars: Vec<Expression<E>>,
}

impl<E: ExtensionField> Ord for Expression<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        use Expression::*;
        use Ordering::*;

        match (self, other) {
            (Fixed(a), Fixed(b)) => a.cmp(b),
            (WitIn(a), WitIn(b)) => a.cmp(b),
            (Constant(a), Constant(b)) => cmp_field(a, b),
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
            (Sum(a, b), Sum(c, d)) => {
                let cmp = a.cmp(c);
                if cmp == Equal { b.cmp(d) } else { cmp }
            }
            (Product(a, b), Product(c, d)) => {
                let cmp = a.cmp(c);
                if cmp == Equal { b.cmp(d) } else { cmp }
            }
            (ScaledSum(x, a, b), ScaledSum(y, c, d)) => {
                let cmp = x.cmp(y);
                if cmp == Equal {
                    let cmp = a.cmp(c);
                    if cmp == Equal { b.cmp(d) } else { cmp }
                } else {
                    cmp
                }
            }
            (Fixed(_), _) => Less,
            (WitIn(_), _) => Less,
            (Constant(_), _) => Less,
            (Challenge(..), _) => Less,
            (Sum(..), _) => Less,
            (Product(..), _) => Less,
            (ScaledSum(..), _) => Less,
        }
    }
}

impl<E: ExtensionField> PartialOrd for Expression<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn cmp_field<F: SmallField>(a: &F, b: &F) -> Ordering {
    a.to_canonical_u64().cmp(&b.to_canonical_u64())
}

fn cmp_ext<E: ExtensionField>(a: &E, b: &E) -> Ordering {
    let a = a.as_bases().iter().map(|f| f.to_canonical_u64());
    let b = b.as_bases().iter().map(|f| f.to_canonical_u64());
    a.cmp(b)
}
