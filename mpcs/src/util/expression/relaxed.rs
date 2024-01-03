use crate::util::{
    arithmetic::PrimeField,
    expression::{CommonPolynomial, Expression, Query},
    BitIndex, Itertools,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    iter,
};

pub(crate) struct PolynomialSet {
    pub(crate) preprocess: BTreeSet<usize>,
    pub(crate) folding: BTreeSet<usize>,
}

#[derive(Clone, PartialEq, PartialOrd, Eq, Ord)]
enum ExpressionPolynomial {
    CommonPolynomial(CommonPolynomial),
    Polynomial(Query),
}

impl<F> From<ExpressionPolynomial> for Expression<F> {
    fn from(poly_foldee: ExpressionPolynomial) -> Self {
        match poly_foldee {
            ExpressionPolynomial::CommonPolynomial(common_poly) => {
                Expression::CommonPolynomial(common_poly)
            }
            ExpressionPolynomial::Polynomial(query) => Expression::Polynomial(query),
        }
    }
}

pub(crate) fn cross_term_expressions<F: PrimeField>(
    poly_set: &PolynomialSet,
    products: &[Product<F>],
    num_challenges: usize,
) -> Vec<Expression<F>> {
    let folding_degree = folding_degree(products);
    let num_ts = folding_degree.checked_sub(1).unwrap_or_default();
    let u = num_challenges;
    let [preprocess_poly_indices, folding_poly_indices] = [&poly_set.preprocess, &poly_set.folding]
        .map(|polys| polys.iter().zip(0..).collect::<BTreeMap<_, _>>());

    products
        .iter()
        .fold(
            vec![BTreeMap::<Vec<_>, Expression<F>>::new(); num_ts],
            |mut scalars, product| {
                let (common_scalar, common_poly) = product.preprocess.evaluate(
                    &|constant| (constant, Vec::new()),
                    &|common_poly| {
                        (
                            F::ONE,
                            vec![ExpressionPolynomial::CommonPolynomial(common_poly)],
                        )
                    },
                    &|query| {
                        let poly = preprocess_poly_indices[&query.poly()];
                        let query = Query::new(poly, query.rotation());
                        (F::ONE, vec![ExpressionPolynomial::Polynomial(query)])
                    },
                    &|_| unreachable!(),
                    &|(scalar, expr)| (-scalar, expr),
                    &|_, _| unreachable!(),
                    &|(lhs_scalar, lhs_expr), (rhs_scalar, rhs_expr)| {
                        (lhs_scalar * rhs_scalar, [lhs_expr, rhs_expr].concat())
                    },
                    &|(lhs, expr), rhs| (lhs * rhs, expr),
                );
                for idx in 1usize..(1 << folding_degree) - 1 {
                    let (scalar, mut polys) = iter::empty()
                        .chain(iter::repeat(None).take(folding_degree - product.folding_degree()))
                        .chain(product.foldees.iter().map(Some))
                        .enumerate()
                        .fold(
                            (Expression::Constant(common_scalar), common_poly.clone()),
                            |(mut scalar, mut polys), (nth, foldee)| {
                                let (poly_offset, challenge_offset) = if idx.nth_bit(nth) {
                                    (
                                        preprocess_poly_indices.len() + folding_poly_indices.len(),
                                        num_challenges + 1,
                                    )
                                } else {
                                    (preprocess_poly_indices.len(), 0)
                                };
                                match foldee {
                                    None => {
                                        scalar =
                                            &scalar * Expression::Challenge(challenge_offset + u)
                                    }
                                    Some(Expression::Challenge(challenge)) => {
                                        scalar = &scalar
                                            * Expression::Challenge(challenge_offset + challenge)
                                    }
                                    Some(Expression::Polynomial(query)) => {
                                        let poly =
                                            poly_offset + folding_poly_indices[&query.poly()];
                                        let query = Query::new(poly, query.rotation());
                                        polys.push(ExpressionPolynomial::Polynomial(query));
                                    }
                                    _ => unreachable!(),
                                }
                                (scalar, polys)
                            },
                        );
                    polys.sort_unstable();
                    scalars[idx.count_ones() as usize - 1]
                        .entry(polys)
                        .and_modify(|value| *value = value as &Expression<_> + &scalar)
                        .or_insert(scalar);
                }
                scalars
            },
        )
        .into_iter()
        .map(|exprs| {
            exprs
                .into_iter()
                .map(|(polys, scalar)| {
                    polys
                        .into_iter()
                        .map_into::<Expression<F>>()
                        .product::<Expression<_>>()
                        * scalar
                })
                .sum::<Expression<_>>()
        })
        .collect_vec()
}

pub(crate) fn relaxed_expression<F: PrimeField>(
    products: &[Product<F>],
    u: usize,
) -> Expression<F> {
    let folding_degree = folding_degree(products);
    let powers_of_u = iter::successors(Some(Expression::<F>::one()), |power_of_u| {
        Some(power_of_u * Expression::Challenge(u))
    })
    .take(folding_degree + 1)
    .collect_vec();
    products
        .iter()
        .map(|product| {
            &powers_of_u[folding_degree - product.folding_degree()] * product.expression()
        })
        .sum()
}

pub(crate) fn products<F: PrimeField>(
    preprocess_polys: &BTreeSet<usize>,
    constraint: &Expression<F>,
) -> Vec<Product<F>> {
    let products = constraint.evaluate(
        &|constant| vec![Product::new(Expression::Constant(constant), Vec::new())],
        &|poly| vec![Product::new(Expression::CommonPolynomial(poly), Vec::new())],
        &|query| {
            if preprocess_polys.contains(&query.poly()) {
                vec![Product::new(Expression::Polynomial(query), Vec::new())]
            } else {
                vec![Product::new(
                    Expression::Constant(F::ONE),
                    vec![Expression::Polynomial(query)],
                )]
            }
        },
        &|challenge| {
            vec![Product::new(
                Expression::Constant(F::ONE),
                vec![Expression::Challenge(challenge)],
            )]
        },
        &|products| {
            products
                .into_iter()
                .map(|mut product| {
                    product.preprocess = -product.preprocess;
                    product
                })
                .collect_vec()
        },
        &|lhs, rhs| [lhs, rhs].concat(),
        &|lhs, rhs| {
            lhs.iter()
                .cartesian_product(rhs.iter())
                .map(|(lhs, rhs)| {
                    Product::new(
                        &lhs.preprocess * &rhs.preprocess,
                        iter::empty()
                            .chain(&lhs.foldees)
                            .chain(&rhs.foldees)
                            .cloned()
                            .collect(),
                    )
                })
                .collect_vec()
        },
        &|products, scalar| {
            products
                .into_iter()
                .map(|mut product| {
                    product.preprocess = product.preprocess * scalar;
                    product
                })
                .collect_vec()
        },
    );
    products
        .into_iter()
        .map(|mut product| {
            let (scalar, preprocess) = product.preprocess.evaluate(
                &|constant| (constant, None),
                &|poly| (F::ONE, Some(Expression::CommonPolynomial(poly))),
                &|query| (F::ONE, Some(Expression::Polynomial(query))),
                &|_| unreachable!(),
                &|(scalar, preprocess)| (-scalar, preprocess),
                &|_, _| unreachable!(),
                &|(lhs_scalar, lhs_common), (rhs_scalar, rhs_common)| {
                    let preprocess = match (lhs_common, rhs_common) {
                        (Some(lhs_common), Some(rhs_common)) => Some(lhs_common * rhs_common),
                        (Some(preprocess), None) | (None, Some(preprocess)) => Some(preprocess),
                        (None, None) => None,
                    };
                    (lhs_scalar * rhs_scalar, preprocess)
                },
                &|(lhs, preprocess), rhs| (lhs * rhs, preprocess),
            );

            product.preprocess = preprocess
                .map(|preprocess| {
                    if scalar == F::ONE {
                        preprocess
                    } else {
                        preprocess * scalar
                    }
                })
                .unwrap_or_else(|| Expression::Constant(scalar));
            product
        })
        .collect()
}

#[derive(Clone, Debug)]
pub(crate) struct Product<F> {
    preprocess: Expression<F>,
    foldees: Vec<Expression<F>>,
}

impl<F> Product<F> {
    fn new(preprocess: Expression<F>, foldees: Vec<Expression<F>>) -> Self {
        Self {
            preprocess,
            foldees,
        }
    }

    fn folding_degree(&self) -> usize {
        self.foldees.len()
    }

    fn expression(&self) -> Expression<F>
    where
        F: PrimeField,
    {
        &self.preprocess * self.foldees.iter().product::<Expression<_>>()
    }
}

fn folding_degree<F: PrimeField>(products: &[Product<F>]) -> usize {
    products
        .iter()
        .map(Product::folding_degree)
        .max()
        .unwrap_or_default()
}
