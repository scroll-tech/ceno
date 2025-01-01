use ff::Field;
use ff_ext::ExtensionField;
use itertools::{Itertools, zip_eq};
use multilinear_extensions::virtual_poly::eq_eval;

use crate::{op_by_type, utils::i64_to_field};

use super::{Constant, Expression, FieldType, UniPolyVectorType, VectorType, Witness};

impl Expression {
    pub fn degree(&self) -> usize {
        match self {
            Expression::Const(_) => 0,
            Expression::Wit(_) => 1,
            Expression::Sum(_, _, degree) => *degree,
            Expression::Product(_, _, degree) => *degree,
            Expression::Neg(_, degree) => *degree,
            Expression::Pow(_, _, degree) => *degree,
        }
    }

    pub fn is_ext(&self) -> bool {
        match self {
            Expression::Const(c) => c.is_ext(),
            Expression::Wit(w) => w.is_ext(),
            Expression::Sum(e0, e1, _) | Expression::Product(e0, e1, _) => {
                e0.is_ext() || e1.is_ext()
            }
            Expression::Neg(e, _) => e.is_ext(),
            Expression::Pow(e, d, _) => {
                if *d > 0 {
                    e.is_ext()
                } else {
                    false
                }
            }
        }
    }

    pub fn evaluate<E: ExtensionField>(
        &self,
        ext_mle_evals: &[E],
        base_mle_evals: &[E],
        out_points: &[&[E]],
        in_point: &[E],
        challenges: &[E],
    ) -> E {
        match self {
            Expression::Const(constant) => constant.evaluate(challenges),
            Expression::Wit(w) => w.evaluate(base_mle_evals, ext_mle_evals, out_points, in_point),
            Expression::Sum(e0, e1, _) => {
                e0.evaluate(
                    ext_mle_evals,
                    base_mle_evals,
                    out_points,
                    in_point,
                    challenges,
                ) + e1.evaluate(
                    ext_mle_evals,
                    base_mle_evals,
                    out_points,
                    in_point,
                    challenges,
                )
            }
            Expression::Product(e0, e1, _) => {
                e0.evaluate(
                    ext_mle_evals,
                    base_mle_evals,
                    out_points,
                    in_point,
                    challenges,
                ) * e1.evaluate(
                    ext_mle_evals,
                    base_mle_evals,
                    out_points,
                    in_point,
                    challenges,
                )
            }
            Expression::Neg(e, _) => -e.evaluate(
                ext_mle_evals,
                base_mle_evals,
                out_points,
                in_point,
                challenges,
            ),
            Expression::Pow(e, d, _) => e
                .evaluate(
                    ext_mle_evals,
                    base_mle_evals,
                    out_points,
                    in_point,
                    challenges,
                )
                .pow([*d as u64]),
        }
    }

    pub fn calc<E: ExtensionField>(
        &self,
        ext: &[Vec<E>],
        base: &[Vec<E::BaseField>],
        eqs: &[Vec<E>],
        challenges: &[E],
    ) -> VectorType<E> {
        assert!(!(ext.is_empty() && base.is_empty()));
        let size = if !ext.is_empty() {
            ext[0].len()
        } else {
            base[0].len()
        };
        match self {
            Expression::Const(constant) => {
                VectorType::Ext(vec![constant.evaluate(challenges); size])
            }
            Expression::Wit(w) => match w {
                Witness::BasePoly(index) => VectorType::Base(base[*index].clone()),
                Witness::ExtPoly(index) => VectorType::Ext(ext[*index].clone()),
                Witness::EqPoly(index) => VectorType::Ext(eqs[*index].clone()),
            },
            Expression::Sum(e0, e1, _) => {
                e0.calc(ext, base, eqs, challenges) + e1.calc(ext, base, eqs, challenges)
            }
            Expression::Product(e0, e1, _) => {
                e0.calc(ext, base, eqs, challenges) * e1.calc(ext, base, eqs, challenges)
            }
            Expression::Neg(e, _) => -e.calc(ext, base, eqs, challenges),
            Expression::Pow(e, d, _) => {
                let poly = e.calc(ext, base, eqs, challenges);
                op_by_type!(
                    VectorType,
                    poly,
                    |poly| { poly.into_iter().map(|x| x.pow([*d as u64])).collect_vec() },
                    |ext| VectorType::Ext(ext),
                    |base| VectorType::Base(base)
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sumcheck_uni_poly<E: ExtensionField>(
        &self,
        ext_mles: &[&mut [E]],
        base_after_mles: &[Vec<E>],
        base_mles: &[&[E::BaseField]],
        eqs: &[Vec<E>],
        challenges: &[E],
        size: usize,
        degree: usize,
    ) -> Vec<E> {
        let poly = self.uni_poly_inner(
            ext_mles,
            base_after_mles,
            base_mles,
            eqs,
            challenges,
            size,
            degree,
        );
        op_by_type!(UniPolyVectorType, poly, |poly| {
            poly.into_iter().fold(vec![E::ZERO; degree], |acc, x| {
                zip_eq(acc, x).map(|(a, b)| a + b).collect_vec()
            })
        })
    }

    /// Compute \sum_x (eq(0, x) + eq(1, x)) * expr_0(X, x)
    #[allow(clippy::too_many_arguments)]
    pub fn zerocheck_uni_poly<'a, E: ExtensionField>(
        &self,
        ext_mles: &[&mut [E]],
        base_after_mles: &[Vec<E>],
        base_mles: &[&[E::BaseField]],
        challenges: &[E],
        coeffs: impl Iterator<Item = &'a E>,
        size: usize,
    ) -> Vec<E> {
        let degree = self.degree();
        let poly = self.uni_poly_inner(
            ext_mles,
            base_after_mles,
            base_mles,
            &[],
            challenges,
            size,
            degree,
        );

        op_by_type!(UniPolyVectorType, poly, |poly| {
            zip_eq(coeffs, poly).fold(vec![E::ZERO; degree], |mut acc, (c, poly)| {
                zip_eq(&mut acc, poly).for_each(|(a, x)| *a += *c * x);
                acc
            })
        })
    }

    /// Compute the extension field univariate polynomial evaluated on 1..degree + 1.
    #[allow(clippy::too_many_arguments)]
    fn uni_poly_inner<E: ExtensionField>(
        &self,
        ext_mles: &[&mut [E]],
        base_after_mles: &[Vec<E>],
        base_mles: &[&[E::BaseField]],
        eqs: &[Vec<E>],
        challenges: &[E],
        size: usize,
        degree: usize,
    ) -> UniPolyVectorType<E> {
        match self {
            Expression::Const(constant) => {
                let value = constant.evaluate(challenges);
                UniPolyVectorType::Ext(vec![vec![value; degree]; size >> 1])
            }
            Expression::Wit(w) => match w {
                Witness::BasePoly(index) => {
                    if !base_mles.is_empty() {
                        UniPolyVectorType::Base(uni_poly_helper(base_mles[*index], size, degree))
                    } else {
                        UniPolyVectorType::Ext(uni_poly_helper(
                            &base_after_mles[*index],
                            size,
                            degree,
                        ))
                    }
                }
                Witness::ExtPoly(index) => {
                    UniPolyVectorType::Ext(uni_poly_helper(ext_mles[*index], size, degree))
                }
                Witness::EqPoly(index) => {
                    UniPolyVectorType::Ext(uni_poly_helper(&eqs[*index], size, degree))
                }
            },
            Expression::Sum(expr0, expr1, _) => {
                let poly0 = expr0.uni_poly_inner(
                    ext_mles,
                    base_after_mles,
                    base_mles,
                    eqs,
                    challenges,
                    size,
                    degree,
                );
                let poly1 = expr1.uni_poly_inner(
                    ext_mles,
                    base_after_mles,
                    base_mles,
                    eqs,
                    challenges,
                    size,
                    degree,
                );
                poly0 + poly1
            }
            Expression::Product(expr0, expr1, _) => {
                let poly0 = expr0.uni_poly_inner(
                    ext_mles,
                    base_after_mles,
                    base_mles,
                    eqs,
                    challenges,
                    size,
                    degree,
                );
                let poly1 = expr1.uni_poly_inner(
                    ext_mles,
                    base_after_mles,
                    base_mles,
                    eqs,
                    challenges,
                    size,
                    degree,
                );
                poly0 * poly1
            }
            Expression::Neg(expr, _) => {
                let poly = expr.uni_poly_inner(
                    ext_mles,
                    base_after_mles,
                    base_mles,
                    eqs,
                    challenges,
                    size,
                    degree,
                );
                -poly
            }
            Expression::Pow(expr, d, _) => {
                let poly = expr.uni_poly_inner(
                    ext_mles,
                    base_after_mles,
                    base_mles,
                    eqs,
                    challenges,
                    size,
                    degree,
                );
                op_by_type!(
                    UniPolyVectorType,
                    poly,
                    |poly| {
                        poly.into_iter()
                            .map(|x| x.iter().map(|x| x.pow([*d as u64])).collect_vec())
                            .collect_vec()
                    },
                    |ext| UniPolyVectorType::Ext(ext),
                    |base| UniPolyVectorType::Base(base)
                )
            }
        }
    }
}

impl Constant {
    pub fn is_ext(&self) -> bool {
        match self {
            Constant::Base(_) => false,
            Constant::Challenge(_) => true,
            Constant::Sum(c0, c1) | Constant::Product(c0, c1) => c0.is_ext() || c1.is_ext(),
            Constant::Neg(c) => c.is_ext(),
            Constant::Pow(c, _) => c.is_ext(),
        }
    }

    pub fn evaluate<E: ExtensionField>(&self, challenges: &[E]) -> E {
        let res = self.evaluate_inner(challenges);
        op_by_type!(FieldType, res, |b| b, |e| e, |bf| E::from(bf))
    }

    fn evaluate_inner<E: ExtensionField>(&self, challenges: &[E]) -> FieldType<E> {
        match self {
            Constant::Base(value) => FieldType::Base(i64_to_field(*value)),
            Constant::Challenge(index) => FieldType::Ext(challenges[*index]),
            Constant::Sum(c0, c1) => c0.evaluate_inner(challenges) + c1.evaluate_inner(challenges),
            Constant::Product(c0, c1) => {
                c0.evaluate_inner(challenges) * c1.evaluate_inner(challenges)
            }
            Constant::Neg(c) => -c.evaluate_inner(challenges),
            Constant::Pow(c, degree) => {
                let value = c.evaluate_inner(challenges);
                op_by_type!(
                    FieldType,
                    value,
                    |value| { value.pow([*degree as u64]) },
                    |ext| FieldType::Ext(ext),
                    |base| FieldType::Base(base)
                )
            }
        }
    }

    pub fn entry<E: ExtensionField>(&self, challenges: &[E]) -> E {
        match self {
            Constant::Challenge(index) => challenges[*index],
            _ => unreachable!(),
        }
    }

    pub fn entry_mut<'a, E: ExtensionField>(&self, challenges: &'a mut [E]) -> &'a mut E {
        match self {
            Constant::Challenge(index) => &mut challenges[*index],
            _ => unreachable!(),
        }
    }
}

impl Witness {
    pub fn is_ext(&self) -> bool {
        match self {
            Witness::BasePoly(_) => false,
            Witness::ExtPoly(_) => true,
            Witness::EqPoly(_) => true,
        }
    }

    pub fn evaluate<E: ExtensionField>(
        &self,
        base_mle_evals: &[E],
        ext_mle_evals: &[E],
        out_point: &[&[E]],
        in_point: &[E],
    ) -> E {
        match self {
            Witness::BasePoly(index) => base_mle_evals[*index],
            Witness::ExtPoly(index) => ext_mle_evals[*index],
            Witness::EqPoly(index) => eq_eval(out_point[*index], in_point),
        }
    }

    pub fn base<'a, T>(&self, base_mle_evals: &'a [T]) -> &'a T {
        match self {
            Witness::BasePoly(index) => &base_mle_evals[*index],
            _ => unreachable!(),
        }
    }

    pub fn base_mut<'a, T>(&self, base_mle_evals: &'a mut [T]) -> &'a mut T {
        match self {
            Witness::BasePoly(index) => &mut base_mle_evals[*index],
            _ => unreachable!(),
        }
    }

    pub fn ext<'a, T>(&self, ext_mle_evals: &'a [T]) -> &'a T {
        match self {
            Witness::ExtPoly(index) => &ext_mle_evals[*index],
            _ => unreachable!(),
        }
    }

    pub fn ext_mut<'a, T>(&self, ext_mle_evals: &'a mut [T]) -> &'a mut T {
        match self {
            Witness::ExtPoly(index) => &mut ext_mle_evals[*index],
            _ => unreachable!(),
        }
    }
}

/// Compute the univariate polynomial evaluated on 1..degree.
#[inline]
fn uni_poly_helper<F: Field>(mle: &[F], size: usize, degree: usize) -> Vec<Vec<F>> {
    mle.chunks(2)
        .take(size >> 1)
        .map(|p| {
            let start = p[0];
            let step = p[1] - start;
            (0..degree)
                .scan(start, |state, _| {
                    *state += step;
                    Some(*state)
                })
                .collect_vec()
        })
        .collect_vec()
}

#[cfg(test)]
mod test {
    use crate::field_vec;
    use goldilocks::Goldilocks as F;

    #[test]
    fn test_uni_poly_helper() {
        // (x + 2), (3x + 4), (5x + 6), (7x + 8)
        let mle = field_vec![F, 2, 3, 4, 7, 6, 11, 8, 15, 11, 13, 17, 19, 23, 29, 31, 37];
        let size = 8;
        let degree = 3;
        let expected = vec![
            field_vec![F, 3, 4, 5],
            field_vec![F, 7, 10, 13],
            field_vec![F, 11, 16, 21],
            field_vec![F, 15, 22, 29],
        ];
        let result = super::uni_poly_helper(&mle, size, degree);
        assert_eq!(result, expected);
    }
}
