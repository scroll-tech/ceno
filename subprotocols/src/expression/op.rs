use std::{
    cmp::max,
    ops::{Add, Mul, Neg, Sub},
};

use ff_ext::ExtensionField;
use itertools::zip_eq;

use crate::{define_commutative_op_mle2, define_op_mle, define_op_mle2};

use super::{Expression, FieldType, UniPolyVectorType, VectorType};

impl Add for Expression {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let degree = max(self.degree(), other.degree());
        Expression::Sum(Box::new(self), Box::new(other), degree)
    }
}

impl Mul for Expression {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        #[allow(clippy::suspicious_arithmetic_impl)]
        let degree = self.degree() + other.degree();
        Expression::Product(Box::new(self), Box::new(other), degree)
    }
}

impl Neg for Expression {
    type Output = Self;

    fn neg(self) -> Self {
        let deg = self.degree();
        Expression::Neg(Box::new(self), deg)
    }
}

impl Sub for Expression {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self + (-other)
    }
}

define_commutative_op_mle2!(UniPolyVectorType, Add, add, |x, y| {
    zip_eq(&mut x, y).for_each(|(x, y)| zip_eq(x, y).for_each(|(x, y)| *x += y));
    x
});
define_commutative_op_mle2!(UniPolyVectorType, Mul, mul, |x, y| {
    zip_eq(&mut x, y).for_each(|(x, y)| zip_eq(x, y).for_each(|(x, y)| *x *= y));
    x
});
define_op_mle2!(UniPolyVectorType, Sub, sub, |x, y| x + (-y));
define_op_mle!(UniPolyVectorType, Neg, neg, |x| {
    x.iter_mut()
        .for_each(|x| x.iter_mut().for_each(|x| *x = -(*x)));
    x
});

define_commutative_op_mle2!(VectorType, Add, add, |x, y| {
    zip_eq(&mut x, y).for_each(|(x, y)| *x += y);
    x
});
define_commutative_op_mle2!(VectorType, Mul, mul, |x, y| {
    zip_eq(&mut x, y).for_each(|(x, y)| *x *= y);
    x
});
define_op_mle2!(VectorType, Sub, sub, |x, y| x + (-y));
define_op_mle!(VectorType, Neg, neg, |x| {
    x.iter_mut().for_each(|x| *x = -(*x));
    x
});

define_commutative_op_mle2!(FieldType, Add, add, |x, y| x + y);
define_commutative_op_mle2!(FieldType, Mul, mul, |x, y| x * y);
define_op_mle2!(FieldType, Sub, sub, |x, y| x + (-y));
define_op_mle!(FieldType, Neg, neg, |x| -x);
