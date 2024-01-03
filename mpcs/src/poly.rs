use crate::util::arithmetic::Field;
use std::{fmt::Debug, ops::AddAssign};

pub mod multilinear;

pub trait Polynomial<F: Field>: Clone + Debug + for<'a> AddAssign<(&'a F, &'a Self)> {
    type Point: Clone + Debug;

    fn from_evals(evals: Vec<F>) -> Self;

    fn into_evals(self) -> Vec<F>;

    fn evals(&self) -> &[F];

    fn evaluate(&self, point: &Self::Point) -> F;
}
