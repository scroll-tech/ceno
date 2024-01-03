use crate::util::{
    arithmetic::Field,
    expression::{CommonPolynomial, Expression, Query, Rotation},
};
use std::{fmt::Debug, ops::Deref};

#[derive(Clone, Debug, Default)]
pub(crate) struct ExpressionRegistry<F: Field> {
    offsets: Offsets,
    constants: Vec<F>,
    has_identity: bool,
    lagranges: Vec<i32>,
    eq_xys: Vec<usize>,
    rotations: Vec<Rotation>,
    polys: Vec<(Query, usize)>,
    calculations: Vec<Calculation<ValueSource>>,
    indexed_calculations: Vec<Calculation<usize>>,
    outputs: Vec<ValueSource>,
    indexed_outputs: Vec<usize>,
}

impl<F: Field> ExpressionRegistry<F> {
    pub(crate) fn new() -> Self {
        Self {
            constants: vec![F::ZERO, F::ONE, F::ONE.double()],
            rotations: vec![Rotation(0)],
            ..Default::default()
        }
    }

    pub(crate) fn register(&mut self, expression: &Expression<F>) {
        let output = self.register_expression(expression);
        self.offsets = Offsets::new(
            self.constants.len(),
            self.lagranges.len(),
            self.eq_xys.len(),
            self.polys.len(),
        );
        self.indexed_calculations = self
            .calculations
            .iter()
            .map(|calculation| calculation.indexed(&self.offsets))
            .collect();
        self.outputs.push(output);
        self.indexed_outputs = self
            .outputs
            .iter()
            .map(|output| output.indexed(&self.offsets))
            .collect();
    }

    pub(crate) fn offsets(&self) -> &Offsets {
        &self.offsets
    }

    pub(crate) fn has_identity(&self) -> bool {
        self.has_identity
    }

    pub(crate) fn lagranges(&self) -> &[i32] {
        &self.lagranges
    }

    pub(crate) fn eq_xys(&self) -> &[usize] {
        &self.eq_xys
    }

    pub(crate) fn rotations(&self) -> &[Rotation] {
        &self.rotations
    }

    pub(crate) fn polys(&self) -> &[(Query, usize)] {
        &self.polys
    }

    pub(crate) fn indexed_calculations(&self) -> &[Calculation<usize>] {
        &self.indexed_calculations
    }

    pub(crate) fn indexed_outputs(&self) -> &[usize] {
        &self.indexed_outputs
    }

    pub(crate) fn cache(&self) -> Vec<F> {
        let mut cache = vec![F::ZERO; self.offsets.calculations() + self.calculations.len()];
        cache[..self.constants.len()].clone_from_slice(&self.constants);
        cache
    }

    fn register_value<T: Eq + Clone>(
        &mut self,
        field: impl FnOnce(&mut Self) -> &mut Vec<T>,
        item: &T,
    ) -> usize {
        let field = field(self);
        if let Some(idx) = field.iter().position(|lhs| lhs == item) {
            idx
        } else {
            let idx = field.len();
            field.push(item.clone());
            idx
        }
    }

    fn register_constant(&mut self, constant: &F) -> ValueSource {
        ValueSource::Constant(self.register_value(|ev| &mut ev.constants, constant))
    }

    fn register_identity(&mut self) -> ValueSource {
        self.has_identity = true;
        ValueSource::Identity
    }

    fn register_lagrange(&mut self, i: i32) -> ValueSource {
        ValueSource::Lagrange(self.register_value(|ev| &mut ev.lagranges, &i))
    }

    fn register_eq_xy(&mut self, idx: usize) -> ValueSource {
        ValueSource::EqXY(self.register_value(|ev| &mut ev.eq_xys, &idx))
    }

    fn register_rotation(&mut self, rotation: Rotation) -> usize {
        self.register_value(|ev| &mut ev.rotations, &(rotation))
    }

    fn register_poly(&mut self, query: &Query) -> ValueSource {
        let rotation = self.register_rotation(query.rotation());
        ValueSource::Poly(self.register_value(|ev| &mut ev.polys, &(*query, rotation)))
    }

    fn register_calculation(&mut self, calculation: Calculation<ValueSource>) -> ValueSource {
        ValueSource::Calculation(self.register_value(|ev| &mut ev.calculations, &calculation))
    }

    fn register_expression(&mut self, expr: &Expression<F>) -> ValueSource {
        match expr {
            Expression::Constant(constant) => self.register_constant(constant),
            Expression::CommonPolynomial(poly) => match poly {
                CommonPolynomial::Identity => self.register_identity(),
                CommonPolynomial::Lagrange(i) => self.register_lagrange(*i),
                CommonPolynomial::EqXY(idx) => self.register_eq_xy(*idx),
            },
            Expression::Polynomial(query) => self.register_poly(query),
            Expression::Challenge(_) => unreachable!(),
            Expression::Negated(value) => {
                if let Expression::Constant(constant) = value.deref() {
                    self.register_constant(&-*constant)
                } else {
                    let value = self.register_expression(value);
                    if let ValueSource::Constant(idx) = value {
                        self.register_constant(&-self.constants[idx])
                    } else {
                        self.register_calculation(Calculation::Negated(value))
                    }
                }
            }
            Expression::Sum(lhs, rhs) => match (lhs.deref(), rhs.deref()) {
                (minuend, Expression::Negated(subtrahend))
                | (Expression::Negated(subtrahend), minuend) => {
                    let minuend = self.register_expression(minuend);
                    let subtrahend = self.register_expression(subtrahend);
                    match (minuend, subtrahend) {
                        (ValueSource::Constant(minuend), ValueSource::Constant(subtrahend)) => self
                            .register_constant(
                                &(self.constants[minuend] - &self.constants[subtrahend]),
                            ),
                        (ValueSource::Constant(0), _) => {
                            self.register_calculation(Calculation::Negated(subtrahend))
                        }
                        (_, ValueSource::Constant(0)) => minuend,
                        _ => self.register_calculation(Calculation::Sub(minuend, subtrahend)),
                    }
                }
                _ => {
                    let lhs = self.register_expression(lhs);
                    let rhs = self.register_expression(rhs);
                    match (lhs, rhs) {
                        (ValueSource::Constant(lhs), ValueSource::Constant(rhs)) => {
                            self.register_constant(&(self.constants[lhs] + &self.constants[rhs]))
                        }
                        (ValueSource::Constant(0), other) | (other, ValueSource::Constant(0)) => {
                            other
                        }
                        _ => {
                            if lhs <= rhs {
                                self.register_calculation(Calculation::Add(lhs, rhs))
                            } else {
                                self.register_calculation(Calculation::Add(rhs, lhs))
                            }
                        }
                    }
                }
            },
            Expression::Product(lhs, rhs) => {
                let lhs = self.register_expression(lhs);
                let rhs = self.register_expression(rhs);
                match (lhs, rhs) {
                    (ValueSource::Constant(0), _) | (_, ValueSource::Constant(0)) => {
                        ValueSource::Constant(0)
                    }
                    (ValueSource::Constant(1), other) | (other, ValueSource::Constant(1)) => other,
                    (ValueSource::Constant(2), other) | (other, ValueSource::Constant(2)) => {
                        self.register_calculation(Calculation::Add(other, other))
                    }
                    (lhs, rhs) => {
                        if lhs <= rhs {
                            self.register_calculation(Calculation::Mul(lhs, rhs))
                        } else {
                            self.register_calculation(Calculation::Mul(rhs, lhs))
                        }
                    }
                }
            }
            Expression::Scaled(value, scalar) => {
                if scalar == &F::ZERO {
                    ValueSource::Constant(0)
                } else if scalar == &F::ONE {
                    self.register_expression(value)
                } else {
                    let value = self.register_expression(value);
                    let scalar = self.register_constant(scalar);
                    self.register_calculation(Calculation::Mul(value, scalar))
                }
            }
            Expression::DistributePowers(_, _) => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Offsets(usize, usize, usize, usize, usize);

impl Offsets {
    fn new(
        num_constants: usize,
        num_lagranges: usize,
        num_eq_xys: usize,
        num_polys: usize,
    ) -> Self {
        let mut offset = Self::default();
        offset.0 = num_constants;
        offset.1 = offset.0 + 1;
        offset.2 = offset.1 + num_lagranges;
        offset.3 = offset.2 + num_eq_xys;
        offset.4 = offset.3 + num_polys;
        offset
    }

    pub(crate) fn identity(&self) -> usize {
        self.0
    }

    pub(crate) fn lagranges(&self) -> usize {
        self.1
    }

    pub(crate) fn eq_xys(&self) -> usize {
        self.2
    }

    pub(crate) fn polys(&self) -> usize {
        self.3
    }

    pub(crate) fn calculations(&self) -> usize {
        self.4
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ValueSource {
    Constant(usize),
    Identity,
    Lagrange(usize),
    EqXY(usize),
    Poly(usize),
    Calculation(usize),
}

impl ValueSource {
    fn indexed(&self, offsets: &Offsets) -> usize {
        use ValueSource::*;
        match self {
            Constant(idx) => *idx,
            Identity => offsets.identity(),
            Lagrange(idx) => offsets.lagranges() + idx,
            EqXY(idx) => offsets.eq_xys() + idx,
            Poly(idx) => offsets.polys() + idx,
            Calculation(idx) => offsets.calculations() + idx,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Calculation<T> {
    Negated(T),
    Add(T, T),
    Sub(T, T),
    Mul(T, T),
}

impl Calculation<ValueSource> {
    fn indexed(&self, offsets: &Offsets) -> Calculation<usize> {
        use Calculation::*;
        match self {
            Negated(value) => Negated(value.indexed(offsets)),
            Add(lhs, rhs) => Add(lhs.indexed(offsets), rhs.indexed(offsets)),
            Sub(lhs, rhs) => Sub(lhs.indexed(offsets), rhs.indexed(offsets)),
            Mul(lhs, rhs) => Mul(lhs.indexed(offsets), rhs.indexed(offsets)),
        }
    }
}

impl Calculation<usize> {
    pub(crate) fn calculate<F: Field>(&self, cache: &mut [F], idx: usize) {
        use Calculation::*;
        cache[idx] = match self {
            Negated(value) => -cache[*value],
            Add(lhs, rhs) => cache[*lhs] + &cache[*rhs],
            Sub(lhs, rhs) => cache[*lhs] - &cache[*rhs],
            Mul(lhs, rhs) => cache[*lhs] * &cache[*rhs],
        };
    }
}
