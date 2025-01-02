use std::sync::Arc;

use ff_ext::ExtensionField;

mod evaluate;
mod op;

mod macros;

pub type Point<E> = Arc<Vec<E>>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Constant {
    /// Base field
    Base(i64),
    /// Challenge
    Challenge(usize),
    /// Sum
    Sum(Box<Constant>, Box<Constant>),
    /// Product
    Product(Box<Constant>, Box<Constant>),
    /// Neg
    Neg(Box<Constant>),
    /// Pow
    Pow(Box<Constant>, usize),
}

impl Default for Constant {
    fn default() -> Self {
        Constant::Base(0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Witness {
    /// Base field polynomial (index).
    BasePoly(usize),
    /// Extension field polynomial (index).
    ExtPoly(usize),
    /// Eq polynomial
    EqPoly(usize),
}

impl Default for Witness {
    fn default() -> Self {
        Witness::BasePoly(0)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Expression {
    /// Constant
    Const(Constant),
    /// Witness.
    Wit(Witness),
    /// This is the sum of two expressions, with `degree`.
    Sum(Box<Expression>, Box<Expression>, usize),
    /// This is the product of two expressions, with `degree`.
    Product(Box<Expression>, Box<Expression>, usize),
    /// Neg, with `degree`.
    Neg(Box<Expression>, usize),
    /// Pow, with `D` and `degree`.
    Pow(Box<Expression>, usize, usize),
}

impl std::fmt::Debug for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expression::Const(c) => write!(f, "{:?}", c),
            Expression::Wit(w) => write!(f, "{:?}", w),
            Expression::Sum(a, b, _) => write!(f, "({:?} + {:?})", a, b),
            Expression::Product(a, b, _) => write!(f, "({:?} * {:?})", a, b),
            Expression::Neg(a, _) => write!(f, "(-{:?})", a),
            Expression::Pow(a, n, _) => write!(f, "({:?})^({})", a, n),
        }
    }
}

impl std::fmt::Debug for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Witness::BasePoly(i) => write!(f, "BP[{}]", i),
            Witness::ExtPoly(i) => write!(f, "EP[{}]", i),
            Witness::EqPoly(i) => write!(f, "EQ[{}]", i),
        }
    }
}

/// Vector of univariate polys.
#[derive(Clone, Debug)]
enum UniPolyVectorType<E: ExtensionField> {
    Base(Vec<Vec<E::BaseField>>),
    Ext(Vec<Vec<E>>),
}

/// Vector of field type.
#[derive(Clone, PartialEq, Eq)]
pub enum VectorType<E: ExtensionField> {
    Base(Vec<E::BaseField>),
    Ext(Vec<E>),
}

impl<E: ExtensionField> std::fmt::Debug for VectorType<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VectorType::Base(v) => {
                let mut v = v.iter();
                write!(f, "[")?;
                if let Some(e) = v.next() {
                    write!(f, "{:?}", e)?;
                }
                for _ in 0..2 {
                    if let Some(e) = v.next() {
                        write!(f, ", {:?}", e)?;
                    } else {
                        break;
                    }
                }
                if v.next().is_some() {
                    write!(f, ", ...]")?;
                } else {
                    write!(f, "]")?;
                };
                Ok(())
            }
            VectorType::Ext(v) => {
                let mut v = v.iter();
                write!(f, "[")?;
                if let Some(e) = v.next() {
                    write!(f, "{:?}", e)?;
                }
                for _ in 0..2 {
                    if let Some(e) = v.next() {
                        write!(f, ", {:?}", e)?;
                    } else {
                        break;
                    }
                }
                if v.next().is_some() {
                    write!(f, ", ...]")?;
                } else {
                    write!(f, "]")?;
                };
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug)]
enum FieldType<E: ExtensionField> {
    Base(E::BaseField),
    Ext(E),
}

impl From<Witness> for Expression {
    fn from(w: Witness) -> Self {
        Expression::Wit(w)
    }
}

impl From<Constant> for Expression {
    fn from(c: Constant) -> Self {
        Expression::Const(c)
    }
}
