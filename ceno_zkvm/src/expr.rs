use crate::{
    expression::{Fixed, Instance},
    structs::{ChallengeId, WitnessId},
};
use bumpalo::Bump;
use ff_ext::ExtensionField;

#[derive(Clone, Copy, Debug)]
pub enum BasicExpr<E: ExtensionField> {
    WitIn(WitnessId),
    Fixed(Fixed),
    Instance(Instance),
    Constant(E::BaseField),
}

#[derive(Clone, Copy, Debug)]
pub struct CompoundExpr<'a, E: ExtensionField>(&'a ExprTree<'a, E>);

/// Internal type to represent the expression trees
#[derive(Debug)]
pub enum ExprTree<'a, E: ExtensionField> {
    /// BasicExpr
    Basic(BasicExpr<E>),
    /// This is the sum of two expression
    Sum(CompoundExpr<'a, E>, CompoundExpr<'a, E>),
    /// This is the product of two polynomials
    Product(CompoundExpr<'a, E>, CompoundExpr<'a, E>),
    // TODO(Matthias): Why is this one special, instead of build from `Sum` and `Product`?
    /// This is x, a, b expr to represent ax + b polynomial
    /// and x is one of wit / fixed / instance, a and b are either constant or challenge
    ScaledSum(
        CompoundExpr<'a, E>,
        CompoundExpr<'a, E>,
        CompoundExpr<'a, E>,
    ),
    Challenge(ChallengeId, usize, E, E), // (challenge_id, power, scalar, offset)
}

/// Contains a reference to [`ExprTree`] that is managed by [`ExprBuilder`].
#[derive(Clone, Copy, Debug)]
pub enum Expr<'a, E: ExtensionField> {
    Basic(BasicExpr<E>),
    Compound {
        expr: CompoundExpr<'a, E>,
        builder: &'a ExprBuilder,
    },
}

/// Expression Builder.  Contains a [`Bump`] memory arena that will allocate and
/// store all the [`ExprTree`]s.
#[derive(Debug, Default)]
pub struct ExprBuilder {
    bump: Bump,
}

impl<'a, E: ExtensionField> From<&'a mut ExprTree<'a, E>> for CompoundExpr<'a, E> {
    fn from(value: &'a mut ExprTree<'a, E>) -> Self {
        CompoundExpr(value)
    }
}

impl ExprBuilder {
    /// Internalise an [`ExprTree`] by moving it to memory allocated by the
    /// [`Bump`] arena owned by [`ExprBuilder`].
    fn intern<'a, E: ExtensionField>(&'a self, expr_tree: ExprTree<'a, E>) -> CompoundExpr<'a, E> {
        self.bump.alloc(expr_tree).into()
    }

    fn ensure_interned<'a, E: ExtensionField>(&'a self, expr: Expr<'a, E>) -> CompoundExpr<'a, E> {
        match expr {
            Expr::Compound { expr, .. } => expr,
            Expr::Basic(value) => self.basic_tree(value),
        }
    }

    /// Wrap [`ExprTree`] reference with an [`Expr`] wrapper
    fn wrap<'a, E: ExtensionField>(&'a self, expr: CompoundExpr<'a, E>) -> Expr<'a, E> {
        Expr::Compound {
            expr,
            builder: self,
        }
    }

    // /// Convenience method for creating `BinOp` nodes
    // fn bin_op<'a, E: ExtensionField>(
    //     &'a self,
    //     op: BinOp,
    //     left: CompoundExpr<'a, E>,
    //     right: CompoundExpr<'a, E>,
    // ) -> CompoundExpr<'a, E> {
    //     let expr_tree = ExprTree::BinOp { op, left, right };
    //     self.intern(expr_tree)
    // }

    // /// Convenience method for creating `UnaOp` nodes
    // fn una_op<'a, V>(&'a self, op: UnaOp, expr: CompoundExpr<'a, V>) -> CompoundExpr<'a, V> {
    //     let expr_tree = ExprTree::UnaOp { op, expr };
    //     self.intern(expr_tree)
    // }

    /// Allocate Constant Expression Tree in the Expr Builder
    fn basic_tree<E: ExtensionField>(&self, basic: BasicExpr<E>) -> CompoundExpr<'_, E> {
        self.intern(ExprTree::Basic(basic))
    }

    // fn lit_tree<V>(&self, value: V) -> CompoundExpr<'_, V> {
    //     self.intern(ExprTree::Literal { value })
    // }

    // /// Create a `Constant` expression
    // pub fn constant<V>(&self, value: i64) -> Expr<'_, V> { self.wrap(self.constant_tree(value)) }

    // /// Create a `Literal` expression
    // pub fn lit<V>(&self, value: V) -> Expr<'_, V> { self.wrap(self.lit_tree(value)) }
}
