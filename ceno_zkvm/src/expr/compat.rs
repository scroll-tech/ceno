use ff_ext::ExtensionField;
use crate::expression as X;
use crate::expr::Expr;

impl<'a, E: ExtensionField> From<Expr<'a, E>> for X::Expression<E> {
    fn from(expr: Expr<'a, E>) -> X::Expression<E> {
        match expr {
            Expr::Constant(c) => X::Expression::Constant(c),
            Expr::Compound { expr, .. } => X::Expression::from(expr),
        }
    }
}

impl<'a, E: ExtensionField> From<Comb<'a, E>> for X::Expression<E> {
    fn from(expr: Expr<'a, E>) -> X::Expression<E> {
        match expr {
            Expr::Constant(c) => X::Expression::Constant(c),
            Expr::Compound { expr, .. } => X::Expression::Compound(expr.0),
        }
    }
}
