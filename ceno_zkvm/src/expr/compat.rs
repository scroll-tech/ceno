use crate::{
    expr as Y,
    expr::{CompoundExpr, Expr, ExprBuilder, ExprTree},
    expression as X,
};
use ff_ext::ExtensionField;

impl<'a, E: ExtensionField> From<Expr<'a, E>> for X::Expression<E> {
    fn from(expr: Expr<'a, E>) -> X::Expression<E> {
        match expr {
            Expr::Constant(c) => X::Expression::Constant(c),
            Expr::Compound { expr, .. } => X::Expression::from(expr),
        }
    }
}

impl<'a, E: ExtensionField> From<&Expr<'a, E>> for X::Expression<E> {
    fn from(expr: &Expr<'a, E>) -> X::Expression<E> {
        match expr {
            Expr::Constant(c) => X::Expression::Constant(*c),
            Expr::Compound { expr, .. } => X::Expression::from(expr),
        }
    }
}

impl<'a, E: ExtensionField> From<Y::CompoundExpr<'a, E>> for X::Expression<E> {
    fn from(c: Y::CompoundExpr<'a, E>) -> X::Expression<E> {
        X::Expression::from(c.0)
    }
}

impl<'a, E: ExtensionField> From<&Y::CompoundExpr<'a, E>> for X::Expression<E> {
    fn from(c: &Y::CompoundExpr<'a, E>) -> X::Expression<E> {
        X::Expression::from(c.0)
    }
}

impl<'a, E: ExtensionField> From<&Y::ExprTree<'a, E>> for X::Expression<E> {
    fn from(tree: &Y::ExprTree<'a, E>) -> X::Expression<E> {
        use Y::ExprTree::*;
        match tree {
            WitIn(id) => X::Expression::WitIn(*id),
            Fixed(id) => X::Expression::Fixed(*id),
            Instance(id) => X::Expression::Instance(*id),
            Constant(c) => X::Expression::Constant(*c),
            Sum(a, b) => X::Expression::Sum(
                Box::new(X::Expression::from(a)),
                Box::new(X::Expression::from(b)),
            ),
            Product(a, b) => X::Expression::Product(
                Box::new(X::Expression::from(a)),
                Box::new(X::Expression::from(b)),
            ),
            ScaledSum(a, b, c) => X::Expression::ScaledSum(
                Box::new(X::Expression::from(a)),
                Box::new(X::Expression::from(b)),
                Box::new(X::Expression::from(c)),
            ),
            Challenge(id, power, scalar, offset) => {
                X::Expression::Challenge(*id, *power, *scalar, *offset)
            }
        }
    }
}

impl ExprBuilder {
    fn convert_tree_internal<E: ExtensionField>(&self, x: X::Expression<E>) -> CompoundExpr<'_, E> {
        // match
        let tree = match x {
            X::Expression::WitIn(id) => ExprTree::WitIn(id),
            X::Expression::Fixed(id) => ExprTree::Fixed(id),
            X::Expression::Instance(id) => ExprTree::Instance(id),
            X::Expression::Constant(c) => ExprTree::Constant(c),
            X::Expression::Sum(a, b) => {
                let a = self.convert_tree_internal(*a);
                let b = self.convert_tree_internal(*b);
                ExprTree::Sum(a, b)
            }
            X::Expression::Product(a, b) => {
                let a = self.convert_tree_internal(*a);
                let b = self.convert_tree_internal(*b);
                ExprTree::Product(a, b)
            }
            X::Expression::ScaledSum(a, b, c) => {
                let a = self.convert_tree_internal(*a);
                let b = self.convert_tree_internal(*b);
                let c = self.convert_tree_internal(*c);
                ExprTree::ScaledSum(a, b, c)
            }
            X::Expression::Challenge(id, power, scalar, offset) => {
                ExprTree::Challenge(id, power, scalar, offset)
            }
        };
        self.intern(tree)
    }

    pub fn convert_tree<E: ExtensionField>(&self, x: X::Expression<E>) -> Expr<'_, E> {
        self.wrap(self.convert_tree_internal(x))
    }
}
