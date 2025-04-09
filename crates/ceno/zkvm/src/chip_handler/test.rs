use ff_ext::ExtensionField;

use crate::{circuit_builder::CircuitBuilder, expression::Expression};

pub enum DebugIndex {
    RdWrite = 0,
}

impl<E: ExtensionField> CircuitBuilder<'_, E> {
    pub fn register_debug_expr<T: Into<usize>>(&mut self, debug_index: T, expr: Expression<E>) {
        self.cs.register_debug_expr(debug_index, expr)
    }

    pub fn get_debug_expr<T: Into<usize>>(&mut self, debug_index: T) -> &[Expression<E>] {
        self.cs.get_debug_expr(debug_index)
    }
}
