use serde::{Deserialize, Serialize};

pub mod field_op;

/// This is an arithmetic operation for emulating modular arithmetic.
#[derive(Default, PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
pub enum FieldOperation {
    /// Addition.
    #[default]
    Add,
    /// Multiplication.
    Mul,
    /// Subtraction.
    Sub,
    /// Division.
    Div,
}
