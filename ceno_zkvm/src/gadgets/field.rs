use serde::{Deserialize, Serialize};

pub mod field_inner_product;
pub mod field_op;
pub mod field_sqrt;
pub mod range;

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
