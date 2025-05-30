use thiserror::Error;

use crate::expression::Expression;

#[derive(Clone, Debug, Error)]
pub enum VerifierError<E> {
    #[error("Claim not match: expr: {0:?}\n (expr name: {3:?})\n expect: {1:?}, got: {2:?}")]
    ClaimNotMatch(Expression, E, E, String),
}
