use sumcheck::structs::VerifierError;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum BackendError {
    #[error("layer verification failed: {0:?}, {1:?}")]
    LayerVerificationFailed(Box<str>, VerifierError),
    #[error("circuit build faile")]
    CircuitError(Box<str>),
}

#[derive(Clone, Debug, Error)]
pub enum CircuitBuilderError {
    #[error("circuit build faile")]
    CircuitError(Box<str>),
}
