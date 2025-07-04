use ff_ext::ExtensionField;
use sumcheck::structs::VerifierError;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum BackendError<E: ExtensionField> {
    #[error("layer verification failed: {0:?}, {1:?}")]
    LayerVerificationFailed(String, VerifierError<E>),
    #[error("circuit build faile")]
    CircuitError(String),
}

#[derive(Clone, Debug, Error)]
pub enum CircuitBuilderError {
    #[error("circuit build faile")]
    CircuitError(String),
}
