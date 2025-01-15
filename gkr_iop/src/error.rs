use subprotocols::error::VerifierError;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum BackendError<E> {
    #[error("layer verification failed: {0:?}, {1:?}")]
    LayerVerificationFailed(String, VerifierError<E>),
}
