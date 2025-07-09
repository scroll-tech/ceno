use gkr_iop::error::{BackendError, CircuitBuilderError};
use mpcs::Error;

#[derive(Debug)]
pub enum UtilError {
    UIntError(String),
}

#[derive(Debug)]
pub enum ZKVMError {
    CircuitError,
    CircuitBuilderError(CircuitBuilderError),
    BackendError(BackendError),
    UtilError(UtilError),
    WitnessNotFound(String),
    InvalidWitness(String),
    VKNotFound(String),
    FixedTraceNotFound(String),
    VerifyError(String),
    PCSError(Error),
}

impl From<UtilError> for ZKVMError {
    fn from(error: UtilError) -> Self {
        Self::UtilError(error)
    }
}

impl From<CircuitBuilderError> for ZKVMError {
    fn from(e: CircuitBuilderError) -> Self {
        ZKVMError::CircuitBuilderError(e)
    }
}

impl From<BackendError> for ZKVMError {
    fn from(e: BackendError) -> Self {
        ZKVMError::BackendError(e)
    }
}
