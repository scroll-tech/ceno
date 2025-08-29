use gkr_iop::error::{BackendError, CircuitBuilderError};
use mpcs::Error;

#[derive(Debug)]
pub enum UtilError {
    UIntError(Box<str>),
}

#[derive(Debug)]
pub enum ZKVMError {
    CircuitError,
    CircuitBuilderError(CircuitBuilderError),
    BackendError(BackendError),
    UtilError(UtilError),
    WitnessNotFound(Box<str>),
    InvalidWitness(Box<str>),
    InvalidProof(Box<str>),
    VKNotFound(Box<str>),
    FixedTraceNotFound(Box<str>),
    VerifyError(Box<str>),
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
