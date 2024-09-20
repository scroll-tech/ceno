use mpcs::Error;

#[derive(Debug)]
pub enum UtilError {
    UIntError(String),
}

#[derive(Debug)]
pub enum ZKVMError {
    CircuitError,
    UtilError(UtilError),
    WitnessNotFound(String),
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
