#[derive(Debug)]
pub enum UtilError {
    UIntError(String),
}

#[derive(Debug)]
pub enum ZKVMError {
    CircuitError,
    UtilError(UtilError),
    VerifyError(&'static str),
}

impl From<UtilError> for ZKVMError {
    fn from(error: UtilError) -> Self {
        Self::UtilError(error)
    }
}
