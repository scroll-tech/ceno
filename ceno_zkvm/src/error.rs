use singer_utils::error::UtilError;

#[derive(Debug)]
pub enum ZKVMError {
    CircuitError,
    UtilError(UtilError),
    VerifyError,
}

impl From<UtilError> for ZKVMError {
    fn from(error: UtilError) -> Self {
        Self::UtilError(error)
    }
}
