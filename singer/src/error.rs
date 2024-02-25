use gkr_graph::error::GKRGraphError;
use singer_utils::error::UtilError;

#[derive(Debug)]
pub enum ZKVMError {
    CircuitError,
    UtilError(UtilError),
    GKRGraphError(GKRGraphError),
    VerifyError,
}

impl From<GKRGraphError> for ZKVMError {
    fn from(error: GKRGraphError) -> Self {
        Self::GKRGraphError(error)
    }
}

impl From<UtilError> for ZKVMError {
    fn from(error: UtilError) -> Self {
        Self::UtilError(error)
    }
}
