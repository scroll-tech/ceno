use gkr_graph::error::GKRGraphError;
use singer_utils::error::UtilError;

#[derive(Debug)]
pub enum ZKVMError {
    CircuitError,
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
        match error {
            UtilError::ChipError => Self::CircuitError,
            UtilError::UIntError => Self::CircuitError,
        }
    }
}
