use gkr::error::GKRError;

#[derive(Debug)]
pub enum GKRGraphError {
    GKRError(GKRError),
    GraphCircuitError,
    VerifyError,
}

impl From<GKRError> for GKRGraphError {
    fn from(error: GKRError) -> Self {
        Self::GKRError(error)
    }
}
