#[derive(Debug)]
pub enum GKRGraphError {
    GKRError(gkr::error::GKRError),
    GraphCircuitError,
    VerifyError,
}

impl From<gkr::error::GKRError> for GKRGraphError {
    fn from(error: gkr::error::GKRError) -> Self {
        Self::GKRError(error)
    }
}
