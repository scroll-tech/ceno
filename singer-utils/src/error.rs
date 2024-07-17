use gkr_graph::error::GKRGraphError;

#[derive(Debug)]
pub enum UtilError {
    ChipError,
    ChipHandlerError,
    // TODO: consider splitting this into smaller errors
    UIntError(String),
    GKRGraphError(GKRGraphError),
}

impl From<GKRGraphError> for UtilError {
    fn from(error: GKRGraphError) -> Self {
        Self::GKRGraphError(error)
    }
}
