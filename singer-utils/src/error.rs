use gkr_graph::error::GKRGraphError;

#[derive(Debug)]
pub enum UtilError {
    ChipError,
    ChipHandlerError,
    UIntError,
    GKRGraphError(GKRGraphError),
}

impl From<GKRGraphError> for UtilError {
    fn from(error: GKRGraphError) -> Self {
        Self::GKRGraphError(error)
    }
}
