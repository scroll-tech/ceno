#[derive(Debug)]
pub enum ZKVMError {
    CircuitError,
    GKRGraphError(gkr_graph::error::GKRGraphError),
    VerifyError,
}

impl From<gkr_graph::error::GKRGraphError> for ZKVMError {
    fn from(error: gkr_graph::error::GKRGraphError) -> Self {
        Self::GKRGraphError(error)
    }
}
