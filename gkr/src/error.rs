#[derive(Debug)]
pub enum GKRError {
    InvalidCircuit,
    VerifyError(&'static str),
}
