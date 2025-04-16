#[derive(Clone, Debug)]
pub enum Error {
    MmcsError(String),
    InvalidProof(String),
}
