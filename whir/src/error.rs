#[derive(Debug)]
pub enum Error {
    MmcsError(String),
    InvalidProof(String),
}
