#[derive(Clone, Debug)]
pub enum Error {
    /// See [`multilinear_extensions::Error`].
    MultilinearExtensions(multilinear_extensions::Error),
    MmcsError(String),
    InvalidProof(String),
}

impl From<multilinear_extensions::Error> for Error {
    fn from(value: multilinear_extensions::Error) -> Self {
        Self::MultilinearExtensions(value)
    }
}
