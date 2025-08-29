/// Local error
#[derive(Clone, Debug)]
pub enum Error {
    /// Partial points is greater than the number of variables
    InvalidSizeOfPartialPoint,
}
