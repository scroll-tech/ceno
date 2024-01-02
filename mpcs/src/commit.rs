use multilinear_extensions::mle::DenseMultilinearExtension;

use crate::structs::Commitment;

impl Commitment {
    /// Generate the commitment for a multilinear polynomial
    pub fn commit<F>(_poly: &DenseMultilinearExtension<F>) -> Self {
        todo!()
    }
}
