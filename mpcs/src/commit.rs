use ff_ext::ExtensionField;
use multilinear_extensions::mle::DenseMultilinearExtension;

use crate::structs::Commitment;

impl Commitment {
    /// Generate the commitment for a multilinear polynomial
    pub fn commit<E: ExtensionField>(_poly: &DenseMultilinearExtension<E>) -> Self {
        todo!()
    }
}
