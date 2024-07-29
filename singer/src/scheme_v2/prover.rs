use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly_v2::VirtualPolynomialV2;
use singer_utils::structs_v2::Circuit;

use crate::error::ZKVMError;

use super::ZKVMProof;

pub struct ZKVMProver<E: ExtensionField> {
    circuit: Circuit<E>,
}

impl<E: ExtensionField> ZKVMProver<E> {
    pub fn new(circuit: Circuit<E>) -> Self {
        ZKVMProver { circuit }
    }
    pub fn create_proof(&self, challenges: &[E]) -> Result<ZKVMProof, ZKVMError> {
        // construct main constraint sumcheck virtual polynomial
        let circuit = &self.circuit;

        // witness inference

        Ok(ZKVMProof {})
    }
}
