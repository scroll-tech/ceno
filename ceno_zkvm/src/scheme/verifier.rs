use ff_ext::ExtensionField;
use gkr::structs::PointAndEval;
use singer_utils::structs_v2::Circuit;
use transcript::Transcript;

use crate::error::ZKVMError;

use super::ZKVMProof;

pub struct ZKVMVerifier<E: ExtensionField> {
    circuit: Circuit<E>,
}

impl<E: ExtensionField> ZKVMVerifier<E> {
    pub fn new(circuit: Circuit<E>) -> Self {
        ZKVMVerifier { circuit }
    }
    pub fn verify(
        &self,
        proof: &ZKVMProof<E>,
        _transcript: &mut Transcript<E>,
        out_evals: &PointAndEval<E>,
        challenges: &[E], // derive challenge from PCS
    ) -> Result<(), ZKVMError> {
        // verify and reduce product tower sumcheck

        // verify main + sel sumcheck

        // verify record (degree = 1) statement, thus no sumcheck

        // verify zero expression (degree = 1) statement, thus no sumcheck
        Ok(())
    }
}
