use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly::VPAuxInfo;
use transcript::Transcript;

use crate::structs::{Commitment, PCSProof, PCSVerifierState};

#[allow(unused)]
impl<E: ExtensionField> PCSVerifierState<E> {
    pub fn verify(
        poly_eval_pairs: &[(Commitment, VPAuxInfo<E>, E)],
        eval_point: &[E],
        proof: &PCSProof<E>,
        transcript: &mut Transcript<E>,
    ) -> bool {
        todo!()
    }

    pub(crate) fn verifier_init(aux_info: &[VPAuxInfo<E>]) -> Self {
        todo!()
    }
}
