use goldilocks::SmallField;
use multilinear_extensions::virtual_poly::VPAuxInfo;
use transcript::Transcript;

use crate::structs::{Commitment, PCSProof, PCSVerifierState};

#[allow(unused)]
impl<F: SmallField> PCSVerifierState<F> {
    pub fn verify(
        poly_eval_pairs: &[(Commitment, VPAuxInfo<F>, F)],
        eval_point: &[F],
        proof: &PCSProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool {
        todo!()
    }

    pub(crate) fn verifier_init(aux_info: &[VPAuxInfo<F>]) -> Self {
        todo!()
    }
}
