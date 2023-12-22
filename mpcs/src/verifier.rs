use ff::FromUniformBytes;
use goldilocks::SmallField;
use multilinear_extensions::virtual_poly::VPAuxInfo;
use transcript::Transcript;

use crate::structs::{Commitment, PCSProof, PCSVerifierState};

#[allow(unused)]
impl<F: SmallField + FromUniformBytes<64>> PCSVerifierState<F> {
    pub fn verify(
        poly_eval_pairs: &Vec<(Commitment, VPAuxInfo<F>, F)>,
        eval_point: &Vec<F>,
        proof: &PCSProof<F>,
        transcript: &mut Transcript<F>,
    ) -> bool {
        todo!()
    }

    pub(crate) fn verifier_init(aux_info: &Vec<VPAuxInfo<F>>) -> Self {
        todo!()
    }
}
