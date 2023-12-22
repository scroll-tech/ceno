use std::sync::Arc;

use ff::FromUniformBytes;
use goldilocks::SmallField;
use multilinear_extensions::mle::DenseMultilinearExtension;

use crate::structs::{Commitment, PCSProof, PCSProverState};

#[allow(unused)]
impl<F: SmallField + FromUniformBytes<64>> PCSProverState<F> {
    pub fn prove(
        polys: &Vec<(Commitment, Arc<DenseMultilinearExtension<F>>)>,
        eval_point: &Vec<F>,
    ) -> PCSProof<F> {
        todo!()
    }

    pub(crate) fn prover_init(
        polys: &Vec<(Commitment, Arc<DenseMultilinearExtension<F>>)>,
        eval_point: &Vec<F>,
    ) -> Self {
        todo!()
    }
}
