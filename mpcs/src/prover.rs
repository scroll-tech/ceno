use ff::FromUniformBytes;
use goldilocks::SmallField;
use multilinear_extensions::mle::DenseMultilinearExtension;

use crate::structs::{Commitment, IOPProof, IOPProverState};

#[allow(unused)]
impl<F: SmallField + FromUniformBytes<64>> IOPProverState<F> {
    pub fn prove(
        polys: &Vec<(Commitment, DenseMultilinearExtension<F>)>,
        eval_point: &Vec<F>,
    ) -> IOPProof<F> {
        todo!()
    }

    pub(crate) fn prover_init(
        polys: &Vec<(Commitment, DenseMultilinearExtension<F>)>,
        eval_point: &Vec<F>,
    ) -> Self {
        todo!()
    }
}
