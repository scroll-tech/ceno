use std::sync::Arc;

use goldilocks::SmallField;
use multilinear_extensions::mle::DenseMultilinearExtension;

use crate::structs::{Commitment, PCSProof, PCSProverState};

#[allow(unused)]
impl<F: SmallField> PCSProverState<F> {
    pub fn prove(
        polys: &[(Commitment, Arc<DenseMultilinearExtension<F>>)],
        eval_point: &[F],
    ) -> PCSProof<F> {
        todo!()
    }

    pub(crate) fn prover_init(
        polys: &[(Commitment, Arc<DenseMultilinearExtension<F>>)],
        eval_point: &[F],
    ) -> Self {
        todo!()
    }
}
