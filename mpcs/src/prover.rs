use goldilocks::SmallField;
use multilinear_extensions::mle::ArcDenseMultilinearExtension;

use crate::structs::{Commitment, PCSProof, PCSProverState};

#[allow(unused)]
impl<F: SmallField> PCSProverState<F> {
    pub fn prove(
        polys: &[(Commitment, ArcDenseMultilinearExtension<F>)],
        eval_point: &[F],
    ) -> PCSProof<F> {
        todo!()
    }

    pub(crate) fn prover_init(
        polys: &[(Commitment, ArcDenseMultilinearExtension<F>)],
        eval_point: &[F],
    ) -> Self {
        todo!()
    }
}
