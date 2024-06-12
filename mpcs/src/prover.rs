use ff_ext::ExtensionField;
use multilinear_extensions::mle::ArcDenseMultilinearExtension;

use crate::structs::{Commitment, PCSProof, PCSProverState};

#[allow(unused)]
impl<E: ExtensionField> PCSProverState<E> {
    pub fn prove(
        polys: &[(Commitment, ArcDenseMultilinearExtension<E>)],
        eval_point: &[E],
    ) -> PCSProof<E> {
        todo!()
    }

    pub(crate) fn prover_init(
        polys: &[(Commitment, ArcDenseMultilinearExtension<E>)],
        eval_point: &[E],
    ) -> Self {
        todo!()
    }
}
