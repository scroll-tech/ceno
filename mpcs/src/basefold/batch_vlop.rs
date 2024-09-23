use ff_ext::ExtensionField;
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;
use rand_chacha::rand_core::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use crate::Error;

use super::{
    structure::BasefoldProof, Basefold, BasefoldCommitment, BasefoldProverParams, BasefoldSpec,
    BasefoldVerifierParams,
};

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Rng: RngCore + std::fmt::Debug>
    Basefold<E, Spec, Rng>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) fn batch_open_vlop_inner(
        pp: &BasefoldProverParams<E, Spec>,
        polys: &[&[ArcMultilinearExtension<E>]],
        comms: &[super::BasefoldCommitmentWithData<E>],
        point: &[E],
        evals: &[&[E]],
        transcript: &mut Transcript<E>,
    ) -> Result<BasefoldProof<E>, Error> {
        unimplemented!();
    }

    pub(crate) fn batch_verify_vlop_inner(
        vp: &BasefoldVerifierParams<E, Spec>,
        comms: &[BasefoldCommitment<E>],
        point: &[E],
        evals: &[&[E]],
        proof: &BasefoldProof<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        unimplemented!();
    }
}
