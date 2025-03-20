use super::{WhirDefaultSpec, spec::WhirSpec};
use ff_ext::ExtensionField;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use whir::crypto::Digest;
use whir_external::whir::verifier::WhirCommitmentInTranscript;

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct WhirCommitment<E: ExtensionField> {
    pub(crate) inner: Option<WhirCommitmentInTranscript<E>>,
    pub(crate) num_vars: usize,
}

pub fn digest_to_bytes<Spec: WhirSpec<E>, E: ExtensionField>(
    digest: &Digest<E>,
) -> Result<Vec<u8>, crate::Error> {
    bincode::serialize(digest)
        .map_err(|_| crate::Error::Serialization("Serialize digest failed".to_string()))
}

#[derive(Clone, Debug)]
pub struct Whir<E: ExtensionField, Spec: WhirSpec<E>> {
    phantom: std::marker::PhantomData<(E, Spec)>,
}

pub type WhirDefault<E> = Whir<E, WhirDefaultSpec>;
