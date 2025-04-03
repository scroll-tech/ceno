use super::{WhirDefaultSpec, spec::WhirSpec};
use ff_ext::ExtensionField;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use whir_external::whir::verifier::WhirCommitmentInTranscript;

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct WhirCommitment<E: ExtensionField> {
    pub(crate) inner: Option<WhirCommitmentInTranscript<E>>,
    pub(crate) num_vars: usize,
}

#[derive(Clone, Serialize)]
pub struct Whir<E: ExtensionField, Spec: WhirSpec<E>> {
    phantom: std::marker::PhantomData<(E, Spec)>,
}

pub type WhirDefault<E> = Whir<E, WhirDefaultSpec>;
