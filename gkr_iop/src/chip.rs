use ff_ext::ExtensionField;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::gkr::layer::Layer;

pub mod builder;
pub mod protocol;

/// Chip stores all information required in the GKR protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct Chip<E: ExtensionField> {
    /// The number of fixed inputs committed in the whole protocol.
    pub n_fixed: usize,
    /// The number of base inputs committed in the whole protocol.
    pub n_committed: usize,

    /// The number of challenges generated through the whole protocols
    /// (except the ones inside sumcheck protocols).
    pub n_challenges: usize,
    /// All input evaluations generated at the end of layer protocols will be stored
    /// in a vector and this is the length.
    pub n_evaluations: usize,

    /// The number of output evaluations generated at the end of the protocol.
    pub n_nonzero_out_evals: usize,

    /// The layers of the GKR circuit, in the order outputs-to-inputs.
    pub layers: Vec<Layer<E>>,
    /// The output of the circuit.
    pub final_out_evals: Vec<usize>,
}
