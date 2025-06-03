use ff_ext::ExtensionField;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{evaluation::EvalExpression, gkr::layer::Layer};

pub mod builder;
pub mod protocol;

/// Chip stores all information required in the GKR protocol, including the
/// commit phases, the GKR phase and the opening phase.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct Chip<E: ExtensionField> {
    /// The number of base inputs committed in the whole protocol.
    pub n_committed: usize,

    /// The number of challenges generated through the whole protocols
    /// (except the ones inside sumcheck protocols).
    pub n_challenges: usize,
    /// All input evaluations generated at the end of layer protocols will be stored
    /// in a vector and this is the length.
    pub n_evaluations: usize,
    /// The layers of the GKR circuit, in the order outputs-to-inputs.
    pub layers: Vec<Layer<E>>,

    /// The polynomial index and evaluation expressions of the base inputs.
    pub openings: Vec<(usize, EvalExpression<E>)>,
}
