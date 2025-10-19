use crate::{circuit_builder::CircuitBuilder, gkr::layer::Layer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

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

    /// The layers of the GKR circuit, in the order outputs-to-inputs.
    pub layers: Vec<Layer<E>>,
    /// The output of the circuit.
    pub final_out_evals: Vec<usize>,
}

impl<E: ExtensionField> Chip<E> {
    pub fn new_from_cb(cb: &CircuitBuilder<E>, n_challenges: usize) -> Chip<E> {
        Self {
            n_fixed: cb.cs.num_fixed,
            n_committed: cb.cs.num_witin as usize,
            n_challenges,
            n_evaluations: cb.cs.w_expressions.len()
                + cb.cs.r_expressions.len()
                + cb.cs.lk_expressions.len()
                + cb.cs.w_table_expressions.len()
                + cb.cs.r_table_expressions.len()
                + cb.cs.lk_table_expressions.len() * 2
                + cb.cs.num_fixed
                + cb.cs.num_witin as usize,
            final_out_evals: (0..cb.cs.w_expressions.len()
                + cb.cs.r_expressions.len()
                + cb.cs.lk_expressions.len()
                + cb.cs.w_table_expressions.len()
                + cb.cs.r_table_expressions.len()
                + cb.cs.lk_table_expressions.len() * 2)
                .collect_vec(),
            layers: vec![],
        }
    }
}
