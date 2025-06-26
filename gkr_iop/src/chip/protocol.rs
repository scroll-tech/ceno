use ff_ext::ExtensionField;

use crate::gkr::GKRCircuit;

use super::Chip;

impl<E: ExtensionField> Chip<E> {
    /// Extract information from Chip that required in the GKR phase.
    pub fn gkr_circuit(&self) -> GKRCircuit<E> {
        GKRCircuit {
            layers: self.layers.clone(),
            n_challenges: self.n_challenges,
            n_evaluations: self.n_evaluations,
            n_out_evals: self.n_out_evals,
        }
    }
}
