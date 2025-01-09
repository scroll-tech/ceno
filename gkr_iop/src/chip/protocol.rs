use crate::gkr::GKRCircuit;

use super::Chip;

impl Chip {
    /// Extract information from Chip that required in the GKR phase.
    pub fn gkr_circuit(&'_ self) -> GKRCircuit<'_> {
        GKRCircuit {
            layers: &self.layers,
            n_challenges: self.n_challenges,
            n_evaluations: self.n_evaluations,
            base_openings: &self.base_openings,
            ext_openings: &self.ext_openings,
        }
    }
}
