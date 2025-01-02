use crate::gkr::GKRCircuit;

use super::Chip;

impl Chip {
    /// Extract information for the GKR protocol.
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
