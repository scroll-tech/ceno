use std::sync::Arc;

use gkr::structs::{Circuit, CircuitWitness};
use goldilocks::SmallField;
use simple_frontend::structs::CircuitBuilder;

use crate::{
    error::GKRGraphError,
    structs::{CircuitGraph, CircuitGraphBuilder, CircuitGraphWitness, PredType},
};

impl<F: SmallField> CircuitGraphBuilder<F> {
    pub fn new() -> Self {
        todo!()
    }

    /// Add a new node indicating the predecessors. Return the index of the new
    /// node.
    pub fn add_node_with_witness(
        &mut self,
        label: &'static str,
        circuit: &Arc<CircuitBuilder<F>>,
        preds: Vec<PredType>,
        challenges: Vec<F>,
        sources: Vec<Vec<F>>,
    ) -> Result<usize, GKRGraphError> {
        todo!()
    }

    /// Collect the information of `self.sources` and `self.targets`.
    pub fn finalize(&mut self) -> (CircuitGraph<F>, CircuitGraphWitness<F>) {
        todo!()
    }
}
