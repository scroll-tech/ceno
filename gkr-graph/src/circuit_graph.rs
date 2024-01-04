use frontend::structs::CircuitBuilder;
use goldilocks::SmallField;
use transcript::Challenge;

use crate::structs::{CircuitGraph, CircuitGraphWitness, NodeIndex, WireInIndex, WireOutIndex};

impl<F: SmallField> CircuitGraph<F> {
    pub fn new_from_sources(circuit_builders: &[CircuitBuilder<F>]) -> Self {
        todo!()
    }

    pub fn add_node(
        &mut self,
        label: &'static str,
        circuit_builder: &CircuitBuilder<F>,
        predecessors: &[(NodeIndex, WireOutIndex)],
    ) {
        todo!()
    }

    pub fn finalize() {}
}

impl<F: SmallField> CircuitGraphWitness<F> {
    pub fn new(
        circuit_graph: &CircuitGraph<F>,
        source_wires_in: &[&[F]],
        challenges: &[F],
    ) -> Self {
        todo!()
    }
}
