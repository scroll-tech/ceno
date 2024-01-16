use frontend::structs::CircuitBuilder;
use goldilocks::SmallField;

use crate::structs::{CircuitGraph, CircuitGraphWitness, NodeWireOut};

impl<F: SmallField> CircuitGraph<F> {
    pub fn new_from_sources(circuit_builders: &[CircuitBuilder<F>]) -> Self {
        todo!()
    }

    pub fn add_source(&mut self, label: &'static str, circuit_builder: &CircuitBuilder<F>) {
        todo!()
    }

    pub fn add_node(
        &mut self,
        label: &'static str,
        circuit_builder: &CircuitBuilder<F>,
        predecessors: &[NodeWireOut],
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
