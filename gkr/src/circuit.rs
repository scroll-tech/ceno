use frontend::structs::CircuitBuilder;
use goldilocks::SmallField;

use crate::structs::{Circuit, CircuitWitness, LayerWitness};

impl<F: SmallField> Circuit<F> {
    /// Generate the circuit from circuit builder.
    pub fn new(circuit_builder: &CircuitBuilder<F>) -> Self {
        todo!()
    }
}

impl<F: SmallField> CircuitWitness<F> {
    /// Generate a fresh instance for the circuit.
    pub fn new_instance(circuit: &Circuit<F>, public_input: &[F], witnesses: &[&[F]]) -> Self {
        todo!()
    }

    /// Add another instance for the circuit.
    pub fn add_instance(
        &mut self,
        circuit: &Circuit<F>,
        public_input: &[&[F]],
        witnesses: &[&[F]],
    ) {
        todo!()
    }
}
