use frontend::structs::CircuitBuilder;
use goldilocks::SmallField;

use crate::structs::{Circuit, CircuitWitness, Layer, LayerWitness, Point};

impl<F: SmallField> Circuit<F> {
    /// Generate the circuit from circuit builder.
    pub fn new(circuit_builder: &CircuitBuilder<F>) -> Self {
        todo!()
    }

    pub fn last_layer_ref(&self) -> &Layer<F> {
        todo!()
    }
}

impl<F: SmallField> Layer<F> {
    pub fn size(&self) -> usize {
        todo!()
    }

    pub fn log_size(&self) -> usize {
        todo!()
    }
}

impl<F: SmallField> CircuitWitness<F> {
    /// Initialize the structure of the circuit witness.
    pub fn new(circuit: &Circuit<F>) -> Self {
        todo!()
    }

    /// Generate a fresh instance for the circuit.
    pub fn new_instance(circuit: &Circuit<F>, public_input: &[F], witnesses: &[&[F]]) -> Self {
        todo!()
    }

    /// Add another instance for the circuit.
    pub fn add_instance(&mut self, circuit: &Circuit<F>, public_input: &[F], witnesses: &[&[F]]) {
        todo!()
    }

    pub fn last_layer_witness_ref(&self) -> &LayerWitness<F> {
        todo!()
    }

    pub fn public_input_ref(&self) -> &LayerWitness<F> {
        todo!()
    }

    pub fn witness_ref(&self) -> Vec<&LayerWitness<F>> {
        todo!()
    }
}

impl<F: SmallField> LayerWitness<F> {
    pub fn evaluate(&self, output_point: &Point<F>) -> F {
        todo!()
    }

    pub fn size(&self) -> usize {
        todo!()
    }

    pub fn log_size(&self) -> usize {
        todo!()
    }
}
