use std::sync::Arc;

use frontend::structs::{CircuitBuilder, ConstantType};
use gkr::structs::Circuit;
use goldilocks::SmallField;

use super::ChipCircuitGadgets;

impl<F: SmallField> ChipCircuitGadgets<F> {
    pub fn new() -> Self {
        Self {
            frac_sum_circuit: Arc::new(Self::construct_frac_sum_circuit()),
            product_circuit: Arc::new(Self::construct_product_circuit()),
        }
    }

    fn construct_frac_sum_circuit() -> Circuit<F> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        // (den1, num1, den2, num2)
        let (_, input) = circuit_builder.create_wire_in(4);
        let output = circuit_builder.create_cells(2);
        circuit_builder.mul2(output[0], input[0], input[2], ConstantType::Field(F::ONE));
        circuit_builder.mul2(output[1], input[0], input[3], ConstantType::Field(F::ONE));
        circuit_builder.mul2(output[1], input[1], input[2], ConstantType::Field(F::ONE));
        circuit_builder.configure();
        Circuit::new(&circuit_builder)
    }

    fn construct_product_circuit() -> Circuit<F> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        // (den1, num1, den2, num2)
        let (_, input) = circuit_builder.create_wire_in(2);
        let output = circuit_builder.create_cells(1);
        circuit_builder.mul2(output[0], input[0], input[1], ConstantType::Field(F::ONE));
        circuit_builder.configure();
        Circuit::new(&circuit_builder)
    }
}
