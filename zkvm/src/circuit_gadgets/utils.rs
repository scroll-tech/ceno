use frontend::structs::{CircuitBuilder, ConstantType};
use goldilocks::SmallField;

pub struct PadWithConstCircuitBuilder<F: SmallField> {
    pub circuit_builder: CircuitBuilder<F>,
    pub original_input_idx: usize,
}

impl<F: SmallField> PadWithConstCircuitBuilder<F> {
    pub fn new(constant: i64) -> Self {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (original_input_idx, _) = circuit_builder.create_wire_in(5);
        let _ = circuit_builder.create_constant_in(3, constant);
        circuit_builder.configure();
        Self {
            circuit_builder,
            original_input_idx,
        }
    }
}

pub struct InvSumCircuitBuilder<F: SmallField> {
    pub circuit_builder: CircuitBuilder<F>,
    pub input_idx: usize,
}

impl<F: SmallField> InvSumCircuitBuilder<F> {
    pub fn new() -> Self {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (input_idx, input) = circuit_builder.create_wire_in(2);
        let output = circuit_builder.create_cells(2);
        circuit_builder.mul2(output[0], input[0], input[1], ConstantType::Field(F::ONE));
        circuit_builder.add(output[1], input[0], ConstantType::Field(F::ONE));
        circuit_builder.add(output[1], input[1], ConstantType::Field(F::ONE));
        circuit_builder.configure();
        Self {
            circuit_builder,
            input_idx,
        }
    }
}
pub struct FracSumCircuitBuilder<F: SmallField> {
    pub circuit_builder: CircuitBuilder<F>,
    pub input_idx: usize,
}

impl<F: SmallField> FracSumCircuitBuilder<F> {
    pub fn new() -> Self {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        // (den1, num1, den2, num2)
        let (input_idx, input) = circuit_builder.create_wire_in(4);
        let output = circuit_builder.create_cells(2);
        circuit_builder.mul2(output[0], input[0], input[2], ConstantType::Field(F::ONE));
        circuit_builder.mul2(output[1], input[0], input[3], ConstantType::Field(F::ONE));
        circuit_builder.mul2(output[1], input[1], input[2], ConstantType::Field(F::ONE));
        circuit_builder.configure();
        Self {
            circuit_builder,
            input_idx,
        }
    }
}

pub struct ProductCircuitBuilder<F: SmallField> {
    pub circuit_builder: CircuitBuilder<F>,
    pub input_idx: usize,
}

impl<F: SmallField> ProductCircuitBuilder<F> {
    pub fn new() -> Self {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (input_idx, input) = circuit_builder.create_wire_in(2);
        let output = circuit_builder.create_cells(1);
        circuit_builder.mul2(output[0], input[0], input[1], ConstantType::Field(F::ONE));
        circuit_builder.configure();
        Self {
            circuit_builder,
            input_idx,
        }
    }
}
