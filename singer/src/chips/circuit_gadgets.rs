use frontend::structs::{CircuitBuilder, ConstantType, WireId};
use gkr::structs::Circuit;
use goldilocks::SmallField;

use super::ChipCircuitGadgets;

impl<F: SmallField> ChipCircuitGadgets<F> {
    pub fn new() -> Self {
        Self {
            inv_sum_circuit: Self::construct_inv_sum_circuit(),
            frac_sum_circuit: Self::construct_frac_sum_circuit(),
            product_circuit: Self::construct_product_circuit(),
        }
    }

    fn construct_inv_sum_circuit() -> Circuit<F> {
        let mut circuit_builder = CircuitBuilder::<F>::new();
        let (_, input) = circuit_builder.create_wire_in(2);
        let output = circuit_builder.create_cells(2);
        circuit_builder.mul2(output[0], input[0], input[1], ConstantType::Field(F::ONE));
        circuit_builder.add(output[1], input[0], ConstantType::Field(F::ONE));
        circuit_builder.add(output[1], input[1], ConstantType::Field(F::ONE));
        circuit_builder.configure();
        Circuit::new(&circuit_builder)
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

/// Pad a wire in with size `old_size` to the next power of two. Return the
/// number of variables.
pub(super) fn pad_with_constant_circuit<F: SmallField>(
    constant: i64,
    old_sizes: &[usize],
) -> (Circuit<F>, Vec<WireId>) {
    let mut old_size_ids = (0..old_sizes.len()).collect::<Vec<_>>();
    old_size_ids.sort_by(|i, j| old_sizes[*j].cmp(&old_sizes[*i]));

    let mut circuit_builder = CircuitBuilder::<F>::new();
    let mut wires_in_id = vec![0; old_sizes.len()];
    for old_size_id in old_size_ids {
        let old_size = old_sizes[old_size_id];
        let new_size = old_size.next_power_of_two();
        let (wire_in_id, _) = circuit_builder.create_wire_in(old_size);
        let _ = circuit_builder.create_constant_in(new_size - old_size, constant);
        wires_in_id[old_size_id] = wire_in_id;
    }
    circuit_builder.configure();
    (Circuit::new(&circuit_builder), wires_in_id)
}

/// Given a vector of wire in sizes, output a circuit converting denominators
/// to fractions, padded with zero fractions. Return wire in indices for
/// denominators.
pub(super) fn inv_pad_with_zero_frac<F: SmallField>(
    old_sizes: &[usize],
) -> (Circuit<F>, Vec<WireId>) {
    let mut old_size_ids = (0..old_sizes.len()).collect::<Vec<_>>();
    old_size_ids.sort_by(|i, j| old_sizes[*j].cmp(&old_sizes[*i]));

    let mut circuit_builder = CircuitBuilder::<F>::new();
    let mut wires_in_id = vec![0; old_sizes.len()];

    // Denominators
    for old_size_id in old_size_ids.iter() {
        let old_size = old_sizes[*old_size_id];
        let new_size = old_size.next_power_of_two();
        let (wire_in_id, _) = circuit_builder.create_wire_in(old_size);
        let _ = circuit_builder.create_constant_in(new_size - old_size, 1);
        wires_in_id[*old_size_id] = wire_in_id;
    }

    // Numerators
    for old_size_id in old_size_ids {
        let old_size = old_sizes[old_size_id];
        let new_size = old_size.next_power_of_two();
        let _ = circuit_builder.create_constant_in(old_size, 1);
        let _ = circuit_builder.create_constant_in(new_size - old_size, 0);
    }

    // TODO: to be transposed.

    circuit_builder.configure();
    (Circuit::new(&circuit_builder), wires_in_id)
}

/// Given a vector of wire in sizes, output a circuit converting denominators
/// and numerators to fractions, padded with zero fractions. Return wire in
/// indices for denominators and numerators.
pub(super) fn frac_sum_pad_with_zero_frac<F: SmallField>(
    old_sizes: &[usize],
) -> (Circuit<F>, Vec<WireId>, Vec<WireId>) {
    let mut old_size_ids = (0..old_sizes.len()).collect::<Vec<_>>();
    old_size_ids.sort_by(|i, j| old_sizes[*j].cmp(&old_sizes[*i]));

    let mut circuit_builder = CircuitBuilder::<F>::new();

    // Denominators
    let mut denominator_wires_in_id = vec![0; old_sizes.len()];
    for old_size_id in old_size_ids.iter() {
        let old_size = old_sizes[*old_size_id];
        let new_size = old_size.next_power_of_two();
        let (wire_in_id, _) = circuit_builder.create_wire_in(old_size);
        let _ = circuit_builder.create_constant_in(new_size - old_size, 1);
        denominator_wires_in_id[*old_size_id] = wire_in_id;
    }

    // Numerators
    let mut numerator_wires_in_id = vec![0; old_sizes.len()];
    for old_size_id in old_size_ids {
        let old_size = old_sizes[old_size_id];
        let new_size = old_size.next_power_of_two();
        let (wire_in_id, _) = circuit_builder.create_wire_in(old_size);
        numerator_wires_in_id[old_size_id] = wire_in_id;
        let _ = circuit_builder.create_constant_in(new_size - old_size, 0);
    }
    circuit_builder.configure();
    (
        Circuit::new(&circuit_builder),
        denominator_wires_in_id,
        numerator_wires_in_id,
    )
}
