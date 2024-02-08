use crate::structs::{Circuit, CircuitWitness};
use ff::Field;
use goldilocks::{Goldilocks, SmallField};
use simple_frontend::structs::{CellId, CircuitBuilder};

// build an IsZero Gadget
// IsZero Gadget returns 1 when value == 0, and returns 0 otherwise.
// when value != 0 check inv = value ^ {-1}: cond1 = value * (value *
// inv - 1) = 0
// when value == 0 check inv = 0: cond2 = inv ⋅ (value *
// inv - 1) = 0
// value and inv must occupy one cell and are restricted by field size
pub fn IsZeroGadget<Ext: SmallField>(
    circuit_builder: &mut CircuitBuilder<Ext>,
    value: CellId,
    inv: CellId,
) -> (CellId, CellId, CellId) {
    // value * inv
    let value_mul_inv = circuit_builder.create_cell();
    circuit_builder.mul2(value_mul_inv, value, inv, Ext::BaseField::ONE);
    // value * inv - 1
    let value_mul_inv_minus_one = value_mul_inv;
    circuit_builder.add_const(value_mul_inv_minus_one, -Ext::BaseField::ONE);
    // cond1 = value * (value * inv - 1)
    let cond1 = circuit_builder.create_cell();
    circuit_builder.mul2(cond1, value, value_mul_inv_minus_one, Ext::BaseField::ONE);
    // cond2 = inv * (value * inv - 1)
    let cond2 = circuit_builder.create_cell();
    circuit_builder.mul2(cond2, inv, value_mul_inv_minus_one, Ext::BaseField::ONE);
    // is_zero is a copy of value_mul_inv_minus_one
    let is_zero = circuit_builder.create_cell();
    circuit_builder.add(is_zero, value_mul_inv_minus_one, Ext::BaseField::ONE);

    (is_zero, cond1, cond2)
}

#[test]
fn test_gkr_circuit_IsZeroGadget_simple() {
    // build the circuit, only one cell for value and inv
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
    let (value_wire_in_id, value) = circuit_builder.create_wire_in(1);
    let (inv_wire_in_id, inv) = circuit_builder.create_wire_in(1);
    let (_is_zero, _cond1, _cond2) = IsZeroGadget(&mut circuit_builder, value[0], inv[0]);
    //let cond_wire_out_id = circuit_builder.create_wire_out_from_cells(&[cond1, cond2]);
    //let is_zero_wire_out_id = circuit_builder.create_wire_out_from_cells(&[is_zero]);
    circuit_builder.configure();
    circuit_builder.print_info();
    let circuit = Circuit::new(&circuit_builder);
    println!("circuit: {:?}", circuit);

    // assign wire in
    let n_wires_in = circuit.n_wires_in;
    let mut wires_in = vec![vec![]; n_wires_in];
    wires_in[value_wire_in_id as usize] = vec![Goldilocks::from(5)];
    wires_in[inv_wire_in_id as usize] = vec![Goldilocks::from(5).invert().unwrap()];
    let circuit_witness = {
        let challenges = vec![Goldilocks::from(2)];
        let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
        circuit_witness.add_instance(&circuit, &wires_in);
        circuit_witness
    };
    println!("circuit witness: {:?}", circuit_witness);
    circuit_witness.check_correctness(&circuit);

    // check the result
    let layers = circuit_witness.layers_ref();
    println!("layers: {:?}", layers);
    let result_values = circuit_witness.last_layer_witness_ref();
    println!("outputs: {:?}", result_values);
    // cond1 and cond2
    assert_eq!(result_values[0][0], Goldilocks::from(0));
    assert_eq!(result_values[0][1], Goldilocks::from(0));
    // is_zero
    assert_eq!(result_values[0][2], Goldilocks::from(0));
}

#[test]
fn test_gkr_circuit_IsZeroGadget_U256() {
    // IsZero for U256. Each cell holds 4 bits.
    // value is decomposed into 64 cells
    // assert IsZero(value) when all 64 cells are zero
    const UINT256_4_N_OPERAND_CELLS: usize = 64;

    // build the circuit, number of cells for value is UINT256_4_N_OPERAND_CELLS
    // inv is the inverse of each cell's value, if value = 0 then inv = 0
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
    let (value_wire_in_id, value) = circuit_builder.create_wire_in(UINT256_4_N_OPERAND_CELLS);
    let (inv_wire_in_id, inv) = circuit_builder.create_wire_in(UINT256_4_N_OPERAND_CELLS);

    // is_zero_value = prod_{value_item} (is_zero_value_item)
    let mut cond1: Vec<CellId> = vec![];
    let mut cond2: Vec<CellId> = vec![];
    let mut is_zero_prev_items = circuit_builder.create_cell();
    circuit_builder.add_const(is_zero_prev_items, Goldilocks::from(1));
    for (value_item, inv_item) in value.into_iter().zip(inv) {
        let (is_zero_item, cond1_item, cond2_item) =
            IsZeroGadget(&mut circuit_builder, value_item, inv_item);
        cond1.push(cond1_item);
        cond2.push(cond2_item);
        let is_zero = circuit_builder.create_cell();
        circuit_builder.mul2(
            is_zero,
            is_zero_prev_items,
            is_zero_item,
            Goldilocks::from(1),
        );
        is_zero_prev_items = is_zero;
    }

    circuit_builder.configure();
    circuit_builder.print_info();

    let circuit = Circuit::new(&circuit_builder);
    println!("circuit: {:?}", circuit);

    // assign wire in
    let n_wires_in = circuit.n_wires_in;
    let mut wires_in = vec![vec![]; n_wires_in];
    wires_in[value_wire_in_id as usize] = vec![Goldilocks::from(5); UINT256_4_N_OPERAND_CELLS];
    wires_in[inv_wire_in_id as usize] =
        vec![Goldilocks::from(5).invert().unwrap(); UINT256_4_N_OPERAND_CELLS];
    let circuit_witness = {
        let challenges = vec![Goldilocks::from(2)];
        let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
        circuit_witness.add_instance(&circuit, &wires_in);
        circuit_witness
    };
    println!("circuit witness: {:?}", circuit_witness);
    circuit_witness.check_correctness(&circuit);

    // check the result
    let layers = circuit_witness.layers_ref();
    println!("layers: {:?}", layers);
    let result_values = circuit_witness.last_layer_witness_ref();
    println!("outputs: {:?}", result_values);

    // is_zero
    assert_eq!(result_values[0][0], Goldilocks::from(0));

    // TODO: take cond1 and cond2 cells and check they are zero
}
