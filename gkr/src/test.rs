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
) -> (CellId, CellId) {
    // value * inv
    let value_mul_inv = circuit_builder.create_cell();
    circuit_builder.mul2(value_mul_inv, value, inv, Ext::BaseField::ONE);
    // value * inv - 1
    let value_mul_inv_minus_one = circuit_builder.create_cell();
    circuit_builder.add_const(value_mul_inv_minus_one, -Ext::BaseField::ONE);
    // value * (value * inv - 1)
    let cond1 = circuit_builder.create_cell();
    circuit_builder.mul2(cond1, value, value_mul_inv_minus_one, Ext::BaseField::ONE);
    // inv * (value * inv - 1)
    let cond2 = circuit_builder.create_cell();
    circuit_builder.mul2(cond2, inv, value_mul_inv_minus_one, Ext::BaseField::ONE);

    (cond1, cond2)
}

#[test]
fn test_gkr_circuit_IsZeroGadget_simple() {
    // build the circuit, only one cell for value and inv
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
    let (value_wire_in_id, value) = circuit_builder.create_wire_in(1);
    let (inv_wire_in_id, inv) = circuit_builder.create_wire_in(1);
    let (cond1, cond2) = IsZeroGadget(&mut circuit_builder, value[0], inv[0]);
    circuit_builder.configure();
    let circuit = Circuit::new(&circuit_builder);
    println!("{:?}", circuit);

    // assign wire in
    let n_wires_in = circuit.n_wires_in;
    let mut wires_in = vec![vec![]; n_wires_in];
    wires_in[value_wire_in_id as usize] = vec![Goldilocks::from(1)];
    wires_in[inv_wire_in_id as usize] = vec![Goldilocks::from(1)];
    let circuit_witness = {
        let challenges = vec![Goldilocks::from(2)];
        let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
        circuit_witness.add_instance(&circuit, &wires_in);
        circuit_witness
    };
    println!("{:?}", circuit_witness);
    circuit_witness.check_correctness(&circuit);

    // check the result
    let result_values = circuit_witness.last_layer_witness_ref();
    println!("{:?}", result_values[0]);
    assert_eq!(result_values[0][0], -Goldilocks::from(1));
    assert_eq!(result_values[0][1], -Goldilocks::from(1));
}

//#[test]
// IsZero Gadget for U256. Each cell holds 4 bits.
// value is decomposed into 64 cells
// assert IsZero(value) when all 64 cells are zero
//fn test_gkr_circuit_IsZeroGadget_U256() {
// we take value to be 256-bit, each cell is 4 bits
// in order multiplications not to overflow Goldiocks size
//const UINT256_4_N_OPERAND_CELLS: usize = 64;
//const BASE: usize = 1 << 4;
//let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
//let (value_wire_in_id, value) = circuit_builder.create_wire_in(UINT256_4_N_OPERAND_CELLS);
//let (inv_wire_in_id, inv) = circuit_builder.create_wire_in(UINT256_4_N_OPERAND_CELLS);

// since we split value and inv into cells,
// we create all possible value[i] * inv[j] cells
// to prevent overflow, we need i + j <= UINT256_4_N_OPERAND_CELLS
//let mut value_i_inv_j: Vec<Vec<CellId>> = vec![vec![]; UINT256_4_N_OPERAND_CELLS];
//for i in 0..UINT256_4_N_OPERAND_CELLS {
//    for j in 0..UINT256_4_N_OPERAND_CELLS-i {
//        value_i_inv_j[i].push(circuit_builder.create_cell());
//        circuit_builder.mul2(
//            value_i_inv_j[i][j],
//            value[i],
//            inv[j],
//            Goldilocks::from(1),
//        );
//    }
//}
//let value_mul_inv = circuit_builder.create_cells(UINT256_4_N_OPERAND_CELLS);
//for idx in 0..UINT256_4_N_OPERAND_CELLS {
//    circuit_builder.add(
//        value_mul_inv[idx],
//        value_i_inv_j[]
//    )
//}
//}
