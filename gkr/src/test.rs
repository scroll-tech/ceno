use crate::structs::Circuit;
use goldilocks::Goldilocks;
use simple_frontend::structs::{CellId, CircuitBuilder};

#[test]
// this test builds an IsZero Gadget
// IsZero Gadget returns `1` when `value == 0`, and returns `0` otherwise.
// when `value != 0` check `inv = value ^ {-1}`: value * (1 - value *
// inv)
// when `value == 0` check `inv = 0`: `inv ⋅ (1 - value *
// inv)`
fn test_gkr_circuit_IsZeroGadget() {
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
    let (value_wire_in_id, value) = circuit_builder.create_wire_in(1);
    let (inv_wire_in_id, inv) = circuit_builder.create_wire_in(1);
    let value_mul_inv = circuit_builder.create_cell();
    circuit_builder.mul2(value_mul_inv, value[0], inv[0], Goldilocks::from(1));
    let cond1 = circuit_builder.create_cell();
    circuit_builder.mul2(cond1, value[0], value_mul_inv, Goldilocks::from(1));
    circuit_builder.mul2(cond1, value[0], value_mul_inv, Goldilocks::from(1));
    circuit_builder.configure();
    let circuit = Circuit::new(&circuit_builder);
    println!("{:?}", circuit);

    // TODO: we take value to be 256-bit, each cell is 4 bit
    //       in order multiplications not to overflow Goldiocks size
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
}
