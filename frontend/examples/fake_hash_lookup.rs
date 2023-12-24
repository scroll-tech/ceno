use ff::Field;
use frontend::structs::{CellType, CircuitBuilder, TableChallenge};
use goldilocks::Goldilocks;

enum TableType {
    FakeHashTable,
}

fn main() {
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();

    let table_size = 4;
    let pow_of_xs = circuit_builder.create_cells(table_size);
    for i in 0..table_size - 1 {
        // circuit_builder.mul2(
        //     pow_of_xs[i + 1],
        //     pow_of_xs[i],
        //     pow_of_xs[i],
        //     Goldilocks::ONE,
        // );
        let tmp = circuit_builder.create_cell();
        circuit_builder.mul2(tmp, pow_of_xs[i], pow_of_xs[i], Goldilocks::ONE);
        let diff = circuit_builder.create_cell();
        circuit_builder.add(diff, pow_of_xs[i + 1], Goldilocks::ONE);
        circuit_builder.add(diff, tmp, -Goldilocks::ONE);
        circuit_builder.assert_const(diff, Goldilocks::ZERO);
    }
    circuit_builder.mark_cell(CellType::PublicInput, pow_of_xs[0]);

    let table_type = TableType::FakeHashTable as usize;
    circuit_builder.define_table_type(table_type);
    for i in 0..table_size {
        circuit_builder.add_table_item(table_type, pow_of_xs[i]);
    }

    let inputs = circuit_builder.create_cells(5);
    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    let challenge = circuit_builder.create_challenge_cell();
    circuit_builder.assign_table_challenge(table_type, TableChallenge { index: challenge });

    circuit_builder.configure();
    circuit_builder.print_info();
}
