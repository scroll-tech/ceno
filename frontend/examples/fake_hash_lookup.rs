use ff::Field;
use frontend::structs::{CellType, CircuitBuilder, ConstantType};
use goldilocks::Goldilocks;

enum TableType {
    FakeHashTable,
}

fn main() {
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
    let one = ConstantType::Field(Goldilocks::ONE);
    let neg_one = ConstantType::Field(-Goldilocks::ONE);

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
        circuit_builder.mul2(tmp, pow_of_xs[i], pow_of_xs[i], one);
        let diff = circuit_builder.create_cell();
        circuit_builder.add(diff, pow_of_xs[i + 1], one);
        circuit_builder.add(diff, tmp, neg_one);
        circuit_builder.assert_const(diff, Goldilocks::ZERO);
    }
    circuit_builder.mark_cell(CellType::WireIn(0), pow_of_xs[0]);
    circuit_builder.mark_cells(CellType::OtherInWitness(0), &pow_of_xs[1..pow_of_xs.len()]);

    let table_type = TableType::FakeHashTable as usize;
    circuit_builder.define_table_type(table_type, CellType::OtherInWitness(1));
    for i in 0..table_size {
        circuit_builder.add_table_item(table_type, pow_of_xs[i]);
    }

    let inputs = circuit_builder.create_cells(5);
    circuit_builder.mark_cells(CellType::WireIn(1), &inputs);
    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

    circuit_builder.configure();
    circuit_builder.print_info();
}
