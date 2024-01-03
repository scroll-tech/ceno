use frontend::structs::CircuitBuilder;
use goldilocks::Goldilocks;

enum TableType {
    FakeHashTable,
}

fn main() {
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();

    let pow_of_xs = circuit_builder.create_cells(16);
    let one = Goldilocks::from(1u64);
    for i in 0..15 {
        circuit_builder.mul2(pow_of_xs[i + 1], pow_of_xs[i], pow_of_xs[i], one);
    }

    let table_type = TableType::FakeHashTable as usize;
    circuit_builder.define_table_type(TableType::FakeHashTable as usize);
    for i in 0..16 {
        circuit_builder.add_table_item(table_type, pow_of_xs[i]);
    }

    let inputs = circuit_builder.create_cells(5);
    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });
    circuit_builder.configure();
}
