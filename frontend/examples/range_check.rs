use frontend::structs::CircuitBuilder;
use goldilocks::Goldilocks;

enum TableType {
    Range8bit,
}

fn main() {
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();

    let inputs = circuit_builder.create_cells(5);

    let table_type = TableType::Range8bit as usize;
    circuit_builder.define_table_type(table_type);
    for i in 0..8 as u64 {
        circuit_builder.add_table_item_const(table_type, Goldilocks::from(i))
    }

    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    circuit_builder.configure();
}
