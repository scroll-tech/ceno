use frontend::structs::CircuitBuilder;
use goldilocks::Goldilocks;

fn main() {
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();

    let inputs = circuit_builder.create_cells(5);

    let table_type = circuit_builder.define_table_type("8-bit-range-check");
    for i in 0..8 as u64 {
        circuit_builder.add_table_item_const(table_type, Goldilocks::from(i))
    }

    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    circuit_builder.synthesize();
}
