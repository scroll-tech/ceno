use frontend::structs::{CellType, CircuitBuilder, ConstantType};
use goldilocks::Goldilocks;

enum TableType {
    Range8bit,
}

fn main() {
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();

    let inputs = circuit_builder.create_cells(5);
    circuit_builder.mark_cells(CellType::WireIn(0), &inputs);

    let table_type = TableType::Range8bit as usize;
    circuit_builder.define_table_type(table_type, CellType::OtherInWitness(0));
    for i in 0..8 as u64 {
        circuit_builder.add_table_item_const(table_type, Goldilocks::from(i))
    }

    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

    circuit_builder.configure();
    circuit_builder.print_info();
}
