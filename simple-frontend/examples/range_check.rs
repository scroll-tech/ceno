use goldilocks::Goldilocks;
use simple_frontend::structs::{CircuitBuilder, ConstantType};

enum TableType {
    Range8bit,
}

fn main() {
    todo!()
    // let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();

    // let (_, inputs) = circuit_builder.create_wire_in(5);

    // let table_type = TableType::Range8bit as u16;
    // circuit_builder.define_table_type(table_type);
    // for i in 0..8 as u64 {
    //     circuit_builder.add_table_item_const(table_type, &Goldilocks::from(i))
    // }

    // inputs.iter().for_each(|input| {
    //     circuit_builder.add_lookup_input_item(table_type, *input);
    // });

    // circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

    // circuit_builder.configure();
    // #[cfg(debug_assertions)]
    // circuit_builder.print_info();
}
