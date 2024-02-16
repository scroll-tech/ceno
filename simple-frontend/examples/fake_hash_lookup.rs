use ff::Field;
use goldilocks::Goldilocks;
use simple_frontend::structs::{CircuitBuilder, ConstantType};

enum TableType {
    FakeHashTable,
}

fn main() {
    todo!()
    // let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
    // let one = Goldilocks::ONE;
    // let neg_one = -Goldilocks::ONE;
    // let zero = Goldilocks::ZERO;

    // let table_size = 4;
    // let pow_of_xs = {
    //     let (_, x) = circuit_builder.create_wire_in(1);
    //     let (_, other_pows_of_x) = circuit_builder.create_wire_in(table_size - 1);
    //     [x, other_pows_of_x].concat()
    // };
    // for i in 0..table_size - 1 {
    //     // circuit_builder.mul2(
    //     //     pow_of_xs[i + 1],
    //     //     pow_of_xs[i],
    //     //     pow_of_xs[i],
    //     //     Goldilocks::ONE,
    //     // );
    //     let tmp = circuit_builder.create_cell();
    //     circuit_builder.mul2(tmp, pow_of_xs[i], pow_of_xs[i], one);
    //     let diff = circuit_builder.create_cell();
    //     circuit_builder.add(diff, pow_of_xs[i + 1], one);
    //     circuit_builder.add(diff, tmp, neg_one);
    //     circuit_builder.assert_const(diff, zero);
    // }

    // let table_type = TableType::FakeHashTable as u16;
    // circuit_builder.define_table_type(table_type);
    // for i in 0..table_size {
    //     circuit_builder.add_lookup_table_item(table_type, pow_of_xs[i]);
    // }

    // let (_, inputs) = circuit_builder.create_wire_in(5);
    // inputs.iter().for_each(|input| {
    //     circuit_builder.add_lookup_input_item(table_type, *input);
    // });

    // circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

    // circuit_builder.configure();
    // #[cfg(debug_assertions)]
    // circuit_builder.print_info();
}
