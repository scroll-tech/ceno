use ff::Field;
use frontend::structs::{CircuitBuilder, ConstantType};
use goldilocks::Goldilocks;

enum TableType {
    FakeHashTable,
}

fn main() {
    let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
    let one = ConstantType::Field(Goldilocks::ONE);
    let neg_one = ConstantType::Field(-Goldilocks::ONE);

    let table_size = 4;
    let pow_of_xs = {
        let (_, x): (usize, Vec<usize>) = circuit_builder.create_wire_in(1);
        let (_, other_pows_of_x) = circuit_builder.create_wire_in(table_size - 1);
        [x, other_pows_of_x].concat()
    };
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
        circuit_builder.assert_const(diff, &Goldilocks::ZERO);
    }

    let table_type = TableType::FakeHashTable as usize;
    circuit_builder.define_table_type(table_type);
    for i in 0..table_size {
        circuit_builder.add_table_item(table_type, pow_of_xs[i]);
    }

    let (_, inputs) = circuit_builder.create_wire_in(5);
    inputs.iter().for_each(|input| {
        circuit_builder.add_input_item(table_type, *input);
    });

    circuit_builder.assign_table_challenge(table_type, ConstantType::Challenge(0));

    circuit_builder.configure();
    circuit_builder.print_info();
}
