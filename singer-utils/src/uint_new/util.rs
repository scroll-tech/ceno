use crate::error::UtilError;
use ff_ext::ExtensionField;
use simple_frontend::structs::{CellId, CircuitBuilder};

/// Given some data represented by n small cells of size s
/// this function represents the same data in m big cells of size b
/// where b >= s
/// e.g.
/// information = 1100
/// represented with 2 small cells of size 2 each
/// small -> 11 | 00
/// we can pack this into a single big cell of size 4
/// big -> 1100
fn convert_decomp<E: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<E>,
    small_cells: &[CellId],
    small_cell_bit_width: usize,
    big_cell_bit_width: usize,
    is_little_endian: bool,
) -> Result<Vec<CellId>, UtilError> {
    // TODO: technically there is a limit on the bit width (based on the field size),
    //  we should handle this edge case
    //  not sure this should (or can) be handled here tho
    if small_cell_bit_width > big_cell_bit_width {
        return Err(UtilError::UIntError(
            "cannot pack bigger width cells into smaller width cells".to_string(),
        ));
    }

    if small_cell_bit_width == big_cell_bit_width {
        return Ok(small_cells.to_vec());
    }

    // ensure the small cell values are in little endian form
    let small_cells = if !is_little_endian {
        small_cells.to_vec().into_iter().rev().collect()
    } else {
        small_cells.to_vec()
    };

    // compute the number of small cells that can fit into each big cell
    let small_cell_count_per_big_cell = big_cell_bit_width / small_cell_bit_width;

    let mut new_cell_ids = vec![];

    // iteratively take and pack n small cells into 1 big cell
    for values in small_cells.chunks(small_cell_count_per_big_cell) {
        let big_cell = circuit_builder.create_cell();
        for (small_chunk_index, small_bit_cell) in values.iter().enumerate() {
            let shift_size =
                (small_cell_count_per_big_cell - small_chunk_index - 1) * small_cell_bit_width;
            circuit_builder.add(
                big_cell,
                *small_bit_cell,
                E::BaseField::from(1 << shift_size),
            );
        }
        new_cell_ids.push(big_cell);
    }

    Ok(new_cell_ids)
}

#[cfg(test)]
mod tests {
    use crate::uint_new::util::convert_decomp;
    use gkr::structs::{Circuit, CircuitWitness};
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use simple_frontend::structs::CircuitBuilder;

    #[test]
    #[should_panic]
    fn test_pack_big_cells_into_small_cells() {
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();
        let (_, big_values) = circuit_builder.create_witness_in(5);
        let big_bit_width = 5;
        let small_bit_width = 2;
        let cell_packing_result = convert_decomp(
            &mut circuit_builder,
            &big_values,
            big_bit_width,
            small_bit_width,
            true,
        )
        .unwrap();
    }

    #[test]
    fn test_pack_same_size_cells() {
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();
        let (_, initial_values) = circuit_builder.create_witness_in(5);
        let small_bit_width = 2;
        let big_bit_width = 2;
        let new_values = convert_decomp(
            &mut circuit_builder,
            &initial_values,
            small_bit_width,
            big_bit_width,
            true,
        )
        .unwrap();
        assert_eq!(initial_values, new_values);
    }

    #[test]
    fn test_pack_small_cells_into_big_cells() {
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();
        let (witness_id, small_values) = circuit_builder.create_witness_in(9);
        let small_bit_width = 2;
        let big_bit_width = 5;
        let big_values = convert_decomp(
            &mut circuit_builder,
            &small_values,
            small_bit_width,
            big_bit_width,
            true,
        )
        .unwrap();
        assert_eq!(big_values.len(), 5);

        // verify construction against concrete witness values
        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);

        // input
        // we start with cells of bit width 2 (9 of them)
        // 11 00 10 11 01 10 01 01 11 (bit representation)
        //  3  0  2  3  1  2  1  1  3 (field representation)
        //
        // expected output
        // repacking into cells of bit width 5
        // we can only fit two 2-bit cells into a 5 bit cell
        // 1100 1011 0110 0101 1100 (bit representation)
        //   12   11    6    5   12 (field representation)

        let witness_values = vec![3, 0, 2, 3, 1, 2, 1, 1, 3]
            .into_iter()
            .map(|v| Goldilocks::from(v))
            .collect::<Vec<_>>();
        let circuit_witness = {
            let challenges = vec![GoldilocksExt2::from(2)];
            let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
            circuit_witness.add_instance(&circuit, vec![witness_values]);
            circuit_witness
        };

        circuit_witness.check_correctness(&circuit);

        let output = circuit_witness.output_layer_witness_ref().instances[0].to_vec();

        assert_eq!(
            &output[..5],
            vec![12, 11, 6, 5, 12]
                .into_iter()
                .map(|v| Goldilocks::from(v))
                .collect::<Vec<_>>()
        );

        assert_eq!(
            &output[5..],
            vec![0, 0, 0]
                .into_iter()
                .map(|v| Goldilocks::from(v))
                .collect_vec()
        );
    }
}
