use ff::PrimeField;
use crate::error::UtilError;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
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
pub fn convert_decomp<E: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<E>,
    small_cells: &[CellId],
    small_cell_bit_width: usize,
    big_cell_bit_width: usize,
    is_little_endian: bool,
) -> Result<Vec<CellId>, UtilError> {
    assert!(E::BaseField::NUM_BITS >= big_cell_bit_width as u32);

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
            let shift_size = small_chunk_index * small_cell_bit_width;
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

/// Pads a `Vec<CellId>` with new cells to reach some given size n
pub fn pad_cells<E: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<E>,
    cells: &mut Vec<CellId>,
    size: usize,
) {
    if cells.len() < size {
        cells.extend(circuit_builder.create_cells(size - cells.len()))
    }
}

/// Compile time evaluated minimum function
/// returns min(a, b)
pub const fn const_min(a: usize, b: usize) -> usize {
    if a <= b {
        a
    } else {
        b
    }
}

/// Assumes each limb < max_value
/// adds 1 to the big value, while preserving the above constraint
pub fn add_one_to_big_num<F: SmallField>(limb_modulo: F, limbs: &[F]) -> Vec<F> {
    let mut should_add_one = true;
    let mut result = vec![];

    for limb in limbs {
        let mut new_limb_value = limb.clone();
        if should_add_one {
            new_limb_value += F::ONE;
            if new_limb_value == limb_modulo {
                new_limb_value = F::ZERO;
            } else {
                should_add_one = false;
            }
        }
        result.push(new_limb_value);
    }

    result
}

#[cfg(test)]
mod tests {
    use crate::uint::util::{add_one_to_big_num, const_min, convert_decomp, pad_cells};
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
        let (_, small_values) = circuit_builder.create_witness_in(9);
        let small_bit_width = 2;
        let big_bit_width = 6;
        let big_values = convert_decomp(
            &mut circuit_builder,
            &small_values,
            small_bit_width,
            big_bit_width,
            true,
        )
        .unwrap();
        assert_eq!(big_values.len(), 3);
        circuit_builder.create_witness_out_from_cells(&big_values);

        // verify construction against concrete witness values
        circuit_builder.configure();
        let circuit = Circuit::new(&circuit_builder);

        // input
        // we start with cells of bit width 2 (9 of them)
        // 11 00 10 11 01 10 01 01 11 (bit representation)
        //  3  0  2  3  1  2  1  1  3 (field representation)
        //
        // expected output
        // repacking into cells of bit width 6
        // we can only fit three 2-bit cells into a 6 bit cell
        // 100011 100111 110101 (bit representation)
        // 35     39     53     (field representation)

        let witness_values = vec![3, 0, 2, 3, 1, 2, 1, 1, 3]
            .into_iter()
            .map(|v| Goldilocks::from(v))
            .collect::<Vec<_>>();
        let circuit_witness = {
            let mut circuit_witness = CircuitWitness::new(&circuit, vec![]);
            circuit_witness.add_instance(&circuit, vec![witness_values]);
            circuit_witness
        };

        circuit_witness.check_correctness(&circuit);

        let output = circuit_witness.output_layer_witness_ref().instances[0].to_vec();

        assert_eq!(
            &output[..3],
            vec![35, 39, 53]
                .into_iter()
                .map(|v| Goldilocks::from(v))
                .collect::<Vec<_>>()
        );

        // padding to power of 2
        assert_eq!(
            &output[3..],
            vec![0]
                .into_iter()
                .map(|v| Goldilocks::from(v))
                .collect_vec()
        );
    }

    #[test]
    fn test_pad_cells() {
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();
        let (_, mut small_values) = circuit_builder.create_witness_in(3);
        // assert before padding
        assert_eq!(small_values, vec![0, 1, 2]);
        // pad
        pad_cells(&mut circuit_builder, &mut small_values, 5);
        // assert after padding
        assert_eq!(small_values, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_min_function() {
        assert_eq!(const_min(2, 3), 2);
        assert_eq!(const_min(3, 3), 3);
        assert_eq!(const_min(5, 3), 3);
    }

    #[test]
    fn test_add_one_big_num() {
        let limb_modulo = Goldilocks::from(2);

        // 000
        let initial_limbs = vec![Goldilocks::from(0); 3];

        // 100
        let updated_limbs = add_one_to_big_num(limb_modulo, &initial_limbs);
        assert_eq!(
            updated_limbs,
            vec![
                Goldilocks::from(1),
                Goldilocks::from(0),
                Goldilocks::from(0)
            ]
        );

        // 010
        let updated_limbs = add_one_to_big_num(limb_modulo, &updated_limbs);
        assert_eq!(
            updated_limbs,
            vec![
                Goldilocks::from(0),
                Goldilocks::from(1),
                Goldilocks::from(0)
            ]
        );

        // 110
        let updated_limbs = add_one_to_big_num(limb_modulo, &updated_limbs);
        assert_eq!(
            updated_limbs,
            vec![
                Goldilocks::from(1),
                Goldilocks::from(1),
                Goldilocks::from(0)
            ]
        );

        // 001
        let updated_limbs = add_one_to_big_num(limb_modulo, &updated_limbs);
        assert_eq!(
            updated_limbs,
            vec![
                Goldilocks::from(0),
                Goldilocks::from(0),
                Goldilocks::from(1)
            ]
        );

        // 101
        let updated_limbs = add_one_to_big_num(limb_modulo, &updated_limbs);
        assert_eq!(
            updated_limbs,
            vec![
                Goldilocks::from(1),
                Goldilocks::from(0),
                Goldilocks::from(1)
            ]
        );

        // 011
        let updated_limbs = add_one_to_big_num(limb_modulo, &updated_limbs);
        assert_eq!(
            updated_limbs,
            vec![
                Goldilocks::from(0),
                Goldilocks::from(1),
                Goldilocks::from(1)
            ]
        );

        // 111
        let updated_limbs = add_one_to_big_num(limb_modulo, &updated_limbs);
        assert_eq!(
            updated_limbs,
            vec![
                Goldilocks::from(1),
                Goldilocks::from(1),
                Goldilocks::from(1)
            ]
        );

        // restart cycle
        // 000
        let updated_limbs = add_one_to_big_num(limb_modulo, &updated_limbs);
        assert_eq!(
            updated_limbs,
            vec![
                Goldilocks::from(0),
                Goldilocks::from(0),
                Goldilocks::from(0)
            ]
        );
    }
}
