use crate::util::{arithmetic::base_from_raw_bytes, log2_strict, num_of_bytes};
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ark_std::{end_timer, start_timer};
use ctr;
use ff::{BatchInverter, Field, PrimeField};
use ff_ext::ExtensionField;
use generic_array::GenericArray;
use multilinear_extensions::mle::FieldType;
use rayon::prelude::{ParallelIterator, ParallelSlice, ParallelSliceMut};

use itertools::Itertools;

use crate::util::plonky2_util::reverse_index_bits_in_place;
use rand_chacha::rand_core::RngCore;
use rayon::prelude::IntoParallelRefIterator;

use crate::util::arithmetic::{horner, steps};

pub fn encode_field_type_rs_basecode<E: ExtensionField>(
    poly: &FieldType<E>,
    rate: usize,
    message_size: usize,
) -> Vec<FieldType<E>> {
    match poly {
        FieldType::Ext(poly) => encode_rs_basecode(poly, rate, message_size)
            .iter()
            .map(|x| FieldType::Ext(x.clone()))
            .collect(),
        FieldType::Base(poly) => encode_rs_basecode(poly, rate, message_size)
            .iter()
            .map(|x| FieldType::Base(x.clone()))
            .collect(),
        _ => panic!("Unsupported field type"),
    }
}

// Split the input into chunks of message size, encode each message, and return the codewords
pub fn encode_rs_basecode<F: Field>(
    poly: &Vec<F>,
    rate: usize,
    message_size: usize,
) -> Vec<Vec<F>> {
    let timer = start_timer!(|| "Encode basecode");
    // The domain is just counting 1, 2, 3, ... , domain_size
    let domain: Vec<F> = steps(F::ONE).take(message_size * rate).collect();
    let res = poly
        .par_chunks_exact(message_size)
        .map(|chunk| {
            let mut target = vec![F::ZERO; message_size * rate];
            // Just Reed-Solomon code, but with the naive domain
            target
                .iter_mut()
                .enumerate()
                .for_each(|(i, target)| *target = horner(&chunk[..], &domain[i]));
            target
        })
        .collect::<Vec<Vec<F>>>();
    end_timer!(timer);

    res
}

fn concatenate_field_types<E: ExtensionField>(coeffs: &Vec<FieldType<E>>) -> FieldType<E> {
    match coeffs[0] {
        FieldType::Ext(_) => {
            let res = coeffs
                .iter()
                .map(|x| match x {
                    FieldType::Ext(x) => x.iter().map(|x| *x),
                    _ => unreachable!(),
                })
                .flatten()
                .collect::<Vec<_>>();
            FieldType::Ext(res)
        }
        FieldType::Base(_) => {
            let res = coeffs
                .iter()
                .map(|x| match x {
                    FieldType::Base(x) => x.iter().map(|x| *x),
                    _ => unreachable!(),
                })
                .flatten()
                .collect::<Vec<_>>();
            FieldType::Base(res)
        }
        _ => unreachable!(),
    }
}

// this function assumes all codewords in base_codeword has equivalent length
pub fn evaluate_over_foldable_domain_generic_basecode<E: ExtensionField>(
    base_message_length: usize,
    num_coeffs: usize,
    log_rate: usize,
    base_codewords: Vec<FieldType<E>>,
    table: &Vec<Vec<E::BaseField>>,
) -> FieldType<E> {
    let timer = start_timer!(|| "evaluate over foldable domain");
    let k = num_coeffs;
    let logk = log2_strict(k);
    let base_log_k = log2_strict(base_message_length);
    // concatenate together all base codewords
    //    let now = Instant::now();
    let mut coeffs_with_bc = concatenate_field_types(&base_codewords);
    //    println!("concatenate base codewords {:?}", now.elapsed());
    // iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let mut chunk_size = base_codewords[0].len(); // block length of the base code
    for i in base_log_k..logk {
        // In beginning of each iteration, the current codeword size is 1<<i, after this iteration,
        // every two adjacent codewords are folded into one codeword of size 1<<(i+1).
        // Fetch the table that has the same size of the *current* codeword size.
        let level = &table[i + log_rate];
        // chunk_size is equal to 1 << (i+1), i.e., the codeword size after the current iteration
        // half_chunk is equal to 1 << i, i.e. the current codeword size
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size >> 1);
        match coeffs_with_bc {
            FieldType::Ext(ref mut coeffs_with_bc) => {
                coeffs_with_bc.par_chunks_mut(chunk_size).for_each(|chunk| {
                    let half_chunk = chunk_size >> 1;
                    for j in half_chunk..chunk_size {
                        // Suppose the current codewords are (a, b)
                        // The new codeword is computed by two halves:
                        // left  = a + t * b
                        // right = a - t * b
                        let rhs = chunk[j] * E::from(level[j - half_chunk]);
                        chunk[j] = chunk[j - half_chunk] - rhs;
                        chunk[j - half_chunk] = chunk[j - half_chunk] + rhs;
                    }
                });
            }
            FieldType::Base(ref mut coeffs_with_bc) => {
                coeffs_with_bc.par_chunks_mut(chunk_size).for_each(|chunk| {
                    let half_chunk = chunk_size >> 1;
                    for j in half_chunk..chunk_size {
                        // Suppose the current codewords are (a, b)
                        // The new codeword is computed by two halves:
                        // left  = a + t * b
                        // right = a - t * b
                        let rhs = chunk[j] * level[j - half_chunk];
                        chunk[j] = chunk[j - half_chunk] - rhs;
                        chunk[j - half_chunk] = chunk[j - half_chunk] + rhs;
                    }
                });
            }
            _ => unreachable!(),
        }
    }
    end_timer!(timer);
    coeffs_with_bc
}

pub fn get_table_aes<E: ExtensionField, Rng: RngCore + Clone>(
    poly_size: usize,
    rate: usize,
    rng: &mut Rng,
) -> (
    Vec<Vec<(E::BaseField, E::BaseField)>>,
    Vec<Vec<E::BaseField>>,
) {
    // The size (logarithmic) of the codeword for the polynomial
    let lg_n: usize = rate + log2_strict(poly_size);

    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;

    let mut cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );

    // Allocate the buffer for storing n field elements (the entire codeword)
    let bytes = num_of_bytes::<E::BaseField>(1 << lg_n);
    let mut dest: Vec<u8> = vec![0u8; bytes];
    cipher.apply_keystream(&mut dest[..]);

    // Now, dest is a vector filled with random data for a field vector of size n

    // Collect the bytes into field elements
    let flat_table: Vec<E::BaseField> = dest
        .par_chunks_exact(num_of_bytes::<E::BaseField>(1))
        .map(|chunk| base_from_raw_bytes::<E>(&chunk.to_vec()))
        .collect::<Vec<_>>();

    // Now, flat_table is a field vector of size n, filled with random field elements
    assert_eq!(flat_table.len(), 1 << lg_n);

    // Multiply -2 to every element to get the weights. Now weights = { -2x }
    let mut weights: Vec<E::BaseField> = flat_table
        .par_iter()
        .map(|el| E::BaseField::ZERO - *el - *el)
        .collect();

    // Then invert all the elements. Now weights = { -1/2x }
    let mut scratch_space = vec![E::BaseField::ZERO; weights.len()];
    BatchInverter::invert_with_external_scratch(&mut weights, &mut scratch_space);

    // Zip x and -1/2x together. The result is the list { (x, -1/2x) }
    // What is this -1/2x? It is used in linear interpolation over the domain (x, -x), which
    // involves computing 1/(b-a) where b=-x and a=x, and 1/(b-a) here is exactly -1/2x
    let flat_table_w_weights = flat_table
        .iter()
        .zip(weights)
        .map(|(el, w)| (*el, w))
        .collect_vec();

    // Split the positions from 0 to n-1 into slices of sizes:
    // 2, 2, 4, 8, ..., n/2, exactly lg_n number of them
    // The weights are (x, -1/2x), the table elements are just x

    let mut unflattened_table_w_weights = vec![Vec::new(); lg_n];
    let mut unflattened_table = vec![Vec::new(); lg_n];

    let mut level_weights = flat_table_w_weights[0..2].to_vec();
    // Apply the reverse-bits permutation to a vector of size 2, equivalent to just swapping
    reverse_index_bits_in_place(&mut level_weights);
    unflattened_table_w_weights[0] = level_weights;

    unflattened_table[0] = flat_table[0..2].to_vec();
    for i in 1..lg_n {
        unflattened_table[i] = flat_table[(1 << i)..(1 << (i + 1))].to_vec();
        let mut level = flat_table_w_weights[(1 << i)..(1 << (i + 1))].to_vec();
        reverse_index_bits_in_place(&mut level);
        unflattened_table_w_weights[i] = level;
    }

    return (unflattened_table_w_weights, unflattened_table);
}

pub fn query_point<E: ExtensionField>(
    block_length: usize,
    eval_index: usize,
    level: usize,
    mut cipher: &mut ctr::Ctr32LE<aes::Aes128>,
) -> E::BaseField {
    let level_index = eval_index % (block_length);
    let mut el =
        query_root_table_from_rng_aes::<E>(level, level_index % (block_length >> 1), &mut cipher);

    if level_index >= (block_length >> 1) {
        el = -E::BaseField::ONE * el;
    }

    return el;
}

pub fn query_root_table_from_rng_aes<E: ExtensionField>(
    level: usize,
    index: usize,
    cipher: &mut ctr::Ctr32LE<aes::Aes128>,
) -> E::BaseField {
    let mut level_offset: u128 = 1;
    for lg_m in 1..=level {
        let half_m = 1 << (lg_m - 1);
        level_offset += half_m;
    }

    let pos = ((level_offset + (index as u128))
        * ((E::BaseField::NUM_BITS as usize).next_power_of_two() as u128))
        .checked_div(8)
        .unwrap();

    cipher.seek(pos);

    let bytes = (E::BaseField::NUM_BITS as usize).next_power_of_two() / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    cipher.apply_keystream(&mut dest);

    let res = base_from_raw_bytes::<E>(&dest);

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use goldilocks::GoldilocksExt2;
    use multilinear_extensions::mle::DenseMultilinearExtension;

    #[test]
    fn time_rs_code() {
        use rand::rngs::OsRng;

        let poly = DenseMultilinearExtension::random(20, &mut OsRng);

        encode_field_type_rs_basecode::<GoldilocksExt2>(&poly.evaluations, 2, 64);
    }
}
