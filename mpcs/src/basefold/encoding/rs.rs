use std::marker::PhantomData;

use super::{concatenate_field_types, EncodingProverParameters, EncodingScheme};
use crate::{
    util::{
        arithmetic::base_from_raw_bytes, log2_strict, num_of_bytes, plonky2_util::reverse_bits,
    },
    Error,
};
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ark_std::{end_timer, start_timer};
use ctr;
use ff::{BatchInverter, Field, PrimeField};
use ff_ext::ExtensionField;
use generic_array::GenericArray;
use multilinear_extensions::mle::FieldType;
use rand::SeedableRng;
use rayon::prelude::{ParallelIterator, ParallelSlice, ParallelSliceMut};

use itertools::Itertools;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::util::plonky2_util::reverse_index_bits_in_place;
use rand_chacha::{rand_core::RngCore, ChaCha8Rng};
use rayon::prelude::IntoParallelRefIterator;

use crate::util::arithmetic::{horner, steps};

pub trait RSCodeSpec: std::fmt::Debug + Clone {
    fn get_number_queries() -> usize;

    fn get_rate_log() -> usize;

    fn get_basecode_size_log() -> usize;
}

pub type FftRootTable<F> = Vec<Vec<F>>;

pub fn fft_root_table<F: PrimeField>(n: usize) -> FftRootTable<F> {
    let lg_n = log2_strict(n);
    // bases[i] = g^2^i, for i = 0, ..., lg_n - 1
    let mut bases = Vec::with_capacity(lg_n);
    let mut base = F::ROOT_OF_UNITY.pow(&[(1 << (F::S - lg_n as u32)) as u64]);
    bases.push(base);
    for _ in 1..lg_n {
        base = base.square(); // base = g^2^_
        bases.push(base);
    }

    let mut root_table = Vec::with_capacity(lg_n);
    for lg_m in 1..=lg_n {
        let half_m = 1 << (lg_m - 1);
        let base = bases[lg_n - lg_m];
        let mut root_row = Vec::with_capacity(half_m.max(2));
        root_row[0] = F::ONE;
        for i in 1..root_row.len() {
            root_row[i] = root_row[i - 1] * base;
        }
        root_table.push(root_row);
    }
    root_table
}

#[inline]
fn fft_dispatch<F: PrimeField>(
    input: &mut [F],
    zero_factor: Option<usize>,
    root_table: Option<&FftRootTable<F>>,
) {
    let computed_root_table = root_table.is_none().then(|| fft_root_table(input.len()));
    let used_root_table = root_table.or(computed_root_table.as_ref()).unwrap();

    fft_classic(input, zero_factor.unwrap_or(0), used_root_table);
}

#[inline]
pub fn fft<F: PrimeField>(coeffs: Vec<F>) -> Vec<F> {
    fft_with_options(coeffs, None, None)
}

#[inline]
pub fn fft_with_options<F: PrimeField>(
    poly: Vec<F>,
    zero_factor: Option<usize>,
    root_table: Option<&FftRootTable<F>>,
) -> Vec<F> {
    let mut buffer = poly;
    fft_dispatch(&mut buffer, zero_factor, root_table);
    buffer
}

#[inline]
pub fn ifft<F: PrimeField>(poly: Vec<F>) -> Vec<F> {
    ifft_with_options(poly, None, None)
}

pub fn ifft_with_options<F: PrimeField>(
    poly: Vec<F>,
    zero_factor: Option<usize>,
    root_table: Option<&FftRootTable<F>>,
) -> Vec<F> {
    let n = poly.len();
    let lg_n = log2_strict(n);
    let n_inv = (F::ONE + F::ONE).invert().unwrap().pow(&[lg_n as u64]);

    let mut buffer = poly;
    fft_dispatch(&mut buffer, zero_factor, root_table);

    // We reverse all values except the first, and divide each by n.
    buffer[0] *= n_inv;
    buffer[n / 2] *= n_inv;
    for i in 1..(n / 2) {
        let j = n - i;
        let coeffs_i = buffer[j] * n_inv;
        let coeffs_j = buffer[i] * n_inv;
        buffer[i] = coeffs_i;
        buffer[j] = coeffs_j;
    }
    buffer
}

/// Generic FFT implementation.
fn fft_classic_simd<F: Field>(
    values: &mut [F],
    r: usize,
    lg_n: usize,
    root_table: &FftRootTable<F>,
) {
    // We've already done the first lg_packed_width (if they were required) iterations.

    for lg_half_m in r..lg_n {
        let n = 1 << lg_n;
        let lg_m = lg_half_m + 1;
        let m = 1 << lg_m; // Subarray size (in field elements).
        let half_m = m / 2;
        debug_assert!(half_m != 0);

        // omega values for this iteration, as slice of vectors
        let omega_table = &root_table[lg_half_m][..];
        for k in (0..n).step_by(m) {
            for j in 0..half_m {
                let omega = omega_table[j];
                let t = omega * values[k + half_m + j];
                let u = values[k + j];
                values[k + j] = u + t;
                values[k + half_m + j] = u - t;
            }
        }
    }
}

/// FFT implementation based on Section 32.3 of "Introduction to
/// Algorithms" by Cormen et al.
///
/// The parameter r signifies that the first 1/2^r of the entries of
/// input may be non-zero, but the last 1 - 1/2^r entries are
/// definitely zero.
pub(crate) fn fft_classic<F: Field>(values: &mut [F], r: usize, root_table: &FftRootTable<F>) {
    reverse_index_bits_in_place(values);

    let n = values.len();
    let lg_n = log2_strict(n);

    if root_table.len() != lg_n {
        panic!(
            "Expected root table of length {}, but it was {}.",
            lg_n,
            root_table.len()
        );
    }

    // After reverse_index_bits, the only non-zero elements of values
    // are at indices i*2^r for i = 0..n/2^r.  The loop below copies
    // the value at i*2^r to the positions [i*2^r + 1, i*2^r + 2, ...,
    // (i+1)*2^r - 1]; i.e. it replaces the 2^r - 1 zeros following
    // element i*2^r with the value at i*2^r.  This corresponds to the
    // first r rounds of the FFT when there are 2^r zeros at the end
    // of the original input.
    if r > 0 {
        // if r == 0 then this loop is a noop.
        let mask = !((1 << r) - 1);
        for i in 0..n {
            values[i] = values[i & mask];
        }
    }

    fft_classic_simd::<F>(values, r, lg_n, root_table);
}

pub(crate) fn coset_fft_with_options<F: PrimeField>(
    coeffs: &Vec<F>,
    shift: F,
    zero_factor: Option<usize>,
    root_table: Option<&FftRootTable<F>>,
) -> Vec<F> {
    let mut modified_poly = coeffs.clone();
    let mut shift_power = F::ONE;
    for (i, coeff) in modified_poly.iter_mut().enumerate() {
        *coeff *= shift_power;
        shift_power *= shift;
    }
    fft_with_options(modified_poly, zero_factor, root_table)
}

#[derive(Debug, Clone)]
pub struct RSCodeDefaultSpec {}

impl RSCodeSpec for RSCodeDefaultSpec {
    fn get_number_queries() -> usize {
        260
    }

    fn get_rate_log() -> usize {
        3
    }

    fn get_basecode_size_log() -> usize {
        7
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct RSCodeParameters<E: ExtensionField> {
    pub(crate) table: Vec<Vec<E::BaseField>>,
    pub(crate) table_w_weights: Vec<Vec<(E::BaseField, E::BaseField)>>,
    pub(crate) rng_seed: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct RSCodeProverParameters<E: ExtensionField, Spec: RSCodeSpec> {
    pub(crate) table: Vec<Vec<E::BaseField>>,
    pub(crate) table_w_weights: Vec<Vec<(E::BaseField, E::BaseField)>>,
    pub(crate) rng_seed: [u8; 32],
    #[serde(skip)]
    _phantom: PhantomData<fn() -> Spec>,
}

impl<E: ExtensionField, Spec: RSCodeSpec> EncodingProverParameters
    for RSCodeProverParameters<E, Spec>
{
    fn get_max_message_size_log(&self) -> usize {
        self.table.len() - Spec::get_rate_log()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RSCodeVerifierParameters {
    pub(crate) rng_seed: [u8; 32],
    pub(crate) aes_key: [u8; 16],
    pub(crate) aes_iv: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct RSCode<Spec: RSCodeSpec> {
    _phantom_data: PhantomData<Spec>,
}

impl<E: ExtensionField, Spec: RSCodeSpec> EncodingScheme<E> for RSCode<Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type PublicParameters = RSCodeParameters<E>;

    type ProverParameters = RSCodeProverParameters<E, Spec>;

    type VerifierParameters = RSCodeVerifierParameters;

    fn setup(max_msg_size_log: usize, rng_seed: [u8; 32]) -> Self::PublicParameters {
        let rng = ChaCha8Rng::from_seed(rng_seed.clone());
        let (table_w_weights, table) =
            get_table_aes::<E, _>(max_msg_size_log, Spec::get_rate_log(), &mut rng.clone());
        RSCodeParameters {
            table,
            table_w_weights,
            rng_seed,
        }
    }

    fn trim(
        pp: &Self::PublicParameters,
        max_msg_size_log: usize,
    ) -> Result<(Self::ProverParameters, Self::VerifierParameters), Error> {
        if pp.table.len() < Spec::get_rate_log() + max_msg_size_log {
            return Err(Error::InvalidPcsParam(format!(
                "Public parameter is setup for a smaller message size (log={}) than the trimmed message size (log={})",
                pp.table.len() - Spec::get_rate_log(),
                max_msg_size_log,
            )));
        }
        let mut key: [u8; 16] = [0u8; 16];
        let mut iv: [u8; 16] = [0u8; 16];
        let mut rng = ChaCha8Rng::from_seed(pp.rng_seed);
        rng.set_word_pos(0);
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        Ok((
            Self::ProverParameters {
                table_w_weights: pp.table_w_weights.clone(),
                table: pp.table.clone(),
                rng_seed: pp.rng_seed.clone(),
                _phantom: PhantomData,
            },
            Self::VerifierParameters {
                rng_seed: pp.rng_seed.clone(),
                aes_key: key,
                aes_iv: iv,
            },
        ))
    }

    fn encode(pp: &Self::ProverParameters, coeffs: &FieldType<E>) -> FieldType<E> {
        // Split the input into chunks of message size, encode each message, and return the codewords
        let basecode = encode_field_type_rs_basecode(
            coeffs,
            1 << Spec::get_rate_log(),
            1 << Spec::get_basecode_size_log(),
        );

        // Apply the recursive definition of the BaseFold code to the list of base codewords,
        // and produce the final codeword
        evaluate_over_foldable_domain_generic_basecode::<E>(
            1 << Spec::get_basecode_size_log(),
            coeffs.len(),
            Spec::get_rate_log(),
            basecode,
            &pp.table,
        )
    }

    fn encode_small(coeffs: &FieldType<E>) -> FieldType<E> {
        let mut basecode =
            encode_field_type_rs_basecode(coeffs, 1 << Spec::get_rate_log(), coeffs.len());
        assert_eq!(basecode.len(), 1);
        basecode.remove(0)
    }

    fn get_number_queries() -> usize {
        return Spec::get_number_queries();
    }

    fn get_rate_log() -> usize {
        return Spec::get_rate_log();
    }

    fn get_basecode_size_log() -> usize {
        return Spec::get_basecode_size_log();
    }

    fn prover_folding_coeffs(pp: &Self::ProverParameters, level: usize, index: usize) -> (E, E, E) {
        let level = &pp.table_w_weights[level];
        (
            E::from(level[index].0),
            E::from(-level[index].0),
            E::from(level[index].1),
        )
    }

    fn verifier_folding_coeffs(
        vp: &Self::VerifierParameters,
        level: usize,
        index: usize,
    ) -> (E, E, E) {
        type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
        let mut cipher = Aes128Ctr64LE::new(
            GenericArray::from_slice(&vp.aes_key[..]),
            GenericArray::from_slice(&vp.aes_iv[..]),
        );

        let x0: E::BaseField = query_root_table_from_rng_aes::<E>(level, index, &mut cipher);
        let x1 = -x0;

        let w = (x1 - x0).invert().unwrap();

        (E::from(x0), E::from(x1), E::from(w))
    }
}

fn encode_field_type_rs_basecode<E: ExtensionField>(
    poly: &FieldType<E>,
    rate: usize,
    message_size: usize,
) -> Vec<FieldType<E>> {
    match poly {
        FieldType::Ext(poly) => get_basecode(poly, rate, message_size)
            .iter()
            .map(|x| FieldType::Ext(x.clone()))
            .collect(),
        FieldType::Base(poly) => get_basecode(poly, rate, message_size)
            .iter()
            .map(|x| FieldType::Base(x.clone()))
            .collect(),
        _ => panic!("Unsupported field type"),
    }
}

// Split the input into chunks of message size, encode each message, and return the codewords
fn get_basecode<F: Field>(poly: &Vec<F>, rate: usize, message_size: usize) -> Vec<Vec<F>> {
    let timer = start_timer!(|| "Encode RSCode");
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
    poly_size_log: usize,
    rate: usize,
    rng: &mut Rng,
) -> (
    Vec<Vec<(E::BaseField, E::BaseField)>>,
    Vec<Vec<E::BaseField>>,
) {
    // The size (logarithmic) of the codeword for the polynomial
    let lg_n: usize = rate + poly_size_log;

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

    unflattened_table_w_weights[0] = flat_table_w_weights[1..2].to_vec();
    unflattened_table[0] = flat_table[1..2].to_vec();
    for i in 1..lg_n {
        unflattened_table[i] = flat_table[(1 << i)..(1 << (i + 1))].to_vec();
        let mut level = flat_table_w_weights[(1 << i)..(1 << (i + 1))].to_vec();
        reverse_index_bits_in_place(&mut level);
        unflattened_table_w_weights[i] = level;
    }

    return (unflattened_table_w_weights, unflattened_table);
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

    let pos = ((level_offset + (reverse_bits(index, level) as u128))
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

    #[test]
    fn prover_verifier_consistency() {
        type Code = RSCode<RSCodeDefaultSpec>;
        let pp: RSCodeParameters<GoldilocksExt2> = Code::setup(10, [0; 32]);
        let (pp, vp) = Code::trim(&pp, 10).unwrap();
        for level in 0..(10 + <Code as EncodingScheme<GoldilocksExt2>>::get_rate_log()) {
            for index in 0..(1 << level) {
                assert_eq!(
                    Code::prover_folding_coeffs(&pp, level, index),
                    Code::verifier_folding_coeffs(&vp, level, index),
                    "failed for level = {}, index = {}",
                    level,
                    index
                );
            }
        }
    }
}
