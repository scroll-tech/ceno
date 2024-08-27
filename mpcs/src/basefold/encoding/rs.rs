use std::marker::PhantomData;

use super::{EncodingProverParameters, EncodingScheme};
use crate::{
    util::{field_type_index_mul_base, log2_strict},
    Error,
};
use ark_std::{end_timer, start_timer};
use ff::{Field, PrimeField};
use ff_ext::ExtensionField;
use multilinear_extensions::mle::FieldType;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::util::plonky2_util::reverse_index_bits_in_place;

use crate::util::arithmetic::horner;

pub trait RSCodeSpec: std::fmt::Debug + Clone {
    fn get_number_queries() -> usize;

    fn get_rate_log() -> usize;

    fn get_basecode_msg_size_log() -> usize;
}

/// The FFT codes in this file are borrowed and adapted from Plonky2.
type FftRootTable<F> = Vec<Vec<F>>;

fn fft_root_table<F: PrimeField>(lg_n: usize) -> FftRootTable<F> {
    // bases[i] = g^2^i, for i = 0, ..., lg_n - 1
    // Note that the end of bases is g^{n/2} = -1
    let mut bases = Vec::with_capacity(lg_n);
    let mut base = F::ROOT_OF_UNITY.pow(&[(1 << (F::S - lg_n as u32)) as u64]);
    bases.push(base);
    for _ in 1..lg_n {
        base = base.square(); // base = g^2^_
        bases.push(base);
    }

    // The result table looks like this:
    // len=2: [1, g^{n/2}=-1]
    // len=2: [1, g^{n/4}]
    // len=4: [1, g^{n/8}, g^{n/4}, g^{3n/8}]
    // len=8: [1, g^{n/16}, ..., g^{7n/16}]
    // ...
    // len=n/2: [1, g, ..., g^{n/2-1}]
    // There is no need to compute the other halves of these powers, because
    // those would be simply the negations of the previous halves.
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

#[allow(unused)]
fn ifft<E: ExtensionField>(
    poly: &mut FieldType<E>,
    zero_factor: usize,
    root_table: &FftRootTable<E::BaseField>,
) {
    let n = poly.len();
    let lg_n = log2_strict(n);
    let n_inv = (E::BaseField::ONE + E::BaseField::ONE)
        .invert()
        .unwrap()
        .pow(&[lg_n as u64]);

    fft(poly, zero_factor, root_table);

    // We reverse all values except the first, and divide each by n.
    field_type_index_mul_base(poly, 0, &n_inv);
    field_type_index_mul_base(poly, n / 2, &n_inv);
    match poly {
        FieldType::Base(poly) => {
            for i in 1..(n / 2) {
                let j = n - i;
                let coeffs_i = poly[j] * n_inv;
                let coeffs_j = poly[i] * n_inv;
                poly[i] = coeffs_i;
                poly[j] = coeffs_j;
            }
        }
        FieldType::Ext(poly) => {
            for i in 1..(n / 2) {
                let j = n - i;
                let coeffs_i = poly[j] * n_inv;
                let coeffs_j = poly[i] * n_inv;
                poly[i] = coeffs_i;
                poly[j] = coeffs_j;
            }
        }
        _ => panic!("Unsupported field type"),
    }
}

/// Core FFT implementation.
fn fft_classic_inner<E: ExtensionField>(
    values: &mut FieldType<E>,
    r: usize,
    lg_n: usize,
    root_table: &[Vec<E::BaseField>],
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
        match values {
            FieldType::Base(values) => {
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
            FieldType::Ext(values) => {
                for k in (0..n).step_by(m) {
                    for j in 0..half_m {
                        let omega = omega_table[j];
                        let t = values[k + half_m + j] * omega;
                        let u = values[k + j];
                        values[k + j] = u + t;
                        values[k + half_m + j] = u - t;
                    }
                }
            }
            _ => panic!("Unsupported field type"),
        }
    }
}

/// FFT implementation based on Section 32.3 of "Introduction to
/// Algorithms" by Cormen et al.
///
/// The parameter r signifies that the first 1/2^r of the entries of
/// input may be non-zero, but the last 1 - 1/2^r entries are
/// definitely zero.
pub(crate) fn fft<E: ExtensionField>(
    values: &mut FieldType<E>,
    r: usize,
    root_table: &[Vec<E::BaseField>],
) {
    match values {
        FieldType::Base(values) => {
            reverse_index_bits_in_place(values);
        }
        FieldType::Ext(values) => {
            reverse_index_bits_in_place(values);
        }
        _ => panic!("Unsupported field type"),
    }

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
        match values {
            FieldType::Base(values) => {
                for i in 0..n {
                    values[i] = values[i & mask];
                }
            }
            FieldType::Ext(values) => {
                for i in 0..n {
                    values[i] = values[i & mask];
                }
            }
            _ => panic!("Unsupported field type"),
        }
    }

    fft_classic_inner::<E>(values, r, lg_n, root_table);
}

pub(crate) fn coset_fft<E: ExtensionField>(
    coeffs: &mut FieldType<E>,
    shift: E::BaseField,
    zero_factor: usize,
    root_table: &[Vec<E::BaseField>],
) {
    let mut shift_power = E::BaseField::ONE;
    match coeffs {
        FieldType::Base(coeffs) => {
            for coeff in coeffs.iter_mut() {
                *coeff *= shift_power;
                shift_power *= shift;
            }
        }
        FieldType::Ext(coeffs) => {
            for coeff in coeffs.iter_mut() {
                *coeff *= shift_power;
                shift_power *= shift;
            }
        }
        _ => panic!("Unsupported field type"),
    }
    fft(coeffs, zero_factor, root_table);
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

    fn get_basecode_msg_size_log() -> usize {
        7
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct RSCodeParameters<E: ExtensionField> {
    pub(crate) fft_root_table: FftRootTable<E::BaseField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct RSCodeProverParameters<E: ExtensionField> {
    pub(crate) fft_root_table: FftRootTable<E::BaseField>,
    pub(crate) gamma_powers: Vec<E::BaseField>,
    pub(crate) gamma_powers_inv_div_two: Vec<E::BaseField>,
}

impl<E: ExtensionField> EncodingProverParameters for RSCodeProverParameters<E> {
    fn get_max_message_size_log(&self) -> usize {
        self.fft_root_table.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RSCodeVerifierParameters<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    /// The verifier also needs a FFT table (much smaller)
    /// for small-size encoding. It contains the same roots as the
    /// prover's version for the first few levels (i < basecode_msg_size_log)
    /// For the other levels (i >= basecode_msg_size_log),
    /// it contains only the g^(2^i).
    pub(crate) fft_root_table: FftRootTable<E::BaseField>,
    pub(crate) full_message_size_log: usize,
    pub(crate) gamma_powers: Vec<E::BaseField>,
    pub(crate) gamma_powers_inv_div_two: Vec<E::BaseField>,
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

    type ProverParameters = RSCodeProverParameters<E>;

    type VerifierParameters = RSCodeVerifierParameters<E>;

    fn setup(max_msg_size_log: usize, _rng_seed: [u8; 32]) -> Self::PublicParameters {
        RSCodeParameters {
            fft_root_table: fft_root_table(max_msg_size_log),
        }
    }

    fn trim(
        pp: &Self::PublicParameters,
        max_msg_size_log: usize,
    ) -> Result<(Self::ProverParameters, Self::VerifierParameters), Error> {
        if pp.fft_root_table.len() < max_msg_size_log {
            return Err(Error::InvalidPcsParam(format!(
                "Public parameter is setup for a smaller message size (log={}) than the trimmed message size (log={})",
                pp.fft_root_table.len(),
                max_msg_size_log,
            )));
        }
        let mut gamma_powers = Vec::with_capacity(max_msg_size_log);
        let mut gamma_powers_inv = Vec::with_capacity(max_msg_size_log);
        gamma_powers[0] = E::BaseField::MULTIPLICATIVE_GENERATOR;
        gamma_powers_inv[0] = E::BaseField::MULTIPLICATIVE_GENERATOR.invert().unwrap();
        for i in 1..max_msg_size_log {
            gamma_powers[i] = gamma_powers[i - 1].square();
            gamma_powers_inv[i] = gamma_powers_inv[i - 1].square();
        }
        let inv_of_two = E::BaseField::from(2).invert().unwrap();
        gamma_powers_inv.iter_mut().for_each(|x| *x *= inv_of_two);
        Ok((
            Self::ProverParameters {
                fft_root_table: pp.fft_root_table[..max_msg_size_log].to_vec(),
                gamma_powers: gamma_powers.clone(),
                gamma_powers_inv_div_two: gamma_powers_inv.clone(),
            },
            Self::VerifierParameters {
                fft_root_table: pp.fft_root_table[..Spec::get_basecode_msg_size_log()]
                    .iter()
                    .map(|v| v.clone())
                    .chain(
                        pp.fft_root_table[..Spec::get_basecode_msg_size_log()]
                            .iter()
                            .map(|v| vec![v[1]]),
                    )
                    .collect(),
                full_message_size_log: max_msg_size_log,
                gamma_powers,
                gamma_powers_inv_div_two: gamma_powers_inv,
            },
        ))
    }

    fn encode(pp: &Self::ProverParameters, coeffs: &FieldType<E>) -> FieldType<E> {
        // Use the length of the FFT root table as the full message size to
        // determine the shift factor.
        Self::encode_internal(&pp.fft_root_table, coeffs)
    }

    fn encode_small(vp: &Self::VerifierParameters, coeffs: &FieldType<E>) -> FieldType<E> {
        // Use the length of the FFT root table as the full message size to
        // determine the shift factor.
        Self::encode_internal(&vp.fft_root_table, coeffs)
    }

    fn get_number_queries() -> usize {
        return Spec::get_number_queries();
    }

    fn get_rate_log() -> usize {
        return Spec::get_rate_log();
    }

    fn get_basecode_msg_size_log() -> usize {
        return Spec::get_basecode_msg_size_log();
    }

    fn prover_folding_coeffs(pp: &Self::ProverParameters, level: usize, index: usize) -> (E, E, E) {
        // level is the logarithmic of the codeword size after folded.
        // Therefore, the domain after folded is gamma^2^(full_log_n - level) H
        // where H is the multiplicative subgroup of size 2^level.
        // The element at index i in this domain is
        // gamma^2^(full_log_n - level) * ((2^level)-th root of unity)^i
        // The x0 and x1 are exactly the two square roots, i.e.,
        // x0 = gamma^2^(full_log_n - level - 1) * ((2^(level+1))-th root of unity)^i
        let x0 = pp.gamma_powers[pp.fft_root_table.len() - level - 1]
            * pp.fft_root_table[level + 1][index];
        let x1 = -x0;
        // The weight is 1/(x1-x0) = -1/(2x0)
        // = -1/2 * (gamma^{-1})^2^(full_log_n - level - 1) * ((2^(level+1))-th root of unity)^{2^(level+1)-i}
        let w = -pp.gamma_powers_inv_div_two[pp.fft_root_table.len() - level - 1]
            * pp.fft_root_table[level + 1][(1 << (level + 1)) - index];
        (E::from(x0), E::from(x1), E::from(w))
    }

    fn verifier_folding_coeffs(
        vp: &Self::VerifierParameters,
        level: usize,
        index: usize,
    ) -> (E, E, E) {
        // The same as prover_folding_coeffs, exept that the powers of
        // g is computed on the fly for levels exceeding the root table.
        let x0 = if level + 1 < Spec::get_basecode_msg_size_log() {
            vp.fft_root_table[level + 1][index]
        } else {
            // In this case, this level of fft root table of the verifier
            // only stores the first 2^(level+1)-th root of unity.
            vp.fft_root_table[level + 1][0].pow(&[index as u64])
        };
        let x1 = -x0;
        // The weight is 1/(x1-x0) = -1/(2x0)
        // = -1/2 * (gamma^{-1})^2^(full_log_n - level - 1) * ((2^(level+1))-th root of unity)^{2^(level+1)-i}
        let w = -vp.gamma_powers_inv_div_two[vp.fft_root_table.len() - level - 1]
            * if level + 1 < Spec::get_basecode_msg_size_log() {
                vp.fft_root_table[level + 1][(1 << (level + 1)) - index]
            } else {
                // In this case, this level of fft root table of the verifier
                // only stores the first 2^(level+1)-th root of unity.
                vp.fft_root_table[level + 1][0].pow(&[(1 << (level + 1)) - index as u64])
            };
        (E::from(x0), E::from(x1), E::from(w))
    }
}

impl<Spec: RSCodeSpec> RSCode<Spec> {
    fn encode_internal<E: ExtensionField>(
        fft_root_table: &FftRootTable<E::BaseField>,
        coeffs: &FieldType<E>,
    ) -> FieldType<E>
    where
        E::BaseField: Serialize + DeserializeOwned,
    {
        let lg_m = log2_strict(coeffs.len());
        let full_lg_n = fft_root_table.len();
        let fft_root_table = &fft_root_table[..lg_m];
        assert!(
            lg_m <= full_lg_n,
            "Encoded message exceeds the maximum supported message size of the table."
        );
        let rate = 1 << Spec::get_rate_log();
        let mut ret = match coeffs {
            FieldType::Base(coeffs) => {
                let mut coeffs = coeffs.clone();
                coeffs.extend(itertools::repeat_n(
                    E::BaseField::ZERO,
                    coeffs.len() * (rate - 1),
                ));
                FieldType::Base(coeffs)
            }
            FieldType::Ext(coeffs) => {
                let mut coeffs = coeffs.clone();
                coeffs.extend(itertools::repeat_n(E::ZERO, coeffs.len() * (rate - 1)));
                FieldType::Ext(coeffs)
            }
            _ => panic!("Unsupported field type"),
        };
        // Let gamma be the multiplicative generator of the base field.
        // The full domain is gamma H where H is the multiplicative subgroup
        // of size n * rate.
        // When the input message size is not n, but n/2^k, then the domain is
        // gamma^2^k H.
        let k = 1 << (fft_root_table.len() - lg_m);
        coset_fft(
            &mut ret,
            E::BaseField::MULTIPLICATIVE_GENERATOR.pow(&[k]),
            lg_m,
            fft_root_table,
        );
        ret
    }
}

#[allow(unused)]
fn naive_fft<E: ExtensionField>(poly: &Vec<E>, rate: usize, shift: E::BaseField) -> Vec<E> {
    let timer = start_timer!(|| "Encode RSCode");
    let message_size = poly.len();
    // The domain is shift * H where H is the multiplicative subgroup of size
    // message_size * rate.
    let mut domain = Vec::<E::BaseField>::with_capacity(message_size * rate);
    domain[0] = shift;
    for i in 1..message_size * rate {
        domain[i] = domain[i - 1] * shift;
    }
    let mut res = vec![E::ZERO; message_size * rate];
    res.iter_mut()
        .enumerate()
        .for_each(|(i, target)| *target = horner(&poly[..], &E::from(domain[i])));
    end_timer!(timer);

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use goldilocks::{Goldilocks, GoldilocksExt2};

    #[test]
    fn time_naive_code() {
        use rand::rngs::OsRng;

        let poly: Vec<GoldilocksExt2> = (0..(1 << 20))
            .map(|_| GoldilocksExt2::random(&mut OsRng))
            .collect();

        naive_fft::<GoldilocksExt2>(&poly, 2, Goldilocks::MULTIPLICATIVE_GENERATOR);
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
