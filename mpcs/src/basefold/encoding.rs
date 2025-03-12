use ff_ext::ExtensionField;
use multilinear_extensions::mle::FieldType;

mod utils;

mod rs;
use plonky2::util::log2_strict;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
pub use rs::{RSCode, RSCodeDefaultSpec, coset_fft, fft, fft_root_table};

use serde::{Serialize, de::DeserializeOwned};
use witness::RowMajorMatrix;

use crate::{Error, util::arithmetic::interpolate2_weights};

pub trait EncodingProverParameters {
    fn get_max_message_size_log(&self) -> usize;
}

pub trait EncodingScheme<E: ExtensionField>: std::fmt::Debug + Clone {
    type PublicParameters: Clone + std::fmt::Debug + Serialize + DeserializeOwned;
    type ProverParameters: Clone
        + std::fmt::Debug
        + Serialize
        + DeserializeOwned
        + EncodingProverParameters;
    type VerifierParameters: Clone + std::fmt::Debug + Serialize + DeserializeOwned;
    type EncodedData;

    fn setup(max_msg_size_log: usize) -> Self::PublicParameters;

    fn trim(
        pp: Self::PublicParameters,
        max_msg_size_log: usize,
    ) -> Result<(Self::ProverParameters, Self::VerifierParameters), Error>;

    fn encode(pp: &Self::ProverParameters, rmm: RowMajorMatrix<E::BaseField>) -> Self::EncodedData;

    /// Encodes a message of small length, such that the verifier is also able
    /// to execute the encoding.
    fn encode_small(vp: &Self::VerifierParameters, coeffs: &FieldType<E>) -> FieldType<E>;

    fn get_number_queries() -> usize;

    fn get_rate_log() -> usize;

    fn get_basecode_msg_size_log() -> usize;

    /// Whether the message needs to be bit-reversed to allow even-odd
    /// folding. If the folding is already even-odd style (like RS code),
    /// then set this function to return false. If the folding is originally
    /// left-right, like basefold, then return true.
    fn message_is_left_and_right_folding() -> bool;

    fn message_is_even_and_odd_folding() -> bool {
        !Self::message_is_left_and_right_folding()
    }

    /// Returns three values: x0, x1 and 1/(x1-x0). Note that although
    /// 1/(x1-x0) can be computed from the other two values, we return it
    /// separately because inversion is expensive.
    /// These three values can be used to interpolate a linear function
    /// that passes through the two points (x0, y0) and (x1, y1), for the
    /// given y0 and y1, then compute the value of the linear function at
    /// any give x.
    /// Params:
    /// - level: which particular code in this family of codes?
    /// - index: position in the codeword (after folded)
    fn prover_folding_coeffs(pp: &Self::ProverParameters, level: usize, index: usize) -> (E, E, E);

    /// The same as `prover_folding_coeffs`, but for the verifier. The two
    /// functions, although provide the same functionality, may use different
    /// implementations. For example, prover can use precomputed values stored
    /// in the parameters, but the verifier may need to recompute them.
    fn verifier_folding_coeffs(
        vp: &Self::VerifierParameters,
        level: usize,
        index: usize,
    ) -> (E, E, E);

    /// TODO add docs
    fn prover_folding_coeffs_level(pp: &Self::ProverParameters, level: usize) -> &[E::BaseField];

    /// TODO add docs
    fn verifier_folding_coeffs_level(
        pp: &Self::VerifierParameters,
        level: usize,
    ) -> &[E::BaseField];
}

fn concatenate_field_types<E: ExtensionField>(coeffs: &[FieldType<E>]) -> FieldType<E> {
    match coeffs[0] {
        FieldType::Ext(_) => {
            let res = coeffs
                .iter()
                .flat_map(|x| match x {
                    FieldType::Ext(x) => x.iter().copied(),
                    _ => unreachable!(),
                })
                .collect::<Vec<_>>();
            FieldType::Ext(res)
        }
        FieldType::Base(_) => {
            let res = coeffs
                .iter()
                .flat_map(|x| match x {
                    FieldType::Base(x) => x.iter().copied(),
                    _ => unreachable!(),
                })
                .collect::<Vec<_>>();
            FieldType::Base(res)
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use ff_ext::ExtensionField;
    use multilinear_extensions::mle::FieldType;
    use rand::rngs::OsRng;

    use crate::util::plonky2_util::reverse_index_bits_in_place_field_type;

    use super::EncodingScheme;

    pub fn test_codeword_folding<E: ExtensionField, Code: EncodingScheme<E>>() {
        let num_vars = 12;

        let poly: Vec<E> = (0..(1 << num_vars)).map(|i| E::from_u64(i)).collect();
        let mut poly = FieldType::Ext(poly);

        let pp: Code::PublicParameters = Code::setup(num_vars);
        let (pp, _) = Code::trim(pp, num_vars).unwrap();
        let mut codeword = Code::encode(&pp, &poly);
        reverse_index_bits_in_place_field_type(&mut codeword);
        if Code::message_is_left_and_right_folding() {
            reverse_index_bits_in_place_field_type(&mut poly);
        }
        let challenge = E::random(&mut OsRng);
        let folded_codeword = Code::fold_bitreversed_codeword(&pp, &codeword, challenge);
        let mut folded_message = FieldType::Ext(Code::fold_message(&poly, challenge));
        if Code::message_is_left_and_right_folding() {
            // Reverse the message back before encoding if it has been
            // bit-reversed
            reverse_index_bits_in_place_field_type(&mut folded_message);
        }
        let mut encoded_folded_message = Code::encode(&pp, &folded_message);
        reverse_index_bits_in_place_field_type(&mut encoded_folded_message);
        let encoded_folded_message = match encoded_folded_message {
            FieldType::Ext(coeffs) => coeffs,
            _ => panic!("Wrong field type"),
        };
        for (i, (a, b)) in folded_codeword
            .iter()
            .zip(encoded_folded_message.iter())
            .enumerate()
        {
            assert_eq!(a, b, "Failed at index {}", i);
        }

        let mut folded_codeword = FieldType::Ext(folded_codeword);
        for round in 0..4 {
            let folded_codeword_vec =
                Code::fold_bitreversed_codeword(&pp, &folded_codeword, challenge);

            if Code::message_is_left_and_right_folding() {
                reverse_index_bits_in_place_field_type(&mut folded_message);
            }
            folded_message = FieldType::Ext(Code::fold_message(&folded_message, challenge));
            if Code::message_is_left_and_right_folding() {
                reverse_index_bits_in_place_field_type(&mut folded_message);
            }
            let mut encoded_folded_message = Code::encode(&pp, &folded_message);
            reverse_index_bits_in_place_field_type(&mut encoded_folded_message);
            let encoded_folded_message = match encoded_folded_message {
                FieldType::Ext(coeffs) => coeffs,
                _ => panic!("Wrong field type"),
            };
            for (i, (a, b)) in folded_codeword_vec
                .iter()
                .zip(encoded_folded_message.iter())
                .enumerate()
            {
                assert_eq!(a, b, "Failed at index {} in round {}", i, round);
            }
            folded_codeword = FieldType::Ext(folded_codeword_vec);
        }
    }
}
