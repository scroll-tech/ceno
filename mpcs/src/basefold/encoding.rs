use ff_ext::ExtensionField;

mod rs;
use p3::field::TwoAdicField;
pub use rs::{RSCode, RSCodeDefaultSpec};

use serde::{Serialize, de::DeserializeOwned};
use witness::RowMajorMatrix;

use crate::Error;

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

    fn encode(
        pp: &Self::ProverParameters,
        rmm: RowMajorMatrix<E::BaseField>,
    ) -> Result<Self::EncodedData, Error>;

    fn encode_slow_ext<F: TwoAdicField>(
        rmm: p3::matrix::dense::RowMajorMatrix<F>,
    ) -> p3::matrix::dense::RowMajorMatrix<F>;

    /// Encodes a message in extension field, such that the verifier is also able
    /// to execute the encoding.
    fn encode_small(
        vp: &Self::VerifierParameters,
        rmm: p3::matrix::dense::RowMajorMatrix<E>,
    ) -> p3::matrix::dense::RowMajorMatrix<E>;

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
    ) -> E::BaseField;

    fn prover_folding_coeffs_level(pp: &Self::ProverParameters, level: usize) -> &[E::BaseField];
}
