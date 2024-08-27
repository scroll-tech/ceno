use ff_ext::ExtensionField;
use multilinear_extensions::mle::FieldType;

mod basecode;
pub use basecode::{Basecode, BasecodeDefaultSpec};

mod rs;
pub use rs::{RSCode, RSCodeDefaultSpec};

use serde::{de::DeserializeOwned, Serialize};

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
        + EncodingProverParameters
        + Sync;
    type VerifierParameters: Clone + std::fmt::Debug + Serialize + DeserializeOwned + Sync;

    fn setup(max_msg_size_log: usize, rng_seed: [u8; 32]) -> Self::PublicParameters;

    fn trim(
        pp: &Self::PublicParameters,
        max_msg_size_log: usize,
    ) -> Result<(Self::ProverParameters, Self::VerifierParameters), Error>;

    fn encode(pp: &Self::ProverParameters, coeffs: &FieldType<E>) -> FieldType<E>;

    /// Encodes a message of small length, such that the verifier is also able
    /// to execute the encoding.
    fn encode_small(vp: &Self::VerifierParameters, coeffs: &FieldType<E>) -> FieldType<E>;

    fn get_number_queries() -> usize;

    fn get_rate_log() -> usize;

    fn get_basecode_msg_size_log() -> usize;

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
