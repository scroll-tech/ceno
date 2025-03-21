use std::marker::PhantomData;

use super::{EncodingProverParameters, EncodingScheme};
use crate::{Error, basefold::PolyEvalsCodeword};
use ff_ext::ExtensionField;
use itertools::Itertools;
use p3::{
    dft::{Radix2Dit, Radix2DitParallel, TwoAdicSubgroupDft},
    field::{PrimeCharacteristicRing, TwoAdicField, batch_multiplicative_inverse},
    matrix::{Matrix, bitrev::BitReversableMatrix, dense::DenseMatrix},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use witness::RowMajorMatrix;

pub trait RSCodeSpec: std::fmt::Debug + Clone {
    fn get_number_queries() -> usize;

    fn get_rate_log() -> usize;

    fn get_basecode_msg_size_log() -> usize;
}

#[derive(Debug, Clone)]
pub struct RSCodeDefaultSpec {}

impl RSCodeSpec for RSCodeDefaultSpec {
    // According to Theorem 1 of paper <BaseFold in the List Decoding Regime>
    // (https://eprint.iacr.org/2024/1571), the soundness error is bounded by
    // $O(1/|F|) + (\sqrt{\rho}+\epsilon)^s$
    // where $s$ is the query complexity and $\epsilon$ is a small value
    // that can be ignored. So the number of queries can be estimated by
    // $$
    // \frac{2\lambda}{-\log\rho}
    // $$
    // If we take $\lambda=100$ and $\rho=1/2$, then the number of queries is $200$.
    fn get_number_queries() -> usize {
        200
    }

    fn get_rate_log() -> usize {
        1
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
    phantom: PhantomData<E>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct RSCodeProverParameters<E: ExtensionField> {
    #[serde(skip)]
    pub(crate) dft: Radix2DitParallel<E::BaseField>,
    pub(crate) t_inv_halves: Vec<Vec<E::BaseField>>,
    pub(crate) full_message_size_log: usize,
}

impl<E: ExtensionField> EncodingProverParameters for RSCodeProverParameters<E> {
    fn get_max_message_size_log(&self) -> usize {
        self.full_message_size_log
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RSCodeVerifierParameters<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    #[serde(skip)]
    // pub(crate) dft: Radix2Dit<E::BaseField>,
    pub(crate) dft: Radix2Dit<E>,
    pub(crate) t_inv_halves: Vec<Vec<E::BaseField>>,
    pub(crate) full_message_size_log: usize,
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

    type EncodedData = PolyEvalsCodeword<E>;

    fn setup(_max_message_size_log: usize) -> Self::PublicParameters {
        RSCodeParameters {
            phantom: PhantomData,
        }
    }

    fn trim(
        _pp: Self::PublicParameters,
        max_message_size_log: usize,
    ) -> Result<(Self::ProverParameters, Self::VerifierParameters), Error> {
        if max_message_size_log < Spec::get_basecode_msg_size_log() {
            // Message smaller than this size will not be encoded in BaseFold.
            // So just give trivial parameters.
            return Ok((
                Self::ProverParameters {
                    dft: Default::default(),
                    t_inv_halves: Default::default(),
                    full_message_size_log: max_message_size_log,
                },
                Self::VerifierParameters {
                    dft: Default::default(),
                    t_inv_halves: Default::default(),
                    full_message_size_log: max_message_size_log,
                },
            ));
        }

        // initialize twiddles in dft to accelarate the process
        let prover_dft: Radix2DitParallel<E::BaseField> = Default::default();
        (0..max_message_size_log + Spec::get_rate_log()).for_each(|n| {
            prover_dft.dft_batch(p3::matrix::dense::DenseMatrix::new_col(
                vec![E::BaseField::ZERO; 1 << (n + 1)],
            ));
        });
        let verifier_dft: Radix2Dit<E> = Default::default();
        (Spec::get_basecode_msg_size_log()
            ..Spec::get_basecode_msg_size_log() + Spec::get_rate_log())
            .for_each(|n| {
                verifier_dft.dft_batch(p3::matrix::dense::DenseMatrix::new_col(vec![
                    E::ZERO;
                    1 << (n + 1)
                ]));
            });

        // directly return bit reverse format, matching with codeword index
        let t_inv_halves_prover = (0..max_message_size_log + Spec::get_rate_log())
            .map(|i| {
                if i < Spec::get_basecode_msg_size_log() {
                    vec![]
                } else {
                    let t_i = E::BaseField::two_adic_generator(i + 1)
                        .powers()
                        .take(1 << i)
                        .collect_vec();
                    p3::matrix::dense::RowMajorMatrix::new(
                        batch_multiplicative_inverse(
                            &t_i.iter().map(E::BaseField::double).collect_vec(),
                        ),
                        1,
                    )
                    .bit_reverse_rows()
                    .to_row_major_matrix()
                    .values
                }
            })
            .collect_vec();

        Ok((
            Self::ProverParameters {
                dft: prover_dft,
                t_inv_halves: t_inv_halves_prover.clone(),
                full_message_size_log: max_message_size_log,
            },
            Self::VerifierParameters {
                dft: verifier_dft,
                // TODO make verifier calculate fft root by itself
                t_inv_halves: t_inv_halves_prover,
                full_message_size_log: max_message_size_log,
            },
        ))
    }

    fn encode(pp: &Self::ProverParameters, rmm: RowMajorMatrix<E::BaseField>) -> Self::EncodedData {
        // bh_evals is just a copy of poly.evals().
        // Note that this function implicitly assumes that the size of poly.evals() is a
        // power of two. Otherwise, the function crashes with index out of bound.
        let num_vars = rmm.num_vars();
        let num_polys = rmm.width();
        if num_vars > pp.get_max_message_size_log() {
            return PolyEvalsCodeword::TooBig(num_vars);
        }

        // In this case, the polynomial is so small that the opening is trivial.
        // So we just build the Merkle tree over the polynomial evaluations.
        // No codeword is needed.
        if num_vars <= Spec::get_basecode_msg_size_log() {
            return PolyEvalsCodeword::TooSmall(Box::new(rmm.into_default_padded_p3_rmm()));
        }

        // here 2 resize happend. first is padding to next pow2 height, second is pa
        let mut m = rmm.into_default_padded_p3_rmm().to_row_major_matrix();
        m.pad_to_height(m.height() * (1 << Spec::get_rate_log()), E::BaseField::ZERO);
        let codeword = pp
            .dft
            .dft_batch(m)
            // The encoding scheme always folds the codeword in left-and-right
            // manner. However, in query phase the two folded positions are
            // always opened together, so it will be more efficient if the
            // folded positions are simultaneously sibling nodes in the Merkle
            // tree. Therefore, instead of left-and-right folding, we bit-reverse
            // the codeword to make the folding even-and-odd, i.e., adjacent
            // positions are folded.
            .bit_reverse_rows()
            .to_row_major_matrix()
            .values;
        // to make 2 consecutive position to be open together, we need "concat" 2 consecutive leafs
        // so both can be open under same row index
        let codeword = DenseMatrix::new(codeword, num_polys * 2);

        PolyEvalsCodeword::Normal(Box::new(codeword))
    }

    fn encode_small(
        vp: &Self::VerifierParameters,
        rmm: p3::matrix::dense::RowMajorMatrix<E>,
    ) -> p3::matrix::dense::RowMajorMatrix<E> {
        debug_assert!(rmm.height().is_power_of_two());
        let mut m = rmm.to_row_major_matrix();
        m.pad_to_height(m.height() * (1 << Spec::get_rate_log()), E::ZERO);
        vp.dft
            .dft_batch(m)
            // The encoding scheme always folds the codeword in left-and-right
            // manner. However, in query phase the two folded positions are
            // always opened together, so it will be more efficient if the
            // folded positions are simultaneously sibling nodes in the Merkle
            // tree. Therefore, instead of left-and-right folding, we bit-reverse
            // the codeword to make the folding even-and-odd, i.e., adjacent
            // positions are folded.
            .bit_reverse_rows()
            .to_row_major_matrix()
    }

    // slow due to initialized dft object
    fn encode_slow_ext<F: TwoAdicField>(
        rmm: p3::matrix::dense::RowMajorMatrix<F>,
    ) -> p3::matrix::dense::RowMajorMatrix<F> {
        let dft = Radix2Dit::<F>::default();
        debug_assert!(rmm.height().is_power_of_two());
        let mut m = rmm.to_row_major_matrix();
        m.pad_to_height(m.height() * (1 << Spec::get_rate_log()), F::ZERO);
        dft.dft_batch(m)
            // The encoding scheme always folds the codeword in left-and-right
            // manner. However, in query phase the two folded positions are
            // always opened together, so it will be more efficient if the
            // folded positions are simultaneously sibling nodes in the Merkle
            // tree. Therefore, instead of left-and-right folding, we bit-reverse
            // the codeword to make the folding even-and-odd, i.e., adjacent
            // positions are folded.
            .bit_reverse_rows()
            .to_row_major_matrix()
    }

    fn get_number_queries() -> usize {
        Spec::get_number_queries()
    }

    fn get_rate_log() -> usize {
        Spec::get_rate_log()
    }

    fn get_basecode_msg_size_log() -> usize {
        Spec::get_basecode_msg_size_log()
    }

    fn message_is_left_and_right_folding() -> bool {
        false
    }

    fn prover_folding_coeffs(
        _pp: &Self::ProverParameters,
        _level: usize,
        _index: usize,
    ) -> (E, E, E) {
        unimplemented!()
    }

    fn verifier_folding_coeffs(
        _vp: &Self::VerifierParameters,
        _level: usize,
        _index: usize,
    ) -> (E, E, E) {
        unimplemented!()
    }

    fn prover_folding_coeffs_level(pp: &Self::ProverParameters, level: usize) -> &[E::BaseField] {
        &pp.t_inv_halves[level]
    }

    fn verifier_folding_coeffs_level(
        pp: &Self::VerifierParameters,
        level: usize,
    ) -> &[E::BaseField] {
        &pp.t_inv_halves[level]
    }
}

#[cfg(test)]
mod tests {
    use ff_ext::GoldilocksExt2;
    use itertools::izip;
    use p3::{goldilocks::Goldilocks, util::log2_strict_usize};

    use rand::rngs::OsRng;

    use crate::basefold::commit_phase::basefold_one_round_by_interpolation_weights;

    use super::*;

    type E = GoldilocksExt2;
    type F = Goldilocks;
    type Code = RSCode<RSCodeDefaultSpec>;
    use crate::BasefoldRSParams;

    #[test]
    pub fn test_message_codeword_linearity() {
        let num_vars = 10;
        let rmm: RowMajorMatrix<F> = RowMajorMatrix::rand(&mut OsRng, 1 << num_vars, 1);
        let pp = <Code as EncodingScheme<E>>::setup(num_vars);
        let (pp, vp) = Code::trim(pp, num_vars).unwrap();
        let codeword = Code::encode(&pp, rmm.clone());
        let codeword = match codeword {
            PolyEvalsCodeword::Normal(dense_matrix) => dense_matrix,
            PolyEvalsCodeword::TooSmall(_) => todo!(),
            PolyEvalsCodeword::TooBig(_) => todo!(),
        };
        assert_eq!(
            codeword.values.len(),
            1 << (num_vars + <Code as EncodingScheme<E>>::get_rate_log())
        );

        let rmm_ext = p3::matrix::dense::RowMajorMatrix::new(
            rmm.values.iter().map(|v| E::from(*v)).collect(),
            1,
        );
        // test encode small api
        let codeword_ext = Code::encode_small(&vp, rmm_ext);
        assert!(
            izip!(&codeword.values, &codeword_ext.values).all(|(base, ext)| E::from(*base) == *ext)
        );

        // test basefold.encode(raw_message.fold(1-r, r)) ?= codeword.fold(1-r, r)
        let r = E::from_u64(97);
        let folded_codeword = basefold_one_round_by_interpolation_weights::<E, BasefoldRSParams>(
            &pp,
            log2_strict_usize(codeword_ext.values.len()) - 1,
            &codeword_ext.values,
            r,
        );

        // encoded folded raw message
        let codeword_from_folded_rmm = Code::encode_small(
            &vp,
            p3::matrix::dense::DenseMatrix::new(
                rmm.values
                    .chunks(2)
                    .map(|ch| r * (ch[1] - ch[0]) + ch[0])
                    .collect_vec(),
                1,
            ),
        );
        assert_eq!(&folded_codeword.values, &codeword_from_folded_rmm.values);
    }
}
