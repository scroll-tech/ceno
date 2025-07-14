use std::marker::PhantomData;

use super::{EncodingProverParameters, EncodingScheme};
use crate::Error;
use ff_ext::{ExtensionField, FieldFrom};
use itertools::Itertools;
use p3::{
    dft::{Radix2Dit, Radix2DitParallel, TwoAdicSubgroupDft},
    field::{Field, FieldAlgebra, TwoAdicField, batch_multiplicative_inverse},
    matrix::{Matrix, bitrev::BitReversableMatrix, dense::DenseMatrix},
    util::reverse_bits_len,
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
        100
    }

    fn get_rate_log() -> usize {
        1
    }

    fn get_basecode_msg_size_log() -> usize {
        0
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
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct RSCodeVerifierParameters<E: ExtensionField> {
    #[serde(skip)]
    // pub(crate) dft: Radix2Dit<E::BaseField>,
    pub(crate) dft: Radix2Dit<E>,
    pub(crate) two_inv: E::BaseField,
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

    type EncodedData = DenseMatrix<E::BaseField>;

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
                    two_inv: E::BaseField::from_v(2).inverse(),
                    full_message_size_log: max_message_size_log,
                },
            ));
        }

        // warm up twiddles structure within dft to accelarate the first time encoding
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
                t_inv_halves: t_inv_halves_prover,
                full_message_size_log: max_message_size_log,
            },
            Self::VerifierParameters {
                dft: verifier_dft,
                two_inv: E::BaseField::from_v(2).inverse(),
                full_message_size_log: max_message_size_log,
            },
        ))
    }

    fn encode(
        pp: &Self::ProverParameters,
        rmm: RowMajorMatrix<E::BaseField>,
    ) -> Result<Self::EncodedData, Error> {
        let num_vars = rmm.num_vars();
        let num_polys = rmm.width();
        if num_vars > pp.get_max_message_size_log() {
            return Err(Error::PolynomialTooLarge(num_vars));
        }

        let m = rmm
            .into_default_padded_p3_rmm(Some(1 << Spec::get_rate_log()))
            .to_row_major_matrix();
        let codeword = pp
            .dft
            .dft_batch(m)
            // The encoding scheme always folds the codeword in left-and-right
            // manner. However to benefit from
            // - in commit phase of vector locality access
            // - in query phase the two folded positions are always opened together
            // so it will be more efficient if the folded positions are simultaneously sibling nodes in the Merkle
            // tree. Therefore, instead of left-and-right folding, we bit-reverse
            // the codeword to make the folding even-and-odd, i.e., adjacent
            // positions are folded.
            .bit_reverse_rows()
            .to_row_major_matrix()
            .values;
        // to make 2 consecutive position to be open together, we trickily "concat" 2 consecutive leafs
        // so both can be open under same row index
        let codeword = DenseMatrix::new(codeword, num_polys * 2);
        Ok(codeword)
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
            // refer to `encode` function comment for why reverse
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
            // refer to `encode` function comment for why reverse
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

    // returns 1/(2*g^bit_rev(index)) where g^(2^(level+1)) = 1
    fn verifier_folding_coeffs(
        vp: &Self::VerifierParameters,
        level: usize,
        index: usize,
    ) -> E::BaseField {
        let g_inv = E::BaseField::two_adic_generator(level + 1).inverse();
        let idx_bit_rev = reverse_bits_len(index, level);
        let g_inv_index = g_inv.exp_u64(idx_bit_rev as u64);

        g_inv_index * vp.two_inv
    }

    fn prover_folding_coeffs_level(pp: &Self::ProverParameters, level: usize) -> &[E::BaseField] {
        &pp.t_inv_halves[level]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use ff_ext::GoldilocksExt2;
    use itertools::izip;
    use p3::{
        commit::{ExtensionMmcs, Mmcs},
        goldilocks::Goldilocks,
    };

    use rand::rngs::OsRng;
    use transcript::BasicTranscript;

    use crate::{
        basefold::commit_phase::basefold_fri_round, util::merkle_tree::poseidon2_merkle_tree,
    };

    use super::*;

    type E = GoldilocksExt2;
    type F = Goldilocks;
    type Code = RSCode<RSCodeDefaultSpec>;
    use crate::BasefoldRSParams;

    #[test]
    pub fn test_message_codeword_linearity() {
        let num_vars = 10;
        let mmcs_ext = ExtensionMmcs::<F, E, _>::new(poseidon2_merkle_tree::<E>());
        let rmm: RowMajorMatrix<F> = RowMajorMatrix::rand(&mut OsRng, 1 << num_vars, 1);
        let pp = <Code as EncodingScheme<E>>::setup(num_vars);
        let (pp, vp) = Code::trim(pp, num_vars).unwrap();
        let codeword = Code::encode(&pp, rmm.clone()).expect("encode error");
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

        let mut codeword_ext = VecDeque::from(vec![codeword_ext]);
        let mut transcript = BasicTranscript::new(b"test");

        // test basefold.encode(raw_message.fold(1-r, r)) ?= codeword.fold(1-r, r)
        let mut prove_data = vec![];
        let r = E::from_canonical_u64(97);
        basefold_fri_round::<E, BasefoldRSParams>(
            &pp,
            &mut codeword_ext,
            &mut prove_data,
            &mut vec![],
            &mmcs_ext,
            r,
            false,
            &mut transcript,
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
        assert_eq!(
            &mmcs_ext.get_matrices(&prove_data[0])[0].values,
            &codeword_from_folded_rmm.values
        );
    }
}
