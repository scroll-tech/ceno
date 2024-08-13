use crate::{
    sum_check::{
        classic::{ClassicSumCheck, CoefficientsProver},
        eq_xy_eval, SumCheck as _, VirtualPolynomial,
    },
    util::{
        add_polynomial_with_coeff,
        arithmetic::{horner, inner_product, inner_product_three, steps},
        base_to_usize,
        expression::{Expression, Query, Rotation},
        ext_to_usize, field_type_index_ext, field_type_iter_ext,
        hash::{new_hasher, Digest, Hasher},
        log2_strict,
        merkle_tree::{MerklePathWithoutLeafOrRoot, MerkleTree},
        multiply_poly, num_of_bytes,
        plonky2_util::reverse_index_bits_in_place_field_type,
        poly_index_ext, poly_iter_ext,
        transcript::{TranscriptRead, TranscriptWrite},
        u32_to_field,
    },
    validate_input, Error, Evaluation, NoninteractivePCS, PolynomialCommitmentScheme,
};
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ark_std::{end_timer, start_timer};
use core::{fmt::Debug, panic};
use ctr;
use ff::{BatchInverter, Field, PrimeField};
use ff_ext::ExtensionField;
use generic_array::GenericArray;
use std::{borrow::BorrowMut, ops::Deref, time::Instant};

use itertools::Itertools;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use multilinear_extensions::{
    mle::{DenseMultilinearExtension, FieldType},
    virtual_poly::build_eq_x_r_vec,
};

use crate::util::plonky2_util::{reverse_bits, reverse_index_bits_in_place};
use rand_chacha::{rand_core::RngCore, ChaCha8Rng};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice, ParallelSliceMut,
};
use std::{borrow::Cow, marker::PhantomData, slice};
type SumCheck<F> = ClassicSumCheck<CoefficientsProver<F>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldParams<E: ExtensionField, Rng: RngCore>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    log_rate: usize,
    num_verifier_queries: usize,
    max_num_vars: usize,
    table_w_weights: Vec<Vec<(E::BaseField, E::BaseField)>>,
    table: Vec<Vec<E::BaseField>>,
    rng: Rng,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldProverParams<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    log_rate: usize,
    table_w_weights: Vec<Vec<(E::BaseField, E::BaseField)>>,
    table: Vec<Vec<E::BaseField>>,
    num_verifier_queries: usize,
    max_num_vars: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldVerifierParams<Rng: RngCore> {
    rng: Rng,
    max_num_vars: usize,
    log_rate: usize,
    num_verifier_queries: usize,
}

/// A polynomial commitment together with all the data (e.g., the codeword, and Merkle tree)
/// used to generate this commitment and for assistant in opening
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E: Serialize, E::BaseField: Serialize",
    deserialize = "E: DeserializeOwned, E::BaseField: DeserializeOwned",
))]
pub struct BasefoldCommitmentWithData<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    codeword_tree: MerkleTree<E>,
    bh_evals: FieldType<E>,
    num_vars: usize,
    is_base: bool,
}

impl<E: ExtensionField> BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn to_commitment(&self) -> BasefoldCommitment<E> {
        BasefoldCommitment::new(self.codeword_tree.root(), self.num_vars, self.is_base)
    }

    pub fn get_root_ref(&self) -> &Digest<E::BaseField> {
        self.codeword_tree.root_ref()
    }

    pub fn get_root_as(&self) -> Digest<E::BaseField> {
        Digest::<E::BaseField>(self.get_root_ref().0)
    }

    pub fn get_codeword(&self) -> &FieldType<E> {
        self.codeword_tree.leaves()
    }

    pub fn codeword_size(&self) -> usize {
        self.codeword_tree.size()
    }

    pub fn codeword_size_log(&self) -> usize {
        self.codeword_tree.height()
    }

    pub fn poly_size(&self) -> usize {
        self.bh_evals.len()
    }

    pub fn get_codeword_entry_base(&self, index: usize) -> E::BaseField {
        self.codeword_tree.get_leaf_as_base(index)
    }

    pub fn get_codeword_entry_ext(&self, index: usize) -> E {
        self.codeword_tree.get_leaf_as_extension(index)
    }

    pub fn is_base(&self) -> bool {
        self.is_base
    }
}

impl<E: ExtensionField> Into<Digest<E::BaseField>> for BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn into(self) -> Digest<E::BaseField> {
        self.get_root_as()
    }
}

impl<E: ExtensionField> Into<BasefoldCommitment<E>> for &BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn into(self) -> BasefoldCommitment<E> {
        self.to_commitment()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct BasefoldCommitment<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    root: Digest<E::BaseField>,
    num_vars: Option<usize>,
    is_base: bool,
}

impl<E: ExtensionField> BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn new(root: Digest<E::BaseField>, num_vars: usize, is_base: bool) -> Self {
        Self {
            root,
            num_vars: Some(num_vars),
            is_base,
        }
    }

    pub fn root(&self) -> Digest<E::BaseField> {
        self.root.clone()
    }

    pub fn num_vars(&self) -> Option<usize> {
        self.num_vars
    }

    pub fn is_base(&self) -> bool {
        self.is_base
    }

    pub fn as_challenge_field(&self) -> BasefoldCommitment<E> {
        BasefoldCommitment::<E> {
            root: Digest::<E::BaseField>(self.root().0),
            num_vars: self.num_vars,
            is_base: self.is_base,
        }
    }
}

impl<E: ExtensionField> PartialEq for BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn eq(&self, other: &Self) -> bool {
        self.get_codeword().eq(other.get_codeword()) && self.bh_evals.eq(&other.bh_evals)
    }
}

impl<E: ExtensionField> Eq for BasefoldCommitmentWithData<E> where
    E::BaseField: Serialize + DeserializeOwned
{
}

pub trait BasefoldExtParams: Debug {
    fn get_reps() -> usize;

    fn get_rate() -> usize;

    fn get_basecode() -> usize;
}

#[derive(Debug)]
pub struct BasefoldDefaultParams;

impl BasefoldExtParams for BasefoldDefaultParams {
    fn get_reps() -> usize {
        return 260;
    }

    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode() -> usize {
        return 7;
    }
}

#[derive(Debug)]
pub struct Basefold<E: ExtensionField, V: BasefoldExtParams>(PhantomData<(E, V)>);

pub type BasefoldDefault<F> = Basefold<F, BasefoldDefaultParams>;

impl<E: ExtensionField, V: BasefoldExtParams> Clone for Basefold<E, V> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<E: ExtensionField> AsRef<[Digest<E::BaseField>]> for BasefoldCommitment<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn as_ref(&self) -> &[Digest<E::BaseField>] {
        let root = &self.root;
        slice::from_ref(root)
    }
}

impl<E: ExtensionField> AsRef<[Digest<E::BaseField>]> for BasefoldCommitmentWithData<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn as_ref(&self) -> &[Digest<E::BaseField>] {
        let root = self.get_root_ref();
        slice::from_ref(root)
    }
}

impl<E: ExtensionField, V: BasefoldExtParams> PolynomialCommitmentScheme<E> for Basefold<E, V>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    type Param = BasefoldParams<E, ChaCha8Rng>;
    type ProverParam = BasefoldProverParams<E>;
    type VerifierParam = BasefoldVerifierParams<ChaCha8Rng>;
    type CommitmentWithData = BasefoldCommitmentWithData<E>;
    type Commitment = BasefoldCommitment<E>;
    type CommitmentChunk = Digest<E::BaseField>;
    type Rng = ChaCha8Rng;

    fn setup(poly_size: usize, rng: &Self::Rng) -> Result<Self::Param, Error> {
        let log_rate = V::get_rate();
        let (table_w_weights, table) = get_table_aes::<E, _>(poly_size, log_rate, &mut rng.clone());

        Ok(BasefoldParams {
            log_rate,
            num_verifier_queries: V::get_reps(),
            max_num_vars: log2_strict(poly_size),
            table_w_weights,
            table,
            rng: rng.clone(),
        })
    }

    fn trim(param: &Self::Param) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        Ok((
            BasefoldProverParams {
                log_rate: param.log_rate,
                table_w_weights: param.table_w_weights.clone(),
                table: param.table.clone(),
                num_verifier_queries: param.num_verifier_queries,
                max_num_vars: param.max_num_vars,
            },
            BasefoldVerifierParams {
                rng: param.rng.clone(),
                max_num_vars: param.max_num_vars,
                log_rate: param.log_rate,
                num_verifier_queries: param.num_verifier_queries,
            },
        ))
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let timer = start_timer!(|| "Basefold::commit");
        // bh_evals is just a copy of poly.evals().
        // Note that this function implicitly assumes that the size of poly.evals() is a
        // power of two. Otherwise, the function crashes with index out of bound.
        let mut bh_evals = poly.evaluations.clone();
        let num_vars = log2_strict(bh_evals.len());
        assert!(num_vars <= pp.max_num_vars && num_vars >= V::get_basecode());

        // Switch to coefficient form
        let mut coeffs = bh_evals.clone();
        interpolate_field_type_over_boolean_hypercube(&mut coeffs);

        // Split the input into chunks of message size, encode each message, and return the codewords
        let basecode =
            encode_field_type_rs_basecode(&coeffs, 1 << pp.log_rate, 1 << V::get_basecode());

        // Apply the recursive definition of the BaseFold code to the list of base codewords,
        // and produce the final codeword
        let mut codeword = evaluate_over_foldable_domain_generic_basecode::<E>(
            1 << V::get_basecode(),
            coeffs.len(),
            pp.log_rate,
            basecode,
            &pp.table,
        );

        // If using repetition code as basecode, it may be faster to use the following line of code to create the commitment and comment out the two lines above
        //        let mut codeword = evaluate_over_foldable_domain(pp.log_rate, coeffs, &pp.table);

        // The sum-check protocol starts from the first variable, but the FRI part
        // will eventually produce the evaluation at (alpha_k, ..., alpha_1), so apply
        // the bit-reversion to reverse the variable indices of the polynomial.
        // In short: store the poly and codeword in big endian
        reverse_index_bits_in_place_field_type(&mut bh_evals);
        reverse_index_bits_in_place_field_type(&mut codeword);

        // Compute and store all the layers of the Merkle tree
        let hasher = new_hasher::<E::BaseField>();
        let codeword_tree = MerkleTree::<E>::from_leaves(codeword, &hasher);

        end_timer!(timer);

        let is_base = match poly.evaluations {
            FieldType::Ext(_) => false,
            FieldType::Base(_) => true,
            _ => unreachable!(),
        };

        Ok(Self::CommitmentWithData {
            codeword_tree,
            bh_evals,
            num_vars,
            is_base,
        })
    }

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error> {
        let timer = start_timer!(|| "Basefold::batch_commit_and_write");
        let comms = Self::batch_commit(pp, polys)?;
        comms.iter().for_each(|comm| {
            transcript.write_commitment(&comm.get_root_as()).unwrap();
            transcript
                .write_field_element_base(&u32_to_field::<E>(comm.num_vars as u32))
                .unwrap();
            transcript
                .write_field_element_base(&u32_to_field::<E>(comm.is_base as u32))
                .unwrap();
        });
        end_timer!(timer);
        Ok(comms)
    }

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error> {
        let polys_vec: Vec<&DenseMultilinearExtension<E>> =
            polys.into_iter().map(|poly| poly).collect();
        polys_vec
            .par_iter()
            .map(|poly| Self::commit(pp, poly))
            .collect()
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithData,
        point: &[E],
        _eval: &E, // Opening does not need eval, except for sanity check
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let hasher = new_hasher::<E::BaseField>();
        let timer = start_timer!(|| "Basefold::open");
        assert!(comm.num_vars >= V::get_basecode());
        let (trees, oracles) = commit_phase(
            &point,
            &comm,
            transcript,
            poly.num_vars,
            poly.num_vars - V::get_basecode(),
            &pp.table_w_weights,
            pp.log_rate,
            &hasher,
        );

        let query_timer = start_timer!(|| "Basefold::open::query_phase");
        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let queries = query_phase(transcript, &comm, &oracles, pp.num_verifier_queries);
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::open::build_query_result");

        let queries_with_merkle_path =
            QueriesResultWithMerklePath::from_query_result(queries, &trees, comm);
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::open::write_queries");
        queries_with_merkle_path.write_transcript(transcript);
        end_timer!(query_timer);

        end_timer!(timer);

        Ok(())
    }

    fn batch_open(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
        comms: &Vec<Self::CommitmentWithData>,
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let hasher = new_hasher::<E::BaseField>();
        let timer = start_timer!(|| "Basefold::batch_open");
        let num_vars = polys.iter().map(|poly| poly.num_vars).max().unwrap();
        let comms = comms.into_iter().collect_vec();
        let min_num_vars = polys.iter().map(|p| p.num_vars).min().unwrap();
        assert!(min_num_vars >= V::get_basecode());

        if cfg!(feature = "sanity-check") {
            evals.iter().for_each(|eval| {
                assert_eq!(
                    &polys[eval.poly()].evaluate(&points[eval.point()]),
                    eval.value(),
                )
            })
        }

        validate_input(
            "batch open",
            pp.max_num_vars,
            &polys.clone(),
            &points.to_vec(),
        )?;

        let sumcheck_timer = start_timer!(|| "Basefold::batch_open::initial sumcheck");
        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(batch_size_log);

        // Use eq(X,t) where t is random to batch the different evaluation queries.
        // Note that this is a small polynomial (only batch_size) compared to the polynomials
        // to open.
        let eq_xt =
            DenseMultilinearExtension::<E>::from_evaluations_ext_vec(t.len(), build_eq_x_r_vec(&t));
        // When this polynomial is smaller, it will be repeatedly summed over the cosets of the hypercube
        let target_sum = inner_product_three(
            evals.iter().map(Evaluation::value),
            &evals
                .iter()
                .map(|eval| E::from(1 << (num_vars - points[eval.point()].len())))
                .collect_vec(),
            &poly_iter_ext(&eq_xt).take(evals.len()).collect_vec(),
        );

        // Merge the polynomials for every point. One merged polynomial for each point.
        let merged_polys = evals.iter().zip(poly_iter_ext(&eq_xt)).fold(
            // This folding will generate a vector of |points| pairs of (scalar, polynomial)
            // The polynomials are initialized to zero, and the scalars are initialized to one
            vec![(E::ONE, Cow::<DenseMultilinearExtension<E>>::default()); points.len()],
            |mut merged_polys, (eval, eq_xt_i)| {
                // For each polynomial to open, eval.point() specifies which point it is to be opened at.
                if merged_polys[eval.point()].1.num_vars == 0 {
                    // If the accumulator for this point is still the zero polynomial,
                    // directly assign the random coefficient and the polynomial to open to
                    // this accumulator
                    merged_polys[eval.point()] = (eq_xt_i, Cow::Borrowed(&polys[eval.poly()]));
                } else {
                    // If the accumulator is unempty now, first force its scalar to 1, i.e.,
                    // make (scalar, polynomial) to (1, scalar * polynomial)
                    let coeff = merged_polys[eval.point()].0;
                    if coeff != E::ONE {
                        merged_polys[eval.point()].0 = E::ONE;
                        multiply_poly(merged_polys[eval.point()].1.to_mut().borrow_mut(), &coeff);
                    }
                    // Equivalent to merged_poly += poly * batch_coeff. Note that
                    // add_assign_mixed_with_coeff allows adding two polynomials with
                    // different variables, and the result has the same number of vars
                    // with the larger one of the two added polynomials.
                    add_polynomial_with_coeff(
                        merged_polys[eval.point()].1.to_mut().borrow_mut(),
                        &polys[eval.poly()],
                        &eq_xt_i,
                    );

                    // Note that once the scalar in the accumulator becomes ONE, it will remain
                    // to be ONE forever.
                }
                merged_polys
            },
        );

        let points = points.to_vec();
        if cfg!(feature = "sanity-check") {
            let expected_sum = merged_polys
                .iter()
                .zip(&points)
                .map(|((scalar, poly), point)| {
                    inner_product(
                        &poly_iter_ext(poly).collect_vec(),
                        build_eq_x_r_vec(&point).iter(),
                    ) * scalar
                        * E::from(1 << (num_vars - poly.num_vars))
                    // When this polynomial is smaller, it will be repeatedly summed over the cosets of the hypercube
                })
                .sum::<E>();
            assert_eq!(expected_sum, target_sum);

            merged_polys.iter().enumerate().for_each(|(i, (_, poly))| {
                assert_eq!(points[i].len(), poly.num_vars);
            });
        }

        let expression = merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (scalar, _))| {
                Expression::<E>::eq_xy(idx)
                    * Expression::Polynomial(Query::new(idx, Rotation::cur()))
                    * scalar
            })
            .sum();
        let sumcheck_polys: Vec<&DenseMultilinearExtension<E>> = merged_polys
            .iter()
            .map(|(_, poly)| poly.deref())
            .collect_vec();
        let virtual_poly =
            VirtualPolynomial::new(&expression, sumcheck_polys, &[], points.as_slice());

        let (challenges, merged_poly_evals) =
            SumCheck::prove(&(), num_vars, virtual_poly, target_sum, transcript)?;

        end_timer!(sumcheck_timer);

        // Now the verifier has obtained the new target sum, and is able to compute the random
        // linear coefficients, and is able to evaluate eq_xy(point) for each poly to open.
        // The remaining tasks for the prover is to prove that
        // sum_i coeffs[i] poly_evals[i] is equal to
        // the new target sum, where coeffs is computed as follows
        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&challenges[..point.len()], point))
            .collect_vec();
        let mut coeffs = vec![E::ZERO; comms.len()];
        evals.iter().enumerate().for_each(|(i, eval)| {
            coeffs[eval.poly()] += eq_xy_evals[eval.point()] * poly_index_ext(&eq_xt, i);
        });

        if cfg!(feature = "sanity-check") {
            let poly_evals = polys
                .iter()
                .map(|poly| poly.evaluate(&challenges[..poly.num_vars]))
                .collect_vec();
            let new_target_sum = inner_product(&poly_evals, &coeffs);
            let desired_sum = merged_polys
                .iter()
                .zip(points)
                .zip(merged_poly_evals)
                .map(|(((scalar, poly), point), evals_from_sum_check)| {
                    assert_eq!(
                        evals_from_sum_check,
                        poly.evaluate(&challenges[..poly.num_vars])
                    );
                    *scalar
                        * evals_from_sum_check
                        * &eq_xy_eval(point.as_slice(), &challenges[0..point.len()])
                })
                .sum::<E>();
            assert_eq!(new_target_sum, desired_sum);
        }
        // Note that the verifier can also compute these coeffs locally, so no need to pass
        // them to the transcript.

        let point = challenges;

        let (trees, oracles) = batch_commit_phase(
            &point,
            comms.as_slice(),
            transcript,
            num_vars,
            num_vars - V::get_basecode(),
            &pp.table_w_weights,
            pp.log_rate,
            coeffs.as_slice(),
            &hasher,
        );

        let query_timer = start_timer!(|| "Basefold::batch_open query phase");
        let query_result = batch_query_phase(
            transcript,
            1 << (num_vars + pp.log_rate),
            comms.as_slice(),
            &oracles,
            pp.num_verifier_queries,
        );
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::batch_open build query result");
        let query_result_with_merkle_path =
            BatchedQueriesResultWithMerklePath::from_batched_query_result(
                query_result,
                &trees,
                &comms,
            );
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::batch_open write query result");
        query_result_with_merkle_path.write_transcript(transcript);
        end_timer!(query_timer);
        end_timer!(timer);

        Ok(())
    }

    fn read_commitments(
        _: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        let roots = (0..num_polys)
            .map(|_| {
                let commitment = transcript.read_commitment().unwrap();
                let num_vars = base_to_usize::<E>(&transcript.read_field_element_base().unwrap());
                let is_base =
                    base_to_usize::<E>(&transcript.read_field_element_base().unwrap()) != 0;
                (num_vars, commitment, is_base)
            })
            .collect_vec();

        Ok(roots
            .iter()
            .map(|(num_vars, commitment, is_base)| {
                BasefoldCommitment::new(commitment.clone(), *num_vars, *is_base)
            })
            .collect_vec())
    }

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let comm = Self::commit(pp, poly)?;

        transcript.write_commitment(&comm.get_root_as())?;
        transcript.write_field_element_base(&u32_to_field::<E>(comm.num_vars as u32))?;
        transcript.write_field_element_base(&u32_to_field::<E>(comm.is_base as u32))?;

        Ok(comm)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::verify");
        assert!(comm.num_vars().unwrap() >= V::get_basecode());
        let hasher = new_hasher::<E::BaseField>();

        let _field_size = 255;
        let num_vars = point.len();
        let num_rounds = num_vars - V::get_basecode();

        let mut fold_challenges: Vec<E> = Vec::with_capacity(vp.max_num_vars);
        let _size = 0;
        let mut roots = Vec::new();
        let mut sumcheck_messages = Vec::with_capacity(num_rounds);
        let sumcheck_timer = start_timer!(|| "Basefold::verify::interaction");
        for i in 0..num_rounds {
            sumcheck_messages.push(transcript.read_field_elements_ext(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
            if i < num_rounds - 1 {
                roots.push(transcript.read_commitment().unwrap());
            }
        }
        end_timer!(sumcheck_timer);

        let read_timer = start_timer!(|| "Basefold::verify::read transcript");
        let final_message = transcript
            .read_field_elements_ext(1 << V::get_basecode())
            .unwrap();
        let query_challenges = transcript
            .squeeze_challenges(vp.num_verifier_queries)
            .iter()
            .map(|index| ext_to_usize(index) % (1 << (num_vars + vp.log_rate)))
            .collect_vec();
        let read_query_timer = start_timer!(|| "Basefold::verify::read query");
        let query_result_with_merkle_path = if comm.is_base() {
            QueriesResultWithMerklePath::read_transcript_base(
                transcript,
                num_rounds,
                vp.log_rate,
                num_vars,
                query_challenges.as_slice(),
            )
        } else {
            QueriesResultWithMerklePath::read_transcript_ext(
                transcript,
                num_rounds,
                vp.log_rate,
                num_vars,
                query_challenges.as_slice(),
            )
        };
        end_timer!(read_query_timer);
        end_timer!(read_timer);

        // coeff is the eq polynomial evaluated at the last challenge.len() variables
        // in reverse order.
        let rev_challenges = fold_challenges.clone().into_iter().rev().collect_vec();
        let coeff = eq_xy_eval(
            &point[point.len() - fold_challenges.len()..],
            &rev_challenges,
        );
        // Compute eq as the partially evaluated eq polynomial
        let mut eq = build_eq_x_r_vec(&point[..point.len() - fold_challenges.len()]);
        eq.par_iter_mut().for_each(|e| *e *= coeff);

        verifier_query_phase(
            &query_result_with_merkle_path,
            &sumcheck_messages,
            &fold_challenges,
            num_rounds,
            num_vars,
            vp.log_rate,
            &final_message,
            &roots,
            comm,
            eq.as_slice(),
            vp.rng.clone(),
            &eval,
            &hasher,
        );
        end_timer!(timer);

        Ok(())
    }

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &Vec<Self::Commitment>,
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::batch_verify");
        // 	let key = "RAYON_NUM_THREADS";
        // 	env::set_var(key, "32");
        let hasher = new_hasher::<E::BaseField>();
        let comms = comms.into_iter().collect_vec();
        let num_vars = points.iter().map(|point| point.len()).max().unwrap();
        let num_rounds = num_vars - V::get_basecode();
        validate_input("batch verify", vp.max_num_vars, &vec![], &points.to_vec())?;
        let poly_num_vars = comms.iter().map(|c| c.num_vars().unwrap()).collect_vec();
        evals.iter().for_each(|eval| {
            assert_eq!(
                points[eval.point()].len(),
                comms[eval.poly()].num_vars().unwrap()
            );
        });
        assert!(poly_num_vars.iter().min().unwrap() >= &V::get_basecode());

        let sumcheck_timer = start_timer!(|| "Basefold::batch_verify::initial sumcheck");
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(batch_size_log);

        let eq_xt =
            DenseMultilinearExtension::from_evaluations_ext_vec(t.len(), build_eq_x_r_vec(&t));
        let target_sum = inner_product_three(
            evals.iter().map(Evaluation::value),
            &evals
                .iter()
                .map(|eval| E::from(1 << (num_vars - points[eval.point()].len())))
                .collect_vec(),
            &poly_iter_ext(&eq_xt).take(evals.len()).collect_vec(),
        );

        let (new_target_sum, verify_point) =
            SumCheck::verify(&(), num_vars, 2, target_sum, transcript)?;
        end_timer!(sumcheck_timer);

        // Now the goal is to use the BaseFold to check the new target sum. Note that this time
        // we only have one eq polynomial in the sum-check.
        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&verify_point[..point.len()], point))
            .collect_vec();
        let mut coeffs = vec![E::ZERO; comms.len()];
        evals.iter().enumerate().for_each(|(i, eval)| {
            coeffs[eval.poly()] += eq_xy_evals[eval.point()] * poly_index_ext(&eq_xt, i)
        });

        // start of verify
        // read first $(num_var - 1) commitments
        let read_timer = start_timer!(|| "Basefold::verify::read transcript");
        let mut sumcheck_messages: Vec<Vec<E>> = Vec::with_capacity(num_rounds);
        let mut roots: Vec<Digest<E::BaseField>> = Vec::with_capacity(num_rounds - 1);
        let mut fold_challenges: Vec<E> = Vec::with_capacity(num_rounds);
        for i in 0..num_rounds {
            sumcheck_messages.push(transcript.read_field_elements_ext(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
            if i < num_rounds - 1 {
                roots.push(transcript.read_commitment().unwrap());
            }
        }
        let final_message = transcript
            .read_field_elements_ext(1 << V::get_basecode())
            .unwrap();

        let query_challenges = transcript
            .squeeze_challenges(vp.num_verifier_queries)
            .iter()
            .map(|index| ext_to_usize(index) % (1 << (num_vars + vp.log_rate)))
            .collect_vec();

        let read_query_timer = start_timer!(|| "Basefold::verify::read query");
        // Here we assumed that all the commitments have the same type:
        // either all base field or all extension field. Need to handle
        // more complex case later.
        let query_result_with_merkle_path = if comms[0].is_base {
            BatchedQueriesResultWithMerklePath::read_transcript_base(
                transcript,
                num_rounds,
                vp.log_rate,
                poly_num_vars.as_slice(),
                query_challenges.as_slice(),
            )
        } else {
            BatchedQueriesResultWithMerklePath::read_transcript_ext(
                transcript,
                num_rounds,
                vp.log_rate,
                poly_num_vars.as_slice(),
                query_challenges.as_slice(),
            )
        };
        end_timer!(read_query_timer);
        end_timer!(read_timer);

        // coeff is the eq polynomial evaluated at the last challenge.len() variables
        // in reverse order.
        let rev_challenges = fold_challenges.clone().into_iter().rev().collect_vec();
        let coeff = eq_xy_eval(
            &verify_point.as_slice()[verify_point.len() - fold_challenges.len()..],
            &rev_challenges,
        );
        // Compute eq as the partially evaluated eq polynomial
        let mut eq = build_eq_x_r_vec(
            &verify_point.as_slice()[..verify_point.len() - fold_challenges.len()],
        );
        eq.par_iter_mut().for_each(|e| *e *= coeff);

        batch_verifier_query_phase(
            &query_result_with_merkle_path,
            &sumcheck_messages,
            &fold_challenges,
            num_rounds,
            num_vars,
            vp.log_rate,
            &final_message,
            &roots,
            &comms,
            &coeffs,
            eq.as_slice(),
            vp.rng.clone(),
            &new_target_sum,
            &hasher,
        );
        end_timer!(timer);
        Ok(())
    }
}

impl<E: ExtensionField, V: BasefoldExtParams> NoninteractivePCS<E> for Basefold<E, V>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
}

fn encode_field_type_rs_basecode<E: ExtensionField>(
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
fn encode_rs_basecode<F: Field>(poly: &Vec<F>, rate: usize, message_size: usize) -> Vec<Vec<F>> {
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

#[allow(unused)]
fn encode_repetition_basecode<F: Field>(poly: &Vec<F>, rate: usize) -> Vec<Vec<F>> {
    let mut base_codewords = Vec::new();
    for c in poly {
        let mut rep_code = Vec::new();
        for i in 0..rate {
            rep_code.push(*c);
        }
        base_codewords.push(rep_code);
    }
    return base_codewords;
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

#[allow(unused)]
pub fn evaluate_over_foldable_domain<F: Field>(
    log_rate: usize,
    mut coeffs: Vec<F>,
    table: &Vec<Vec<F>>,
) -> Vec<F> {
    // iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let k = coeffs.len();
    let logk = log2_strict(k);
    let cl = 1 << (logk + log_rate);
    let rate = 1 << log_rate;
    let mut coeffs_with_rep = Vec::with_capacity(cl);
    for i in 0..cl {
        coeffs_with_rep.push(F::ZERO);
    }

    // base code - in this case is the repetition code
    let now = Instant::now();
    for i in 0..k {
        for j in 0..rate {
            coeffs_with_rep[i * rate + j] = coeffs[i];
        }
    }

    let mut chunk_size = rate; // block length of the base code
    for i in 0..logk {
        let level = &table[i + log_rate];
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size >> 1);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut coeffs_with_rep)
            .par_chunks_mut(chunk_size)
            .for_each(|chunk| {
                let half_chunk = chunk_size >> 1;
                for j in half_chunk..chunk_size {
                    let rhs = chunk[j] * level[j - half_chunk];
                    chunk[j] = chunk[j - half_chunk] - rhs;
                    chunk[j - half_chunk] = chunk[j - half_chunk] + rhs;
                }
            });
    }
    coeffs_with_rep
}

fn interpolate_field_type_over_boolean_hypercube<E: ExtensionField>(evals: &mut FieldType<E>) {
    match evals {
        FieldType::Ext(evals) => interpolate_over_boolean_hypercube(evals),
        FieldType::Base(evals) => interpolate_over_boolean_hypercube(evals),
        _ => unreachable!(),
    };
}

fn interpolate_over_boolean_hypercube<F: Field>(evals: &mut Vec<F>) {
    let timer = start_timer!(|| "interpolate_over_hypercube");
    // iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = log2_strict(evals.len());

    evals.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] -= chunk[0];
    });

    // This code implicitly assumes that coeffs has size at least 1 << n,
    // that means the size of evals should be a power of two
    for i in 2..n + 1 {
        let chunk_size = 1 << i;
        evals.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] = chunk[j] - chunk[j - half_chunk];
            }
        });
    }
    end_timer!(timer);
}

fn sum_check_first_round_field_type<E: ExtensionField>(
    mut eq: &mut Vec<E>,
    mut bh_values: &mut FieldType<E>,
) -> Vec<E> {
    // The input polynomials are in the form of evaluations. Instead of viewing
    // every one element as the evaluation of the polynomial at a single point,
    // we can view every two elements as partially evaluating the polynomial at
    // a single point, leaving the first variable free, and obtaining a univariate
    // polynomial. The one_level_interp_hc transforms the evaluation forms into
    // the coefficient forms, for every of these partial polynomials.
    one_level_interp_hc(&mut eq);
    one_level_interp_hc_field_type(&mut bh_values);
    parallel_pi_field_type(bh_values, eq)
    //    p_i(&bh_values, &eq)
}

fn sum_check_first_round<E: ExtensionField>(
    mut eq: &mut Vec<E>,
    mut bh_values: &mut Vec<E>,
) -> Vec<E> {
    // The input polynomials are in the form of evaluations. Instead of viewing
    // every one element as the evaluation of the polynomial at a single point,
    // we can view every two elements as partially evaluating the polynomial at
    // a single point, leaving the first variable free, and obtaining a univariate
    // polynomial. The one_level_interp_hc transforms the evaluation forms into
    // the coefficient forms, for every of these partial polynomials.
    one_level_interp_hc(&mut eq);
    one_level_interp_hc(&mut bh_values);
    parallel_pi(bh_values, eq)
    //    p_i(&bh_values, &eq)
}

pub fn one_level_interp_hc_field_type<E: ExtensionField>(evals: &mut FieldType<E>) {
    match evals {
        FieldType::Ext(evals) => one_level_interp_hc(evals),
        FieldType::Base(evals) => one_level_interp_hc(evals),
        _ => unreachable!(),
    }
}

pub fn one_level_interp_hc<F: Field>(evals: &mut Vec<F>) {
    if evals.len() == 1 {
        return;
    }
    evals.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[1] - chunk[0];
    });
}

pub fn one_level_eval_hc<F: Field>(evals: &mut Vec<F>, challenge: F) {
    evals.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[0] + challenge * chunk[1];
    });

    // Skip every one other element
    let mut index = 0;
    evals.retain(|_| {
        index += 1;
        (index - 1) % 2 == 1
    });
}

fn parallel_pi_field_type<E: ExtensionField>(evals: &mut FieldType<E>, eq: &mut Vec<E>) -> Vec<E> {
    match evals {
        FieldType::Ext(evals) => parallel_pi(evals, &eq),
        FieldType::Base(evals) => parallel_pi_base(evals, &eq),
        _ => unreachable!(),
    }
}

fn parallel_pi<F: Field>(evals: &Vec<F>, eq: &Vec<F>) -> Vec<F> {
    if evals.len() == 1 {
        return vec![evals[0], evals[0], evals[0]];
    }
    let mut coeffs = vec![F::ZERO, F::ZERO, F::ZERO];

    // Manually write down the multiplication formular of two linear polynomials
    let mut firsts = vec![F::ZERO; evals.len()];
    firsts.par_iter_mut().enumerate().for_each(|(i, f)| {
        if i % 2 == 0 {
            *f = evals[i] * eq[i];
        }
    });

    let mut seconds = vec![F::ZERO; evals.len()];
    seconds.par_iter_mut().enumerate().for_each(|(i, f)| {
        if i % 2 == 0 {
            *f = evals[i + 1] * eq[i] + evals[i] * eq[i + 1];
        }
    });

    let mut thirds = vec![F::ZERO; evals.len()];
    thirds.par_iter_mut().enumerate().for_each(|(i, f)| {
        if i % 2 == 0 {
            *f = evals[i + 1] * eq[i + 1];
        }
    });

    coeffs[0] = firsts.par_iter().sum();
    coeffs[1] = seconds.par_iter().sum();
    coeffs[2] = thirds.par_iter().sum();

    coeffs
}

fn parallel_pi_base<E: ExtensionField>(evals: &Vec<E::BaseField>, eq: &Vec<E>) -> Vec<E> {
    if evals.len() == 1 {
        return vec![E::from(evals[0]), E::from(evals[0]), E::from(evals[0])];
    }
    let mut coeffs = vec![E::ZERO, E::ZERO, E::ZERO];

    // Manually write down the multiplication formular of two linear polynomials
    let mut firsts = vec![E::ZERO; evals.len()];
    firsts.par_iter_mut().enumerate().for_each(|(i, f)| {
        if i % 2 == 0 {
            *f = E::from(evals[i]) * eq[i];
        }
    });

    let mut seconds = vec![E::ZERO; evals.len()];
    seconds.par_iter_mut().enumerate().for_each(|(i, f)| {
        if i % 2 == 0 {
            *f = E::from(evals[i + 1]) * eq[i] + E::from(evals[i]) * eq[i + 1];
        }
    });

    let mut thirds = vec![E::ZERO; evals.len()];
    thirds.par_iter_mut().enumerate().for_each(|(i, f)| {
        if i % 2 == 0 {
            *f = E::from(evals[i + 1]) * eq[i + 1];
        }
    });

    coeffs[0] = firsts.par_iter().sum();
    coeffs[1] = seconds.par_iter().sum();
    coeffs[2] = thirds.par_iter().sum();

    coeffs
}

fn sum_check_challenge_round<F: Field>(
    mut eq: &mut Vec<F>,
    mut bh_values: &mut Vec<F>,
    challenge: F,
) -> Vec<F> {
    // Note that when the last round ends, every two elements are in
    // the coefficient form. Use the challenge to reduce the two elements
    // into a single value. This is equivalent to substituting the challenge
    // to the first variable of the poly.
    one_level_eval_hc(&mut bh_values, challenge);
    one_level_eval_hc(&mut eq, challenge);

    one_level_interp_hc(&mut eq);
    one_level_interp_hc(&mut bh_values);

    parallel_pi(&bh_values, &eq)
    // p_i(&bh_values,&eq)
}

fn sum_check_last_round<F: Field>(mut eq: &mut Vec<F>, mut bh_values: &mut Vec<F>, challenge: F) {
    one_level_eval_hc(&mut bh_values, challenge);
    one_level_eval_hc(&mut eq, challenge);
}

fn basefold_one_round_by_interpolation_weights<E: ExtensionField>(
    table: &Vec<Vec<(E::BaseField, E::BaseField)>>,
    level_index: usize,
    values: &Vec<E>,
    challenge: E,
) -> Vec<E> {
    let level = &table[level_index];
    values
        .par_chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            interpolate2_weights(
                [
                    (E::from(level[i].0), ys[0]),
                    (E::from(-(level[i].0)), ys[1]),
                ],
                E::from(level[i].1),
                challenge,
            )
        })
        .collect::<Vec<_>>()
}

fn basefold_get_query<E: ExtensionField>(
    poly_codeword: &FieldType<E>,
    oracles: &Vec<Vec<E>>,
    x_index: usize,
) -> SingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mut index = x_index;
    let p1 = index | 1;
    let p0 = p1 - 1;

    let commitment_query = match poly_codeword {
        FieldType::Ext(poly_codeword) => {
            CodewordSingleQueryResult::new_ext(poly_codeword[p0], poly_codeword[p1], p0)
        }
        FieldType::Base(poly_codeword) => {
            CodewordSingleQueryResult::new_base(poly_codeword[p0], poly_codeword[p1], p0)
        }
        _ => unreachable!(),
    };
    index >>= 1;

    let mut oracle_queries = Vec::with_capacity(oracles.len() + 1);
    for oracle in oracles {
        let p1 = index | 1;
        let p0 = p1 - 1;

        oracle_queries.push(CodewordSingleQueryResult::new_ext(
            oracle[p0], oracle[p1], p0,
        ));
        index >>= 1;
    }

    let oracle_query = OracleListQueryResult {
        inner: oracle_queries,
    };

    return SingleQueryResult {
        oracle_query,
        commitment_query,
    };
}

fn batch_basefold_get_query<E: ExtensionField>(
    comms: &[&BasefoldCommitmentWithData<E>],
    oracles: &Vec<Vec<E>>,
    codeword_size: usize,
    x_index: usize,
) -> BatchedSingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let mut oracle_list_queries = Vec::with_capacity(oracles.len());

    let mut index = x_index;
    index >>= 1;
    for oracle in oracles {
        let p1 = index | 1;
        let p0 = p1 - 1;
        oracle_list_queries.push(CodewordSingleQueryResult::<E>::new_ext(
            oracle[p0], oracle[p1], p0,
        ));
        index >>= 1;
    }
    let oracle_query = OracleListQueryResult {
        inner: oracle_list_queries,
    };

    let comm_queries = comms
        .iter()
        .map(|comm| {
            let x_index = x_index >> (log2_strict(codeword_size) - comm.codeword_size_log());
            let p1 = x_index | 1;
            let p0 = p1 - 1;
            match comm.get_codeword() {
                FieldType::Ext(poly_codeword) => {
                    CodewordSingleQueryResult::new_ext(poly_codeword[p0], poly_codeword[p1], p0)
                }
                FieldType::Base(poly_codeword) => {
                    CodewordSingleQueryResult::new_base(poly_codeword[p0], poly_codeword[p1], p0)
                }
                _ => unreachable!(),
            }
        })
        .collect_vec();

    let commitments_query = CommitmentsQueryResult {
        inner: comm_queries,
    };

    BatchedSingleQueryResult {
        oracle_query,
        commitments_query,
    }
}

#[allow(unused)]
pub fn interpolate2_weights_base<E: ExtensionField>(
    points: [(E, E); 2],
    weight: E::BaseField,
    x: E,
) -> E {
    interpolate2_weights(points, E::from(weight), x)
}

pub fn interpolate2_weights<F: Field>(points: [(F, F); 2], weight: F, x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    if cfg!(feature = "sanity-check") {
        assert_ne!(a0, b0);
        assert_eq!(weight * (b0 - a0), F::ONE);
    }
    // Here weight = 1/(b0-a0). The reason for precomputing it is that inversion is expensive
    a1 + (x - a0) * (b1 - a1) * weight
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

    let res = from_raw_bytes::<E>(&dest);

    res
}

pub fn interpolate2<F: Field>(points: [(F, F); 2], x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    assert_ne!(a0, b0);
    a1 + (x - a0) * (b1 - a1) * (b0 - a0).invert().unwrap()
}

fn degree_2_zero_plus_one<F: Field>(poly: &Vec<F>) -> F {
    poly[0] + poly[0] + poly[1] + poly[2]
}

fn degree_2_eval<F: Field>(poly: &Vec<F>, point: F) -> F {
    poly[0] + point * poly[1] + point * point * poly[2]
}

fn from_raw_bytes<E: ExtensionField>(bytes: &Vec<u8>) -> E::BaseField {
    let mut res = E::BaseField::ZERO;
    bytes.into_iter().for_each(|b| {
        res += E::BaseField::from(u64::from(*b));
    });
    res
}

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
fn commit_phase<E: ExtensionField>(
    point: &[E],
    comm: &BasefoldCommitmentWithData<E>,
    transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(E::BaseField, E::BaseField)>>,
    log_rate: usize,
    hasher: &Hasher<E::BaseField>,
) -> (Vec<MerkleTree<E>>, Vec<Vec<E>>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Commit phase");
    assert_eq!(point.len(), num_vars);
    let mut oracles = Vec::with_capacity(num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut running_oracle = field_type_iter_ext(comm.get_codeword()).collect_vec();
    let mut running_evals = comm.bh_evals.clone();

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let build_eq_timer = start_timer!(|| "Basefold::open");
    let mut eq = build_eq_x_r_vec(&point);
    end_timer!(build_eq_timer);
    reverse_index_bits_in_place(&mut eq);

    let sumcheck_timer = start_timer!(|| "Basefold sumcheck first round");
    let mut last_sumcheck_message = sum_check_first_round_field_type(&mut eq, &mut running_evals);
    end_timer!(sumcheck_timer);

    let mut running_evals = match running_evals {
        FieldType::Ext(evals) => evals,
        FieldType::Base(evals) => evals.iter().map(|x| E::from(*x)).collect_vec(),
        _ => unreachable!(),
    };

    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript
            .write_field_elements_ext(&last_sumcheck_message)
            .unwrap();

        let challenge = transcript.squeeze_challenge();

        // Fold the current oracle for FRI
        running_oracle = basefold_one_round_by_interpolation_weights::<E>(
            &table_w_weights,
            log2_strict(running_oracle.len()) - 1,
            &running_oracle,
            challenge,
        );

        if i < num_rounds - 1 {
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut running_evals, challenge);
            let running_tree =
                MerkleTree::<E>::from_leaves(FieldType::Ext(running_oracle.clone()), hasher);
            let running_root = running_tree.root();
            transcript.write_commitment(&running_root).unwrap();

            oracles.push(running_oracle.clone());
            trees.push(running_tree);
        } else {
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // running_evals is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut running_evals, challenge);
            // For the FRI part, we send the current polynomial as the message.
            // Transform it back into little endiean before sending it
            reverse_index_bits_in_place(&mut running_evals);
            transcript.write_field_elements_ext(&running_evals).unwrap();

            if cfg!(feature = "sanity-check") {
                // If the prover is honest, in the last round, the running oracle
                // on the prover side should be exactly the encoding of the folded polynomial.

                let mut coeffs = running_evals.clone();
                interpolate_over_boolean_hypercube(&mut coeffs);
                let basecode = encode_rs_basecode(&coeffs, 1 << log_rate, coeffs.len());
                assert_eq!(basecode.len(), 1);
                let basecode = basecode[0].clone();

                reverse_index_bits_in_place(&mut running_oracle);
                assert_eq!(basecode, running_oracle);
            }
        }
        end_timer!(sumcheck_timer);
    }
    end_timer!(timer);
    return (trees, oracles);
}

// outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
fn batch_commit_phase<E: ExtensionField>(
    point: &[E],
    comms: &[&BasefoldCommitmentWithData<E>],
    transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(E::BaseField, E::BaseField)>>,
    log_rate: usize,
    coeffs: &[E],
    hasher: &Hasher<E::BaseField>,
) -> (Vec<MerkleTree<E>>, Vec<Vec<E>>)
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Batch Commit phase");
    assert_eq!(point.len(), num_vars);
    let mut oracles = Vec::with_capacity(num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut running_oracle = vec![E::ZERO; 1 << (num_vars + log_rate)];

    let build_oracle_timer = start_timer!(|| "Basefold build initial oracle");
    // Before the interaction, collect all the polynomials whose num variables match the
    // max num variables
    let running_oracle_len = running_oracle.len();
    comms
        .iter()
        .enumerate()
        .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
        .for_each(|(index, comm)| {
            running_oracle
                .iter_mut()
                .zip_eq(field_type_iter_ext(comm.get_codeword()))
                .for_each(|(r, a)| *r += E::from(a) * coeffs[index]);
        });
    end_timer!(build_oracle_timer);

    let build_oracle_timer = start_timer!(|| "Basefold build initial sumcheck evals");
    // Unlike the FRI part, the sum-check part still follows the original procedure,
    // and linearly combine all the polynomials once for all
    let mut sum_of_all_evals_for_sumcheck = vec![E::ZERO; 1 << num_vars];
    comms.iter().enumerate().for_each(|(index, comm)| {
        sum_of_all_evals_for_sumcheck
            .par_iter_mut()
            .enumerate()
            .for_each(|(pos, r)| {
                // Evaluating the multilinear polynomial outside of its interpolation hypercube
                // is equivalent to repeating each element in place.
                // Here is the tricky part: the bh_evals are stored in big endian, but we want
                // to align the polynomials to the variable with index 0 before adding them
                // together. So each element is repeated by
                // sum_of_all_evals_for_sumcheck.len() / bh_evals.len() times
                *r += E::from(field_type_index_ext(
                    &comm.bh_evals,
                    pos >> (num_vars - log2_strict(comm.bh_evals.len())),
                )) * coeffs[index]
            });
    });
    end_timer!(build_oracle_timer);

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let mut eq = build_eq_x_r_vec(&point);
    reverse_index_bits_in_place(&mut eq);

    let sumcheck_timer = start_timer!(|| "Basefold first round");
    let mut sumcheck_messages = Vec::with_capacity(num_rounds + 1);
    let mut last_sumcheck_message =
        sum_check_first_round(&mut eq, &mut sum_of_all_evals_for_sumcheck);
    sumcheck_messages.push(last_sumcheck_message.clone());
    end_timer!(sumcheck_timer);

    for i in 0..num_rounds {
        let sumcheck_timer = start_timer!(|| format!("Batch basefold round {}", i));
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript
            .write_field_elements_ext(&last_sumcheck_message)
            .unwrap();

        let challenge = transcript.squeeze_challenge();

        // Fold the current oracle for FRI
        running_oracle = basefold_one_round_by_interpolation_weights::<E>(
            &table_w_weights,
            log2_strict(running_oracle.len()) - 1,
            &running_oracle,
            challenge,
        );

        if i < num_rounds - 1 {
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            sumcheck_messages.push(last_sumcheck_message.clone());
            let running_tree =
                MerkleTree::<E>::from_leaves(FieldType::Ext(running_oracle.clone()), hasher);
            let running_root = running_tree.root();
            transcript.write_commitment(&running_root).unwrap();

            oracles.push(running_oracle.clone());
            trees.push(running_tree);

            // Then merge the rest polynomials whose sizes match the current running oracle
            let running_oracle_len = running_oracle.len();
            comms
                .iter()
                .enumerate()
                .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
                .for_each(|(index, comm)| {
                    running_oracle
                        .iter_mut()
                        .zip_eq(field_type_iter_ext(comm.get_codeword()))
                        .for_each(|(r, a)| *r += E::from(a) * coeffs[index]);
                });
        } else {
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // sum_of_all_evals_for_sumcheck is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            // For the FRI part, we send the current polynomial as the message.
            // Transform it back into little endiean before sending it
            reverse_index_bits_in_place(&mut sum_of_all_evals_for_sumcheck);
            transcript
                .write_field_elements_ext(&sum_of_all_evals_for_sumcheck)
                .unwrap();

            if cfg!(feature = "sanity-check") {
                // If the prover is honest, in the last round, the running oracle
                // on the prover side should be exactly the encoding of the folded polynomial.

                let mut coeffs = sum_of_all_evals_for_sumcheck.clone();
                interpolate_over_boolean_hypercube(&mut coeffs);
                let basecode = encode_rs_basecode(&coeffs, 1 << log_rate, coeffs.len());
                assert_eq!(basecode.len(), 1);
                let basecode = basecode[0].clone();

                reverse_index_bits_in_place(&mut running_oracle);
                assert_eq!(basecode, running_oracle);
            }
        }
        end_timer!(sumcheck_timer);
    }
    end_timer!(timer);
    return (trees, oracles);
}

fn query_phase<E: ExtensionField>(
    transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>,
    comm: &BasefoldCommitmentWithData<E>,
    oracles: &Vec<Vec<E>>,
    num_verifier_queries: usize,
) -> QueriesResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let queries = transcript.squeeze_challenges(num_verifier_queries);

    // Transform the challenge queries from field elements into integers
    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| ext_to_usize(x_index) % comm.codeword_size())
        .collect_vec();

    QueriesResult {
        inner: queries_usize
            .par_iter()
            .map(|x_index| {
                (
                    *x_index,
                    basefold_get_query::<E>(comm.get_codeword(), &oracles, *x_index),
                )
            })
            .collect(),
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
enum CodewordPointPair<E: ExtensionField> {
    Ext(E, E),
    Base(E::BaseField, E::BaseField),
}

impl<E: ExtensionField> CodewordPointPair<E> {
    pub fn as_ext(&self) -> (E, E) {
        match self {
            CodewordPointPair::Ext(x, y) => (*x, *y),
            CodewordPointPair::Base(x, y) => (E::from(*x), E::from(*y)),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct CodewordSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    codepoints: CodewordPointPair<E>,
    index: usize,
}

impl<E: ExtensionField> CodewordSingleQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn new_ext(left: E, right: E, index: usize) -> Self {
        Self {
            codepoints: CodewordPointPair::Ext(left, right),
            index,
        }
    }

    fn new_base(left: E::BaseField, right: E::BaseField, index: usize) -> Self {
        Self {
            codepoints: CodewordPointPair::Base(left, right),
            index,
        }
    }

    fn left_ext(&self) -> E {
        match &self.codepoints {
            CodewordPointPair::Ext(x, _) => *x,
            CodewordPointPair::Base(x, _) => E::from(*x),
        }
    }

    fn right_ext(&self) -> E {
        match &self.codepoints {
            CodewordPointPair::Ext(_, y) => *y,
            CodewordPointPair::Base(_, y) => E::from(*y),
        }
    }

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        match self.codepoints {
            CodewordPointPair::Ext(x, y) => {
                transcript.write_field_element_ext(&x).unwrap();
                transcript.write_field_element_ext(&y).unwrap();
            }
            CodewordPointPair::Base(x, y) => {
                transcript.write_field_element_base(&x).unwrap();
                transcript.write_field_element_base(&y).unwrap();
            }
        };
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        full_codeword_size_log: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        Self::new_ext(
            transcript.read_field_element_ext().unwrap(),
            transcript.read_field_element_ext().unwrap(),
            index >> (full_codeword_size_log - codeword_size_log),
        )
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        full_codeword_size_log: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        Self::new_base(
            transcript.read_field_element_base().unwrap(),
            transcript.read_field_element_base().unwrap(),
            index >> (full_codeword_size_log - codeword_size_log),
        )
    }
}

#[derive(Debug, Clone)]
struct CodewordSingleQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    query: CodewordSingleQueryResult<E>,
    merkle_path: MerklePathWithoutLeafOrRoot<E>,
}

impl<E: ExtensionField> CodewordSingleQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.query.write_transcript(transcript);
        self.merkle_path.write_transcript(transcript);
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        full_codeword_size_log: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        Self {
            query: CodewordSingleQueryResult::read_transcript_base(
                transcript,
                full_codeword_size_log,
                codeword_size_log,
                index,
            ),
            merkle_path: MerklePathWithoutLeafOrRoot::read_transcript(
                transcript,
                codeword_size_log,
            ),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        full_codeword_size_log: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        Self {
            query: CodewordSingleQueryResult::read_transcript_ext(
                transcript,
                full_codeword_size_log,
                codeword_size_log,
                index,
            ),
            merkle_path: MerklePathWithoutLeafOrRoot::read_transcript(
                transcript,
                codeword_size_log,
            ),
        }
    }

    pub fn check_merkle_path(&self, root: &Digest<E::BaseField>, hasher: &Hasher<E::BaseField>) {
        // let timer = start_timer!(|| "CodewordSingleQuery::Check Merkle Path");
        match self.query.codepoints {
            CodewordPointPair::Ext(left, right) => {
                self.merkle_path.authenticate_leaves_root_ext(
                    left,
                    right,
                    self.query.index,
                    root,
                    hasher,
                );
            }
            CodewordPointPair::Base(left, right) => {
                self.merkle_path.authenticate_leaves_root_base(
                    left,
                    right,
                    self.query.index,
                    root,
                    hasher,
                );
            }
        }
        // end_timer!(timer);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OracleListQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResult<E>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitmentsQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResult<E>>,
}

#[derive(Debug, Clone)]
struct OracleListQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>,
}

impl<E: ExtensionField> OracleListQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn read_transcript(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        codeword_size_log: usize,
        index: usize,
    ) -> Self {
        // Remember that the prover doesn't send the commitment in the last round.
        // In the first round, the oracle is sent after folding, so the first oracle
        // has half the size of the full codeword size.
        Self {
            inner: (0..num_rounds - 1)
                .map(|round| {
                    CodewordSingleQueryResultWithMerklePath::read_transcript_ext(
                        transcript,
                        codeword_size_log,
                        codeword_size_log - round - 1,
                        index,
                    )
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct CommitmentsQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>,
}

impl<E: ExtensionField> CommitmentsQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        max_num_vars: usize,
        poly_num_vars: &[usize],
        log_rate: usize,
        index: usize,
    ) -> Self {
        Self {
            inner: poly_num_vars
                .iter()
                .map(|num_vars| {
                    CodewordSingleQueryResultWithMerklePath::read_transcript_base(
                        transcript,
                        max_num_vars + log_rate,
                        num_vars + log_rate,
                        index,
                    )
                })
                .collect(),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        max_num_vars: usize,
        poly_num_vars: &[usize],
        log_rate: usize,
        index: usize,
    ) -> Self {
        Self {
            inner: poly_num_vars
                .iter()
                .map(|num_vars| {
                    CodewordSingleQueryResultWithMerklePath::read_transcript_ext(
                        transcript,
                        max_num_vars + log_rate,
                        num_vars + log_rate,
                        index,
                    )
                })
                .collect(),
        }
    }
}

impl<E: ExtensionField> ListQueryResult<E> for OracleListQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_inner(&self) -> &Vec<CodewordSingleQueryResult<E>> {
        &self.inner
    }

    fn get_inner_into(self) -> Vec<CodewordSingleQueryResult<E>> {
        self.inner
    }
}

impl<E: ExtensionField> ListQueryResult<E> for CommitmentsQueryResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_inner(&self) -> &Vec<CodewordSingleQueryResult<E>> {
        &self.inner
    }

    fn get_inner_into(self) -> Vec<CodewordSingleQueryResult<E>> {
        self.inner
    }
}

impl<E: ExtensionField> ListQueryResultWithMerklePath<E> for OracleListQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_inner(&self) -> &Vec<CodewordSingleQueryResultWithMerklePath<E>> {
        &self.inner
    }

    fn new(inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>) -> Self {
        Self { inner }
    }
}

impl<E: ExtensionField> ListQueryResultWithMerklePath<E> for CommitmentsQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_inner(&self) -> &Vec<CodewordSingleQueryResultWithMerklePath<E>> {
        &self.inner
    }

    fn new(inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>) -> Self {
        Self { inner }
    }
}

trait ListQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn get_inner(&self) -> &Vec<CodewordSingleQueryResult<E>>;

    fn get_inner_into(self) -> Vec<CodewordSingleQueryResult<E>>;

    fn merkle_path(
        &self,
        path: impl Fn(usize, usize) -> MerklePathWithoutLeafOrRoot<E>,
    ) -> Vec<MerklePathWithoutLeafOrRoot<E>> {
        let ret = self
            .get_inner()
            .into_iter()
            .enumerate()
            .map(|(i, query_result)| {
                let path = path(i, query_result.index);
                path
            })
            .collect_vec();
        ret
    }
}

trait ListQueryResultWithMerklePath<E: ExtensionField>: Sized
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn new(inner: Vec<CodewordSingleQueryResultWithMerklePath<E>>) -> Self;

    fn get_inner(&self) -> &Vec<CodewordSingleQueryResultWithMerklePath<E>>;

    fn from_query_and_trees<LQR: ListQueryResult<E>>(
        query_result: LQR,
        path: impl Fn(usize, usize) -> MerklePathWithoutLeafOrRoot<E>,
    ) -> Self {
        Self::new(
            query_result
                .merkle_path(path)
                .into_iter()
                .zip(query_result.get_inner_into().into_iter())
                .map(
                    |(path, codeword_result)| CodewordSingleQueryResultWithMerklePath {
                        query: codeword_result,
                        merkle_path: path,
                    },
                )
                .collect_vec(),
        )
    }

    fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.get_inner()
            .iter()
            .for_each(|q| q.write_transcript(transcript));
    }

    fn check_merkle_paths(&self, roots: &Vec<Digest<E::BaseField>>, hasher: &Hasher<E::BaseField>) {
        // let timer = start_timer!(|| "ListQuery::Check Merkle Path");
        self.get_inner()
            .iter()
            .zip(roots.iter())
            .for_each(|(q, root)| {
                q.check_merkle_path(root, hasher);
            });
        // end_timer!(timer);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResult<E>,
    commitment_query: CodewordSingleQueryResult<E>,
}

#[derive(Debug, Clone)]
struct SingleQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResultWithMerklePath<E>,
    commitment_query: CodewordSingleQueryResultWithMerklePath<E>,
}

impl<E: ExtensionField> SingleQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_single_query_result(
        single_query_result: SingleQueryResult<E>,
        oracle_trees: &Vec<MerkleTree<E>>,
        commitment: &BasefoldCommitmentWithData<E>,
    ) -> Self {
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::from_query_and_trees(
                single_query_result.oracle_query,
                |i, j| oracle_trees[i].merkle_path_without_leaf_sibling_or_root(j),
            ),
            commitment_query: CodewordSingleQueryResultWithMerklePath {
                query: single_query_result.commitment_query.clone(),
                merkle_path: commitment
                    .codeword_tree
                    .merkle_path_without_leaf_sibling_or_root(
                        single_query_result.commitment_query.index,
                    ),
            },
        }
    }

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.oracle_query.write_transcript(transcript);
        self.commitment_query.write_transcript(transcript);
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        num_vars: usize,
        index: usize,
    ) -> Self {
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::read_transcript(
                transcript,
                num_rounds,
                num_vars + log_rate,
                index,
            ),
            commitment_query: CodewordSingleQueryResultWithMerklePath::read_transcript_base(
                transcript,
                num_vars + log_rate,
                num_vars + log_rate,
                index,
            ),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        num_vars: usize,
        index: usize,
    ) -> Self {
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::read_transcript(
                transcript,
                num_rounds,
                num_vars + log_rate,
                index,
            ),
            commitment_query: CodewordSingleQueryResultWithMerklePath::read_transcript_ext(
                transcript,
                num_vars + log_rate,
                num_vars + log_rate,
                index,
            ),
        }
    }

    pub fn check(
        &self,
        fold_challenges: &Vec<E>,
        num_rounds: usize,
        num_vars: usize,
        log_rate: usize,
        final_codeword: &Vec<E>,
        roots: &Vec<Digest<E::BaseField>>,
        comm: &BasefoldCommitment<E>,
        mut cipher: ctr::Ctr32LE<aes::Aes128>,
        index: usize,
        hasher: &Hasher<E::BaseField>,
    ) {
        let timer = start_timer!(|| "Checking codeword single query");
        self.oracle_query.check_merkle_paths(roots, hasher);
        self.commitment_query
            .check_merkle_path(&Digest(comm.root().0.try_into().unwrap()), hasher);

        let (mut curr_left, mut curr_right) = self.commitment_query.query.codepoints.as_ext();

        let mut right_index = index | 1;
        let mut left_index = right_index - 1;

        for i in 0..num_rounds {
            // let round_timer = start_timer!(|| format!("SingleQueryResult::round {}", i));
            let ri0 = reverse_bits(left_index, num_vars + log_rate - i);

            let x0 = E::from(query_point::<E>(
                1 << (num_vars + log_rate - i),
                ri0,
                num_vars + log_rate - i - 1,
                &mut cipher,
            ));
            let x1 = -x0;

            let res = interpolate2([(x0, curr_left), (x1, curr_right)], fold_challenges[i]);

            let next_index = right_index >> 1;
            let next_oracle_value = if i < num_rounds - 1 {
                right_index = next_index | 1;
                left_index = right_index - 1;
                let next_oracle_query = self.oracle_query.get_inner()[i].clone();
                (curr_left, curr_right) = next_oracle_query.query.codepoints.as_ext();
                if next_index & 1 == 0 {
                    curr_left
                } else {
                    curr_right
                }
            } else {
                // Note that final_codeword has been bit-reversed, so no need to bit-reverse
                // next_index here.
                final_codeword[next_index]
            };
            assert_eq!(res, next_oracle_value, "Failed at round {}", i);
            // end_timer!(round_timer);
        }
        end_timer!(timer);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BatchedSingleQueryResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResult<E>,
    commitments_query: CommitmentsQueryResult<E>,
}

#[derive(Debug, Clone)]
struct BatchedSingleQueryResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    oracle_query: OracleListQueryResultWithMerklePath<E>,
    commitments_query: CommitmentsQueryResultWithMerklePath<E>,
}

impl<E: ExtensionField> BatchedSingleQueryResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_batched_single_query_result(
        batched_single_query_result: BatchedSingleQueryResult<E>,
        oracle_trees: &Vec<MerkleTree<E>>,
        commitments: &Vec<&BasefoldCommitmentWithData<E>>,
    ) -> Self {
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::from_query_and_trees(
                batched_single_query_result.oracle_query,
                |i, j| oracle_trees[i].merkle_path_without_leaf_sibling_or_root(j),
            ),
            commitments_query: CommitmentsQueryResultWithMerklePath::from_query_and_trees(
                batched_single_query_result.commitments_query,
                |i, j| {
                    commitments[i]
                        .codeword_tree
                        .merkle_path_without_leaf_sibling_or_root(j)
                },
            ),
        }
    }

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.oracle_query.write_transcript(transcript);
        self.commitments_query.write_transcript(transcript);
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: &[usize],
        index: usize,
    ) -> Self {
        let num_vars = poly_num_vars.iter().max().unwrap();
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::read_transcript(
                transcript,
                num_rounds,
                *num_vars + log_rate,
                index,
            ),
            commitments_query: CommitmentsQueryResultWithMerklePath::read_transcript_base(
                transcript,
                *num_vars,
                poly_num_vars,
                log_rate,
                index,
            ),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: &[usize],
        index: usize,
    ) -> Self {
        let num_vars = poly_num_vars.iter().max().unwrap();
        Self {
            oracle_query: OracleListQueryResultWithMerklePath::read_transcript(
                transcript,
                num_rounds,
                *num_vars + log_rate,
                index,
            ),
            commitments_query: CommitmentsQueryResultWithMerklePath::read_transcript_ext(
                transcript,
                *num_vars,
                poly_num_vars,
                log_rate,
                index,
            ),
        }
    }

    pub fn check(
        &self,
        fold_challenges: &Vec<E>,
        num_rounds: usize,
        num_vars: usize,
        log_rate: usize,
        final_codeword: &Vec<E>,
        roots: &Vec<Digest<E::BaseField>>,
        comms: &Vec<&BasefoldCommitment<E>>,
        coeffs: &[E],
        mut cipher: ctr::Ctr32LE<aes::Aes128>,
        index: usize,
        hasher: &Hasher<E::BaseField>,
    ) {
        self.oracle_query.check_merkle_paths(roots, hasher);
        self.commitments_query
            .check_merkle_paths(&comms.iter().map(|comm| comm.root()).collect(), hasher);
        // end_timer!(commit_timer);

        let mut curr_left = E::ZERO;
        let mut curr_right = E::ZERO;

        let mut right_index = index | 1;
        let mut left_index = right_index - 1;

        for i in 0..num_rounds {
            // let round_timer = start_timer!(|| format!("BatchedSingleQueryResult::round {}", i));
            let ri0 = reverse_bits(left_index, num_vars + log_rate - i);
            let matching_comms = comms
                .iter()
                .enumerate()
                .filter(|(_, comm)| comm.num_vars().unwrap() == num_vars - i)
                .map(|(index, _)| index)
                .collect_vec();

            matching_comms.iter().for_each(|index| {
                let query = self.commitments_query.get_inner()[*index].query.clone();
                assert_eq!(query.index >> 1, left_index >> 1);
                curr_left += query.left_ext() * coeffs[*index];
                curr_right += query.right_ext() * coeffs[*index];
            });

            let x0: E = E::from(query_point::<E>(
                1 << (num_vars + log_rate - i),
                ri0,
                num_vars + log_rate - i - 1,
                &mut cipher,
            ));
            let x1 = -x0;

            let mut res = interpolate2([(x0, curr_left), (x1, curr_right)], fold_challenges[i]);

            let next_index = right_index >> 1;

            let next_oracle_value = if i < num_rounds - 1 {
                right_index = next_index | 1;
                left_index = right_index - 1;
                let next_oracle_query = &self.oracle_query.get_inner()[i];
                curr_left = next_oracle_query.query.left_ext();
                curr_right = next_oracle_query.query.right_ext();
                if next_index & 1 == 0 {
                    curr_left
                } else {
                    curr_right
                }
            } else {
                // Note that in the last round, res is folded to an element in the final
                // codeword, but has not yet added the committed polynomial evaluations
                // at this position.
                // So we need to repeat the finding and adding procedure here.
                // The reason for the existence of one extra find-and-add is that the number
                // of different polynomial number of variables is one more than the number of
                // rounds.

                let matching_comms = comms
                    .iter()
                    .enumerate()
                    .filter(|(_, comm)| comm.num_vars().unwrap() == num_vars - i - 1)
                    .map(|(index, _)| index)
                    .collect_vec();

                matching_comms.iter().for_each(|index| {
                    let query: CodewordSingleQueryResult<E> =
                        self.commitments_query.get_inner()[*index].query.clone();
                    assert_eq!(query.index >> 1, next_index >> 1);
                    if next_index & 1 == 0 {
                        res += query.left_ext() * coeffs[*index];
                    } else {
                        res += query.right_ext() * coeffs[*index];
                    }
                });

                // Note that final_codeword has been bit-reversed, so no need to bit-reverse
                // next_index here.
                final_codeword[next_index]
            };
            assert_eq!(res, next_oracle_value, "Failed at round {}", i);
            // end_timer!(round_timer);
        }
        // end_timer!(timer);
    }
}

struct BatchedQueriesResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, BatchedSingleQueryResult<E>)>,
}

struct BatchedQueriesResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, BatchedSingleQueryResultWithMerklePath<E>)>,
}

impl<E: ExtensionField> BatchedQueriesResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_batched_query_result(
        batched_query_result: BatchedQueriesResult<E>,
        oracle_trees: &Vec<MerkleTree<E>>,
        commitments: &Vec<&BasefoldCommitmentWithData<E>>,
    ) -> Self {
        Self {
            inner: batched_query_result
                .inner
                .into_iter()
                .map(|(i, q)| {
                    (
                        i,
                        BatchedSingleQueryResultWithMerklePath::from_batched_single_query_result(
                            q,
                            oracle_trees,
                            commitments,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.inner
            .iter()
            .for_each(|(_, q)| q.write_transcript(transcript));
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: &[usize],
        indices: &[usize],
    ) -> Self {
        Self {
            inner: indices
                .iter()
                .map(|index| {
                    (
                        *index,
                        BatchedSingleQueryResultWithMerklePath::read_transcript_base(
                            transcript,
                            num_rounds,
                            log_rate,
                            poly_num_vars,
                            *index,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: &[usize],
        indices: &[usize],
    ) -> Self {
        Self {
            inner: indices
                .iter()
                .map(|index| {
                    (
                        *index,
                        BatchedSingleQueryResultWithMerklePath::read_transcript_ext(
                            transcript,
                            num_rounds,
                            log_rate,
                            poly_num_vars,
                            *index,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn check(
        &self,
        fold_challenges: &Vec<E>,
        num_rounds: usize,
        num_vars: usize,
        log_rate: usize,
        final_codeword: &Vec<E>,
        roots: &Vec<Digest<E::BaseField>>,
        comms: &Vec<&BasefoldCommitment<E>>,
        coeffs: &[E],
        cipher: ctr::Ctr32LE<aes::Aes128>,
        hasher: &Hasher<E::BaseField>,
    ) {
        let timer = start_timer!(|| "BatchedQueriesResult::check");
        self.inner.par_iter().for_each(|(index, query)| {
            query.check(
                fold_challenges,
                num_rounds,
                num_vars,
                log_rate,
                final_codeword,
                roots,
                comms,
                coeffs,
                cipher.clone(),
                *index,
                hasher,
            );
        });
        end_timer!(timer);
    }
}

struct QueriesResult<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, SingleQueryResult<E>)>,
}

struct QueriesResultWithMerklePath<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    inner: Vec<(usize, SingleQueryResultWithMerklePath<E>)>,
}

impl<E: ExtensionField> QueriesResultWithMerklePath<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub fn from_query_result(
        query_result: QueriesResult<E>,
        oracle_trees: &Vec<MerkleTree<E>>,
        commitment: &BasefoldCommitmentWithData<E>,
    ) -> Self {
        Self {
            inner: query_result
                .inner
                .into_iter()
                .map(|(i, q)| {
                    (
                        i,
                        SingleQueryResultWithMerklePath::from_single_query_result(
                            q,
                            oracle_trees,
                            commitment,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn write_transcript(&self, transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>) {
        self.inner
            .iter()
            .for_each(|(_, q)| q.write_transcript(transcript));
    }

    pub fn read_transcript_base(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: usize,
        indices: &[usize],
    ) -> Self {
        Self {
            inner: indices
                .iter()
                .map(|index| {
                    (
                        *index,
                        SingleQueryResultWithMerklePath::read_transcript_base(
                            transcript,
                            num_rounds,
                            log_rate,
                            poly_num_vars,
                            *index,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn read_transcript_ext(
        transcript: &mut impl TranscriptRead<Digest<E::BaseField>, E>,
        num_rounds: usize,
        log_rate: usize,
        poly_num_vars: usize,
        indices: &[usize],
    ) -> Self {
        Self {
            inner: indices
                .iter()
                .map(|index| {
                    (
                        *index,
                        SingleQueryResultWithMerklePath::read_transcript_ext(
                            transcript,
                            num_rounds,
                            log_rate,
                            poly_num_vars,
                            *index,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub fn check(
        &self,
        fold_challenges: &Vec<E>,
        num_rounds: usize,
        num_vars: usize,
        log_rate: usize,
        final_codeword: &Vec<E>,
        roots: &Vec<Digest<E::BaseField>>,
        comm: &BasefoldCommitment<E>,
        cipher: ctr::Ctr32LE<aes::Aes128>,
        hasher: &Hasher<E::BaseField>,
    ) {
        let timer = start_timer!(|| "QueriesResult::check");
        self.inner.par_iter().for_each(|(index, query)| {
            query.check(
                fold_challenges,
                num_rounds,
                num_vars,
                log_rate,
                final_codeword,
                roots,
                comm,
                cipher.clone(),
                *index,
                hasher,
            );
        });
        end_timer!(timer);
    }
}

fn batch_query_phase<E: ExtensionField>(
    transcript: &mut impl TranscriptWrite<Digest<E::BaseField>, E>,
    codeword_size: usize,
    comms: &[&BasefoldCommitmentWithData<E>],
    oracles: &Vec<Vec<E>>,
    num_verifier_queries: usize,
) -> BatchedQueriesResult<E>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    let queries = transcript.squeeze_challenges(num_verifier_queries);

    // Transform the challenge queries from field elements into integers
    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| ext_to_usize(x_index) % codeword_size)
        .collect_vec();

    BatchedQueriesResult {
        inner: queries_usize
            .par_iter()
            .map(|x_index| {
                (
                    *x_index,
                    batch_basefold_get_query::<E>(comms, &oracles, codeword_size, *x_index),
                )
            })
            .collect(),
    }
}

fn verifier_query_phase<E: ExtensionField>(
    queries: &QueriesResultWithMerklePath<E>,
    sum_check_messages: &Vec<Vec<E>>,
    fold_challenges: &Vec<E>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    final_message: &Vec<E>,
    roots: &Vec<Digest<E::BaseField>>,
    comm: &BasefoldCommitment<E>,
    partial_eq: &[E],
    rng: ChaCha8Rng,
    eval: &E,
    hasher: &Hasher<E::BaseField>,
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Verifier query phase");

    let encode_timer = start_timer!(|| "Encode final codeword");
    let mut message = final_message.clone();
    interpolate_over_boolean_hypercube(&mut message);
    let mut final_codeword = encode_rs_basecode(&message, 1 << log_rate, message.len());
    assert_eq!(final_codeword.len(), 1);
    let mut final_codeword = final_codeword.remove(0);
    reverse_index_bits_in_place(&mut final_codeword);
    end_timer!(encode_timer);

    // For computing the weights on the fly, because the verifier is incapable of storing
    // the weights.
    let aes_timer = start_timer!(|| "Initialize AES");
    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    let mut rng = rng.clone();
    rng.set_word_pos(0);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
    let cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );
    end_timer!(aes_timer);

    queries.check(
        fold_challenges,
        num_rounds,
        num_vars,
        log_rate,
        &final_codeword,
        roots,
        comm,
        cipher,
        hasher,
    );

    let final_timer = start_timer!(|| "Final checks");
    assert_eq!(eval, &degree_2_zero_plus_one(&sum_check_messages[0]));

    // The sum-check part of the protocol
    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            degree_2_eval(&sum_check_messages[i], fold_challenges[i]),
            degree_2_zero_plus_one(&sum_check_messages[i + 1])
        );
    }

    // Finally, the last sumcheck poly evaluation should be the same as the sum of the polynomial
    // sent from the prover
    assert_eq!(
        degree_2_eval(
            &sum_check_messages[fold_challenges.len() - 1],
            fold_challenges[fold_challenges.len() - 1]
        ),
        inner_product(final_message, partial_eq)
    );
    end_timer!(final_timer);

    end_timer!(timer);
}

fn batch_verifier_query_phase<E: ExtensionField>(
    queries: &BatchedQueriesResultWithMerklePath<E>,
    sum_check_messages: &Vec<Vec<E>>,
    fold_challenges: &Vec<E>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    final_message: &Vec<E>,
    roots: &Vec<Digest<E::BaseField>>,
    comms: &Vec<&BasefoldCommitment<E>>,
    coeffs: &[E],
    partial_eq: &[E],
    rng: ChaCha8Rng,
    eval: &E,
    hasher: &Hasher<E::BaseField>,
) where
    E::BaseField: Serialize + DeserializeOwned,
{
    let timer = start_timer!(|| "Verifier batch query phase");
    let encode_timer = start_timer!(|| "Encode final codeword");
    let mut message = final_message.clone();
    interpolate_over_boolean_hypercube(&mut message);
    let mut final_codeword = encode_rs_basecode(&message, 1 << log_rate, message.len());
    assert_eq!(final_codeword.len(), 1);
    let mut final_codeword = final_codeword.remove(0);
    reverse_index_bits_in_place(&mut final_codeword);
    end_timer!(encode_timer);

    // For computing the weights on the fly, because the verifier is incapable of storing
    // the weights.
    let aes_timer = start_timer!(|| "Initialize AES");
    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    let mut rng = rng.clone();
    rng.set_word_pos(0);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
    let cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );
    end_timer!(aes_timer);

    queries.check(
        fold_challenges,
        num_rounds,
        num_vars,
        log_rate,
        &final_codeword,
        roots,
        comms,
        coeffs,
        cipher,
        hasher,
    );

    #[allow(unused)]
    let final_timer = start_timer!(|| "Final checks");
    assert_eq!(eval, &degree_2_zero_plus_one(&sum_check_messages[0]));

    // The sum-check part of the protocol
    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            degree_2_eval(&sum_check_messages[i], fold_challenges[i]),
            degree_2_zero_plus_one(&sum_check_messages[i + 1])
        );
    }

    // Finally, the last sumcheck poly evaluation should be the same as the sum of the polynomial
    // sent from the prover
    assert_eq!(
        degree_2_eval(
            &sum_check_messages[fold_challenges.len() - 1],
            fold_challenges[fold_challenges.len() - 1]
        ),
        inner_product(final_message, partial_eq)
    );
    end_timer!(final_timer);
    end_timer!(timer);
}

fn get_table_aes<E: ExtensionField, Rng: RngCore + Clone>(
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
        .map(|chunk| from_raw_bytes::<E>(&chunk.to_vec()))
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

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        basefold::Basefold,
        test::{run_batch_commit_open_verify, run_commit_open_verify},
        util::transcript::PoseidonTranscript,
    };
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    use crate::BasefoldExtParams;

    type PcsGoldilocks = Basefold<GoldilocksExt2, Five>;

    #[derive(Debug)]
    pub struct Five {}

    impl BasefoldExtParams for Five {
        fn get_reps() -> usize {
            return 260;
        }

        fn get_rate() -> usize {
            return 3;
        }

        fn get_basecode() -> usize {
            return 7;
        }
    }

    pub fn p_i<F: Field>(evals: &Vec<F>, eq: &Vec<F>) -> Vec<F> {
        if evals.len() == 1 {
            return vec![evals[0], evals[0], evals[0]];
        }
        // evals coeffs
        let mut coeffs = vec![F::ZERO, F::ZERO, F::ZERO];
        let mut i = 0;
        while i < evals.len() {
            coeffs[0] += evals[i] * eq[i];
            coeffs[1] += evals[i + 1] * eq[i] + evals[i] * eq[i + 1];
            coeffs[2] += evals[i + 1] * eq[i + 1];
            i += 2;
        }

        coeffs
    }

    // helper function
    fn rand_vec<F: Field>(size: usize, mut rng: &mut ChaCha8Rng) -> Vec<F> {
        (0..size).map(|_| F::random(&mut rng)).collect()
    }

    #[test]
    fn time_rs_code() {
        use rand::rngs::OsRng;

        let poly = DenseMultilinearExtension::random(20, &mut OsRng);

        encode_field_type_rs_basecode::<GoldilocksExt2>(&poly.evaluations, 2, 64);
    }

    #[test]
    fn test_sumcheck() {
        let i = 25;
        let mut rng = ChaCha8Rng::from_entropy();
        let evals = rand_vec::<Goldilocks>(1 << i, &mut rng);
        let eq = rand_vec::<Goldilocks>(1 << i, &mut rng);
        let coeffs1 = p_i(&evals, &eq);
        let coeffs2 = parallel_pi(&evals, &eq);
        assert_eq!(coeffs1, coeffs2);
    }

    // #[test]
    // fn commit_open_verify() {
    //     run_commit_open_verify::<_, Pcs, Blake2sTranscript<_>>();
    // }

    #[test]
    fn commit_open_verify_goldilocks_base() {
        // Challenge is over extension field, poly over the base field
        run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<GoldilocksExt2>>(
            true,
        );
    }

    #[test]
    fn commit_open_verify_goldilocks_2() {
        // Both challenge and poly are over extension field
        run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<_>>(false);
    }

    // #[test]
    // fn batch_commit_open_verify() {
    //     run_batch_commit_open_verify::<_, Pcs, Blake2sTranscript<_>>();
    // }

    #[test]
    fn batch_commit_open_verify_goldilocks_base() {
        // Both challenge and poly are over base field
        run_batch_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocks,
            PoseidonTranscript<GoldilocksExt2>,
        >(true);
    }

    #[test]
    fn batch_commit_open_verify_goldilocks_2() {
        // Both challenge and poly are over extension field
        run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<_>>(false);
    }

    #[derive(Debug)]
    pub struct BasefoldExtParamsForGKRTest {}

    impl BasefoldExtParams for BasefoldExtParamsForGKRTest {
        fn get_reps() -> usize {
            return 260;
        }

        fn get_rate() -> usize {
            return 3;
        }

        fn get_basecode() -> usize {
            return 3;
        }
    }
    // type PcsGoldilocksForGKRTest = Basefold<Goldilocks, BasefoldExtParamsForGKRTest>;

    // #[test]
    // fn test_with_gkr_for_goldilocks() {
    //     test_with_gkr::<Goldilocks, PcsGoldilocksForGKRTest, PoseidonTranscript<_>>();
    // }
}
