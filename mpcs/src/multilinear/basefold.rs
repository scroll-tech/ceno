use crate::util::code;
use crate::util::merkle_tree::{MerklePathWithoutLeafOrRoot, MerkleTree};
use crate::Commitment;
use crate::{
    multilinear::validate_input,
    poly::{multilinear::MultilinearPolynomial, Polynomial},
    util::{
        arithmetic::{horner, inner_product, steps, BatchInvert, Field, PrimeField},
        code::LinearCodes,
        expression::{Expression, Query, Rotation},
        hash::{Hash, Output},
        log2_strict,
        new_fields::{Mersenne127, Mersenne61},
        transcript::{FieldTranscript, TranscriptRead, TranscriptWrite},
        Deserialize, DeserializeOwned, Itertools, Serialize,
    },
    AdditiveCommitment, Error, Evaluation, Point, PolynomialCommitmentScheme,
};
use crate::{
    sum_check::{
        classic::{ClassicSumCheck, CoefficientsProver},
        eq_xy_eval, SumCheck as _, VirtualPolynomial,
    },
    util::num_of_bytes,
};
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use core::fmt::Debug;
use core::ptr::addr_of;
use ctr;
use ff::BatchInverter;
use generic_array::GenericArray;
use halo2_curves::bn256::{Bn256, Fr};
use rayon::iter::IntoParallelIterator;
use std::{collections::HashMap, iter, ops::Deref, time::Instant};

use multilinear_extensions::virtual_poly::build_eq_x_r_vec;

use crate::util::plonky2_util::{reverse_bits, reverse_index_bits_in_place};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha12Rng, ChaCha8Rng,
};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice, ParallelSliceMut,
};
use std::{borrow::Cow, marker::PhantomData, mem::size_of, slice};
type SumCheck<F> = ClassicSumCheck<CoefficientsProver<F>>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldParams<F: PrimeField> {
    log_rate: usize,
    num_verifier_queries: usize,
    max_num_vars: usize,
    table_w_weights: Vec<Vec<(F, F)>>,
    table: Vec<Vec<F>>,
    rng: ChaCha8Rng,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldProverParams<F: PrimeField> {
    log_rate: usize,
    table_w_weights: Vec<Vec<(F, F)>>,
    table: Vec<Vec<F>>,
    num_verifier_queries: usize,
    max_num_vars: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldVerifierParams<F: PrimeField> {
    rng: ChaCha8Rng,
    max_num_vars: usize,
    log_rate: usize,
    num_verifier_queries: usize,
    table_w_weights: Vec<Vec<(F, F)>>,
}

/// A polynomial commitment together with all the data (e.g., the codeword, and Merkle tree)
/// used to generate this commitment and for assistant in opening
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct BasefoldCommitmentWithData<F, H: Hash> {
    codeword_tree: MerkleTree<F, H>,
    bh_evals: Vec<F>,
    num_vars: usize,
}

impl<F: PrimeField, H: Hash> BasefoldCommitmentWithData<F, H> {
    pub fn to_commitment(&self) -> BasefoldCommitment<H> {
        BasefoldCommitment::new(self.codeword_tree.root(), self.num_vars)
    }

    pub fn get_root_ref(&self) -> &Output<H> {
        self.codeword_tree.root_ref()
    }

    pub fn get_codeword(&self) -> &Vec<F> {
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

    pub fn get_codeword_entry(&self, index: usize) -> &F {
        self.codeword_tree.get_leaf(index)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct BasefoldCommitment<H: Hash> {
    root: Output<H>,
    num_vars: Option<usize>,
}

impl<H: Hash> BasefoldCommitment<H> {
    fn new(root: Output<H>, num_vars: usize) -> Self {
        Self {
            root,
            num_vars: Some(num_vars),
        }
    }

    fn from_root(root: Output<H>) -> Self {
        Self {
            root,
            num_vars: None,
        }
    }

    fn root(&self) -> Output<H> {
        self.root.clone()
    }

    fn num_vars(&self) -> Option<usize> {
        self.num_vars
    }
}

impl<F: PrimeField, H: Hash> PartialEq for BasefoldCommitmentWithData<F, H> {
    fn eq(&self, other: &Self) -> bool {
        self.get_codeword().eq(other.get_codeword()) && self.bh_evals.eq(&other.bh_evals)
    }
}

impl<F: PrimeField, H: Hash> Eq for BasefoldCommitmentWithData<F, H> {}

pub trait BasefoldExtParams: Debug {
    fn get_reps() -> usize;

    fn get_rate() -> usize;

    fn get_basecode() -> usize;
}

#[derive(Debug)]
pub struct Basefold<F: PrimeField, H: Hash, V: BasefoldExtParams>(PhantomData<(F, H, V)>);

impl<F: PrimeField, H: Hash, V: BasefoldExtParams> Clone for Basefold<F, H, V> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<H: Hash> AsRef<[Output<H>]> for BasefoldCommitment<H> {
    fn as_ref(&self) -> &[Output<H>] {
        let root = &self.root;
        slice::from_ref(root)
    }
}

impl<F: PrimeField, H: Hash> AsRef<[Output<H>]> for BasefoldCommitmentWithData<F, H> {
    fn as_ref(&self) -> &[Output<H>] {
        let root = self.get_root_ref();
        slice::from_ref(root)
    }
}

impl<F: PrimeField, H: Hash> AdditiveCommitment<F> for BasefoldCommitmentWithData<F, H> {
    fn sum_with_scalar<'a>(
        scalars: impl IntoIterator<Item = &'a F> + 'a,
        bases: impl IntoIterator<Item = &'a Self> + 'a,
    ) -> Self {
        let bases = bases.into_iter().collect_vec();

        let scalars = scalars.into_iter().collect_vec();
        let bases = bases.into_iter().collect_vec();
        let k = bases[0].bh_evals.len();
        let num_vars = log2_strict(k);

        let mut new_codeword = vec![F::ZERO; bases[0].codeword_size()];
        new_codeword
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, mut c)| {
                for j in 0..bases.len() {
                    *c += *scalars[j] * bases[j].get_codeword_entry(i);
                }
            });

        let mut new_bh_eval = vec![F::ZERO; k];
        new_bh_eval
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, mut c)| {
                for j in 0..bases.len() {
                    *c += *scalars[j] * bases[j].bh_evals[i];
                }
            });

        let tree = MerkleTree::<F, H>::from_leaves(new_codeword);

        Self {
            bh_evals: Vec::new(),
            codeword_tree: tree,
            num_vars,
        }
    }
}

impl<F, H, V> PolynomialCommitmentScheme<F> for Basefold<F, H, V>
where
    F: PrimeField + Serialize + DeserializeOwned,
    H: Hash,
    V: BasefoldExtParams,
{
    type Param = BasefoldParams<F>;
    type ProverParam = BasefoldProverParams<F>;
    type VerifierParam = BasefoldVerifierParams<F>;
    type Polynomial = MultilinearPolynomial<F>;
    type CommitmentWithData = BasefoldCommitmentWithData<F, H>;
    type Commitment = BasefoldCommitment<H>;
    type CommitmentChunk = Output<H>;

    fn setup(poly_size: usize, _: usize, rng: impl RngCore) -> Result<Self::Param, Error> {
        let log_rate = V::get_rate();
        let mut test_rng = ChaCha8Rng::from_entropy();
        let (table_w_weights, table) = get_table_aes(poly_size, log_rate, &mut test_rng);

        Ok(BasefoldParams {
            log_rate,
            num_verifier_queries: V::get_reps(),
            max_num_vars: log2_strict(poly_size),
            table_w_weights,
            table,
            rng: test_rng.clone(),
        })
    }

    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        let mut rounds = param.max_num_vars;
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
                // Why not trim the weights using poly_size? And is the verifier really
                // able to hold all these weights?
                table_w_weights: param.table_w_weights.clone(),
            },
        ))
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
    ) -> Result<Self::CommitmentWithData, Error> {
        // bh_evals is just a copy of poly.evals().
        // Note that this function implicitly assumes that the size of poly.evals() is a
        // power of two. Otherwise, the function crashes with index out of bound.
        let (coeffs, mut bh_evals) =
            interpolate_over_boolean_hypercube_with_copy(&poly.evals().to_vec());

        let num_vars = log2_strict(bh_evals.len());

        // Split the input into chunks of message size, encode each message, and return the codewords
        let mut basecode = encode_rs_basecode(&coeffs, 1 << pp.log_rate, 1 << V::get_basecode());

        // Apply the recursive definition of the BaseFold code to the list of base codewords,
        // and produce the final codeword
        let mut codeword = evaluate_over_foldable_domain_generic_basecode(
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
        reverse_index_bits_in_place(&mut bh_evals);
        reverse_index_bits_in_place(&mut codeword);

        // Compute and store all the layers of the Merkle tree
        let codeword_tree = MerkleTree::<F, H>::from_leaves(codeword);

        Ok(Self::CommitmentWithData {
            codeword_tree,
            bh_evals,
            num_vars,
        })
    }

    fn batch_commit_and_write<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error>
    where
        Self::Polynomial: 'a,
    {
        let comms = Self::batch_commit(pp, polys)?;
        comms.iter().for_each(|comm| {
            transcript.write_commitment(comm.get_root_ref());
        });
        Ok(comms)
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error> {
        let polys_vec: Vec<&Self::Polynomial> = polys.into_iter().map(|poly| poly).collect();
        polys_vec
            .par_iter()
            .map(|poly| Self::commit(pp, poly))
            .collect()
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::CommitmentWithData,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let cp = Instant::now();
        let (trees, sum_check_oracles, mut oracles, bh_evals, eq, eval) = commit_phase(
            &point,
            &comm,
            transcript,
            poly.num_vars(),
            poly.num_vars() - V::get_basecode(),
            &pp.table_w_weights,
        );

        let qp = Instant::now();

        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let (queried_els, queries_usize_) =
            query_phase(transcript, &comm, &oracles, pp.num_verifier_queries);

        // a proof consists of roots, merkle paths, query paths, sum check oracles, eval, and final oracle
        //write sum check oracles

        transcript
            .write_field_elements(&sum_check_oracles.into_iter().flatten().collect::<Vec<F>>()); //write sumcheck
        transcript.write_field_element(&eval); //write eval

        transcript.write_field_elements(&bh_evals); //write bh_evals
        transcript.write_field_elements(&eq); //write eq (why? can't the verifier evaluate itself?)

        //write final oracle
        let mut final_oracle = oracles.pop().unwrap();
        transcript.write_field_elements(&final_oracle);

        //write query paths
        queried_els
            .iter()
            .map(|q| &q.0)
            .flatten()
            .for_each(|query| {
                transcript.write_field_element(&query.0);
                transcript.write_field_element(&query.1);
            });

        //write merkle paths
        queried_els.iter().for_each(|query| {
            let indices = &query.1;
            indices.into_iter().enumerate().for_each(|(i, q)| {
                if (i == 0) {
                    write_merkle_path::<H, F>(
                        &comm
                            .codeword_tree
                            .merkle_path_without_leaf_sibling_or_root(*q),
                        transcript,
                    );
                } else {
                    write_merkle_path::<H, F>(
                        &trees[i - 1].merkle_path_without_leaf_sibling_or_root(*q),
                        transcript,
                    );
                }
            })
        });

        Ok(())
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::CommitmentWithData>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        use std::env;

        let polys = polys.into_iter().collect_vec();
        let comms = comms.into_iter().collect_vec();

        validate_input("batch open", pp.max_num_vars, polys.clone(), points)?;

        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(batch_size_log);

        // Use eq(X,t) where t is random to batch the different evaluation queries.
        // Note that this is a small polynomial (only batch_size) compared to the polynomials
        // to open.
        let eq_xt = Self::Polynomial::eq_xy(&t);
        // Merge the polynomials for every point. One merged polynomial for each point.
        let merged_polys = evals.iter().zip(eq_xt.evals().iter()).fold(
            // This folding will generate a vector of |points| pairs of (scalar, polynomial)
            // The polynomials are initialized to zero, and the scalars are initialized to one
            vec![(F::ONE, Cow::<Self::Polynomial>::default()); points.len()],
            |mut merged_polys, (eval, eq_xt_i)| {
                // For each polynomial to open, eval.point() specifies which point it is to be opened at.
                if merged_polys[eval.point()].1.is_zero() {
                    // If the accumulator for this point is still the zero polynomial,
                    // directly assign the random coefficient and the polynomial to open to
                    // this accumulator
                    merged_polys[eval.point()] = (*eq_xt_i, Cow::Borrowed(polys[eval.poly()]));
                } else {
                    // If the accumulator is unempty now, first force its scalar to 1, i.e.,
                    // make (scalar, polynomial) to (1, scalar * polynomial)
                    let coeff = merged_polys[eval.point()].0;
                    if coeff != F::ONE {
                        merged_polys[eval.point()].0 = F::ONE;
                        *merged_polys[eval.point()].1.to_mut() *= &coeff;
                    }
                    // Equivalent to merged_poly += poly * batch_coeff. Note that
                    // add_assign_mixed_with_coeff allows adding two polynomials with
                    // different variables, and the result has the same number of vars
                    // with the larger one of the two added polynomials.
                    (*merged_polys[eval.point()].1.to_mut())
                        .add_assign_mixed_with_coeff(polys[eval.poly()], eq_xt_i);

                    // Note that once the scalar in the accumulator becomes ONE, it will remain
                    // to be ONE forever.
                }
                merged_polys
            },
        );

        let mut points = points.to_vec();
        // Note that merged_polys may contain polynomials of different number of variables.
        // Resize the evaluation points so that the size match.
        merged_polys.iter().enumerate().for_each(|(i, (_, poly))| {
            assert!(points[i].len() >= poly.num_vars());
            points[i].resize(poly.num_vars(), F::ZERO)
        });

        let unique_merged_polys = merged_polys
            .iter()
            .unique_by(|(_, poly)| addr_of!(*poly.deref()))
            .collect_vec();
        let unique_merged_poly_indices = unique_merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (_, poly))| (addr_of!(*poly.deref()), idx))
            .collect::<HashMap<_, _>>();
        let expression = merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (scalar, poly))| {
                let poly = unique_merged_poly_indices[&addr_of!(*poly.deref())];
                Expression::<F>::eq_xy(idx)
                    * Expression::Polynomial(Query::new(poly, Rotation::cur()))
                    * scalar
            })
            .sum();
        let virtual_poly = VirtualPolynomial::new(
            &expression,
            unique_merged_polys.iter().map(|(_, poly)| poly.deref()),
            &[],
            points.as_slice(),
        );
        // virtual_poly is a polynomial expression that may also involve polynomials with different
        // number of variables. Use the maximal number of variables in the sum-check.
        let num_vars = unique_merged_polys
            .iter()
            .map(|(_, poly)| poly.num_vars())
            .max()
            .unwrap();
        let tilde_gs_sum =
            inner_product(evals.iter().map(Evaluation::value), &eq_xt[..evals.len()]);
        let (challenges, poly_evals) =
            SumCheck::prove(&(), num_vars, virtual_poly, tilde_gs_sum, transcript)?;

        // Now the verifier has obtained the new target sum, and is able to compute the random
        // linear coefficients, and is able to evaluate eq_xy(point) for each poly to open.
        // The remaining tasks for the prover is to prove that
        // poly_evals[i] = poly[i](challenges[..poly[i].num_vars]) for every i.

        // More precisely, prove sum_i coeffs[i] poly_evals[i] is equal to
        // the new target sum, where coeffs is computed as follows
        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&challenges, point))
            .collect_vec();
        let mut coeffs = vec![F::ZERO; comms.len()];
        evals
            .iter()
            .enumerate()
            .for_each(|(i, eval)| coeffs[eval.poly()] += eq_xy_evals[eval.point()] * eq_xt[i]);
        // Note that the verifier can also compute these coeffs locally, so no need to pass
        // them to the transcript.

        let point = challenges;

        let (trees, sum_check_oracles, mut oracles) = batch_commit_phase(
            &point,
            comms.as_slice(),
            transcript,
            num_vars,
            num_vars - V::get_basecode(),
            &pp.table_w_weights,
            pp.log_rate,
            coeffs.as_slice(),
        );

        let (queried_els, queries_usize) = batch_query_phase(
            transcript,
            1 << (num_vars + pp.log_rate),
            comms.as_slice(),
            &oracles,
            pp.num_verifier_queries,
        );

        let merkle_paths: Vec<Vec<MerklePathWithoutLeafOrRoot<H>>> = queried_els
            .iter()
            .map(|query| {
                let (oracle_queries, poly_queries) = query;
                oracle_queries
                    .into_iter()
                    .enumerate()
                    .map(|(i, query_result)| {
                        trees[i].merkle_path_without_leaf_sibling_or_root(query_result.index)
                    })
                    .chain(
                        poly_queries
                            .into_iter()
                            .enumerate()
                            .map(|(i, query_result)| {
                                comms[i]
                                    .codeword_tree
                                    .merkle_path_without_leaf_sibling_or_root(query_result.index)
                            }),
                    )
                    .collect()
            })
            .collect();

        //write oracle query results
        queried_els
            .iter()
            .map(|q| &q.0)
            .flatten()
            .for_each(|query| {
                transcript.write_field_element(&query.left);
                transcript.write_field_element(&query.right);
            });

        //write poly query results
        queried_els
            .iter()
            .map(|q| &q.1)
            .flatten()
            .for_each(|query| {
                transcript.write_field_element(&query.left);
                transcript.write_field_element(&query.right);
            });

        //write merkle paths
        merkle_paths.iter().flatten().for_each(|path| {
            write_merkle_path(path, transcript);
        });

        Ok(())
    }

    fn read_commitments(
        _: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        let roots = transcript.read_commitments(num_polys).unwrap();

        Ok(roots
            .iter()
            .map(|r| BasefoldCommitment::from_root(r.clone()))
            .collect_vec())
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let field_size = 255;
        let num_vars = point.len();
        let n = (1 << (num_vars + vp.log_rate));
        let num_rounds = num_vars - V::get_basecode();
        //read first $(num_var - 1) commitments

        let mut fold_challenges: Vec<F> = Vec::with_capacity(vp.max_num_vars);
        let mut size = 0;
        let mut roots = Vec::new();
        for i in 0..num_rounds {
            roots.push(transcript.read_commitment().unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
        }
        size = size + 256 * num_rounds;
        //read last commitment (and abandoned), so why write it in the proving side?
        transcript.read_commitment().unwrap();

        let mut query_challenges = transcript.squeeze_challenges(vp.num_verifier_queries);
        //read sum check oracles
        let mut sum_check_oracles: Vec<Vec<F>> = transcript
            .read_field_elements(3 * (num_rounds + 1))
            .unwrap()
            .chunks(3)
            .map(|c| c.to_vec())
            .collect_vec();

        size = size + field_size * (3 * (num_rounds + 1)); // dont need last sumcheck oracle in proof
                                                           //read eval

        // TODO: This eval shadows the eval passed in from the argument.
        // this should not be desired
        let eval = &transcript.read_field_element().unwrap(); //do not need eval in proof

        let mut bh_evals = Vec::new();
        let mut eq = Vec::new();
        bh_evals = transcript
            .read_field_elements(1 << V::get_basecode())
            .unwrap();
        eq = transcript
            .read_field_elements(1 << V::get_basecode())
            .unwrap();
        size = size + field_size * (bh_evals.len() + eq.len());
        //read final oracle
        let mut final_oracle = transcript
            .read_field_elements(1 << (vp.max_num_vars - num_rounds + vp.log_rate))
            .unwrap();

        size = size + field_size * final_oracle.len();
        //read query paths
        let num_queries = vp.num_verifier_queries * 2 * (num_rounds + 1);

        let all_qs = transcript.read_field_elements(num_queries).unwrap();

        size = size + (num_queries - 2) * field_size;
        //        println!("size for all iop queries {:?}", size);

        let i_qs = all_qs.chunks((num_rounds + 1) * 2).collect_vec();

        assert_eq!(i_qs.len(), vp.num_verifier_queries);

        let mut queries = i_qs.iter().map(|q| q.chunks(2).collect_vec()).collect_vec();

        assert_eq!(queries.len(), vp.num_verifier_queries);

        //read merkle paths

        let mut query_merkle_paths: Vec<Vec<Vec<Vec<Output<H>>>>> =
            Vec::with_capacity(vp.num_verifier_queries);
        let query_merkle_paths: Vec<Vec<Vec<Vec<Output<H>>>>> = (0..vp.num_verifier_queries)
            .into_iter()
            .map(|i| {
                let mut merkle_paths: Vec<Vec<Vec<Output<H>>>> = Vec::with_capacity(num_rounds + 1);
                for round in 0..(num_rounds + 1) {
                    let mut merkle_path: Vec<Output<H>> = transcript
                        .read_commitments(2 * (num_vars - round + vp.log_rate - 1))
                        .unwrap();
                    size = size + 256 * (2 * (num_vars - round + vp.log_rate - 1));

                    let chunked_path: Vec<Vec<Output<H>>> =
                        merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                    merkle_paths.push(chunked_path);
                }
                merkle_paths
            })
            .collect();

        verifier_query_phase::<F, H>(
            &query_challenges,
            &query_merkle_paths,
            &sum_check_oracles,
            &fold_challenges,
            &queries,
            num_rounds,
            num_vars,
            vp.log_rate,
            &roots,
            vp.rng.clone(),
            &eval,
        );

        virtual_open(
            num_vars,
            num_rounds,
            &mut eq,
            &mut bh_evals,
            &mut final_oracle,
            point,
            &mut fold_challenges,
            &vp.table_w_weights,
            &mut sum_check_oracles,
        );
        Ok(())
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        use std::env;
        //	let key = "RAYON_NUM_THREADS";
        //	env::set_var(key, "32");
        let comms = comms.into_iter().collect_vec();
        let num_vars = points.iter().map(|point| point.len()).max().unwrap();
        let num_rounds = num_vars - V::get_basecode();
        validate_input("batch verify", vp.max_num_vars, [], points)?;
        let mut poly_num_vars = vec![0usize; comms.len()];
        evals
            .iter()
            .for_each(|eval| poly_num_vars[eval.poly()] = points[eval.point()].len());
        assert!(poly_num_vars.iter().min().unwrap() >= &V::get_basecode());

        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(batch_size_log);

        let eq_xt = MultilinearPolynomial::eq_xy(&t);
        let tilde_gs_sum =
            inner_product(evals.iter().map(Evaluation::value), &eq_xt[..evals.len()]);

        let (new_target_sum, verify_point) =
            SumCheck::verify(&(), num_vars, 2, tilde_gs_sum, transcript)?;

        // Now the goal is to use the BaseFold to check the new target sum. Note that this time
        // we only have one eq polynomial in the sum-check.
        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&verify_point, point))
            .collect_vec();
        let mut coeffs = vec![F::ZERO; comms.len()];
        evals
            .iter()
            .enumerate()
            .for_each(|(i, eval)| coeffs[eval.poly()] += eq_xy_evals[eval.point()] * eq_xt[i]);

        //start of verify
        let n = (1 << (num_vars + vp.log_rate));
        //read first $(num_var - 1) commitments
        let mut sumcheck_messages = Vec::with_capacity(num_rounds);
        let mut roots: Vec<Output<H>> = Vec::with_capacity(num_rounds - 1);
        let mut fold_challenges: Vec<F> = Vec::with_capacity(num_rounds);
        for i in 0..num_rounds {
            sumcheck_messages.push(transcript.read_field_elements(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
            if i < num_rounds - 1 {
                roots.push(transcript.read_commitment().unwrap());
            }
        }
        let final_message = transcript
            .read_field_elements(1 << V::get_basecode())
            .unwrap();

        let mut query_challenges = transcript.squeeze_challenges(vp.num_verifier_queries);

        let mut queries = Vec::with_capacity(vp.num_verifier_queries);
        let mut count = 0;
        for i in 0..vp.num_verifier_queries {
            let mut oracle_queries = Vec::with_capacity(num_rounds - 1);
            for j in 0..num_rounds - 1 {
                let queries = transcript.read_field_elements(2).unwrap();
                oracle_queries.push(queries);
            }
            queries.push(oracle_queries);

            let mut comms_queries = Vec::with_capacity(comms.len());
            for j in 0..comms.len() {
                let queries = transcript.read_field_elements(2).unwrap();
                comms_queries.push(queries);
            }

            queries.push(comms_queries);
        }

        //read merkle paths
        let mut batch_paths = Vec::with_capacity(vp.num_verifier_queries);
        let mut count = 0;
        for i in 0..vp.num_verifier_queries {
            let mut oracle_merkle_paths = Vec::with_capacity(num_rounds - 1);
            for j in 0..num_rounds - 1 {
                let merkle_path = transcript
                    .read_commitments(2 * (num_vars + vp.log_rate - j - 1))
                    .unwrap();
                let chunked_path = merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();
                oracle_merkle_paths.push(chunked_path);
            }
            batch_paths.push(oracle_merkle_paths);
            let mut comms_merkle_paths = Vec::with_capacity(comms.len());
            for j in 0..comms.len() {
                let merkle_path = transcript
                    .read_commitments(2 * (poly_num_vars[j] + vp.log_rate))
                    .unwrap();
                let chunked_path = merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                comms_merkle_paths.push(chunked_path);
            }

            batch_paths.push(comms_merkle_paths);
        }

        let queries_usize = batch_verifier_query_phase::<F, H>(
            &query_challenges,
            &sumcheck_messages,
            &fold_challenges,
            &queries,
            num_rounds,
            num_vars,
            vp.log_rate,
            &roots,
            vp.rng.clone(),
            &new_target_sum,
        );
        for vq in 0..vp.num_verifier_queries {
            let oracle_queries = &queries[vq * 2];
            for cq in 0..oracle_queries.len() {
                let root = &roots[cq];
                assert_eq!(root, &batch_paths[vq * 2][cq].pop().unwrap().pop().unwrap());

                authenticate_merkle_path::<H, F>(
                    &batch_paths[vq * 2][cq],
                    (oracle_queries[cq][0], oracle_queries[cq][1]),
                    queries_usize[vq * 2],
                );
            }

            let comm_queries = &queries[vq * 2 + 1];
            for cq in 0..comm_queries.len() {
                let root = &comms[cq].root();
                assert_eq!(
                    root,
                    &batch_paths[vq * 2 + 1][cq].pop().unwrap().pop().unwrap()
                );

                authenticate_merkle_path::<H, F>(
                    &batch_paths[vq * 2 + 1][cq],
                    (comm_queries[cq][0], comm_queries[cq][1]),
                    queries_usize[vq * 2 + 1],
                );
            }
        }

        for (i, query) in queries.iter().enumerate() {
            let mut lc0 = F::ZERO;
            let mut lc1 = F::ZERO;
            for j in 0..coeffs.len() {
                lc0 += coeffs[j] * queries[i][j][0];
                lc1 += coeffs[j] * queries[i][j][1];
            }
            assert_eq!(query[0][0], lc0);
            assert_eq!(query[0][1], lc1);
        }
        // virtual_open(
        //     num_vars,
        //     num_rounds,
        //     &mut eq,
        //     &mut bh_evals,
        //     &mut final_oracle,
        //     &verify_point,
        //     &mut fold_challenges,
        //     &vp.table_w_weights,
        //     &mut sum_check_oracles,
        // );
        Ok(())
    }
}

#[test]
fn test_evaluate_generic_basecode() {
    use crate::multilinear::basefold::test::Five;
    use blake2::Blake2s256;
    use rand::rngs::OsRng;

    type Pcs = Basefold<Mersenne61, Blake2s256, Five>;
    let mut rng = OsRng;
    let mut poly = MultilinearPolynomial::rand(10, OsRng);
    let mut t_rng = ChaCha8Rng::from_entropy();
    let (table_w_weights_, table) = get_table(poly.evals().len(), 3, &mut t_rng);

    let rate = 8;
    let mut base_codewords = encode_repetition_basecode(&poly.evals().to_vec(), rate);

    let evals1 = evaluate_over_foldable_domain_generic_basecode::<Mersenne61>(
        1,
        poly.evals().len(),
        3,
        base_codewords,
        &table,
    );
    let evals2 = evaluate_over_foldable_domain::<Mersenne61>(3, poly.evals().to_vec(), &table);
    assert_eq!(evals1, evals2);
}

#[test]
fn time_rs_code() {
    use blake2::Blake2s256;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let mut poly = MultilinearPolynomial::rand(20, OsRng);
    let mut t_rng = ChaCha8Rng::from_entropy();

    let rate = 2;
    let now = Instant::now();
    let evals = encode_rs_basecode::<Mersenne61>(&poly.evals().to_vec(), 2, 64);
    //    println!("rs time {:?}", now.elapsed().as_millis());
    //    println!("evals {:?}", evals.len());
}

// Split the input into chunks of message size, encode each message, and return the codewords
fn encode_rs_basecode<F: PrimeField>(
    poly: &Vec<F>,
    rate: usize,
    message_size: usize,
) -> Vec<Vec<F>> {
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

    res
}
fn encode_repetition_basecode<F: PrimeField>(poly: &Vec<F>, rate: usize) -> Vec<Vec<F>> {
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
//this function assumes all codewords in base_codeword has equivalent length
pub fn evaluate_over_foldable_domain_generic_basecode<F: PrimeField>(
    base_message_length: usize,
    num_coeffs: usize,
    log_rate: usize,
    mut base_codewords: Vec<Vec<F>>,
    table: &Vec<Vec<F>>,
) -> Vec<F> {
    let k = num_coeffs;
    let logk = log2_strict(k);
    let cl = 1 << (logk + log_rate);
    let rate = 1 << log_rate;
    let base_log_k = log2_strict(base_message_length);
    //concatenate together all base codewords
    //    let now = Instant::now();
    let mut coeffs_with_bc: Vec<F> = base_codewords.iter().flatten().map(|x| *x).collect();
    //    println!("concatenate base codewords {:?}", now.elapsed());
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let mut chunk_size = base_codewords[0].len(); //block length of the base code
    for i in base_log_k..logk {
        // In beginning of each iteration, the current codeword size is 1<<i, after this iteration,
        // every two adjacent codewords are folded into one codeword of size 1<<(i+1).
        // Fetch the table that has the same size of the *current* codeword size.
        let level = &table[i + log_rate];
        // chunk_size is equal to 1 << (i+1), i.e., the codeword size after the current iteration
        // half_chunk is equal to 1 << i, i.e. the current codeword size
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size >> 1);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut coeffs_with_bc)
            .par_chunks_mut(chunk_size)
            .for_each(|chunk| {
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
    coeffs_with_bc
}

pub fn evaluate_over_foldable_domain<F: PrimeField>(
    log_rate: usize,
    mut coeffs: Vec<F>,
    table: &Vec<Vec<F>>,
) -> Vec<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let k = coeffs.len();
    let logk = log2_strict(k);
    let cl = 1 << (logk + log_rate);
    let rate = 1 << log_rate;
    let mut coeffs_with_rep = Vec::with_capacity(cl);
    for i in 0..cl {
        coeffs_with_rep.push(F::ZERO);
    }

    //base code - in this case is the repetition code
    let now = Instant::now();
    for i in 0..k {
        for j in 0..rate {
            coeffs_with_rep[i * rate + j] = coeffs[i];
        }
    }

    let mut chunk_size = rate; //block length of the base code
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

fn interpolate_over_boolean_hypercube_with_copy<F: PrimeField>(evals: &Vec<F>) -> (Vec<F>, Vec<F>) {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = log2_strict(evals.len());
    let mut coeffs = vec![F::ZERO; evals.len()];
    let mut new_evals = vec![F::ZERO; evals.len()];

    let mut j = 0;
    while (j < coeffs.len()) {
        new_evals[j] = evals[j];
        new_evals[j + 1] = evals[j + 1];

        coeffs[j + 1] = evals[j + 1] - evals[j];
        coeffs[j] = evals[j];
        j += 2
    }

    // This code implicitly assumes that coeffs has size at least 1 << n,
    // that means the size of evals should be a power of two
    for i in 2..n + 1 {
        let chunk_size = 1 << i;
        coeffs.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] = chunk[j] - chunk[j - half_chunk];
            }
        });
    }

    (coeffs, new_evals)
}

//helper function
fn rand_vec<F: PrimeField>(size: usize, mut rng: &mut ChaCha8Rng) -> Vec<F> {
    (0..size).map(|_| F::random(&mut rng)).collect()
}
fn rand_chacha<F: PrimeField>(mut rng: &mut ChaCha8Rng) -> F {
    let bytes = (F::NUM_BITS as usize).next_power_of_two() / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    rng.fill_bytes(&mut dest);
    from_raw_bytes::<F>(&dest)
}

fn sum_check_first_round<F: PrimeField>(mut eq: &mut Vec<F>, mut bh_values: &mut Vec<F>) -> Vec<F> {
    // The input polynomials are in the form of evaluations. Instead of viewing
    // every one element as the evaluation of the polynomial at a single point,
    // we can view every two elements as partially evaluating the polynomial at
    // a single point, leaving the first variable free, and obtaining a univariate
    // polynomial. The one_level_interp_hc transforms the evaluation forms into
    // the coefficient forms, for every of these partial polynomials.
    one_level_interp_hc(&mut eq);
    one_level_interp_hc(&mut bh_values);
    parallel_pi(&bh_values, &eq)
    //    p_i(&bh_values, &eq)
}

pub fn one_level_interp_hc<F: PrimeField>(mut evals: &mut Vec<F>) {
    if (evals.len() == 1) {
        return;
    }
    evals.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[1] - chunk[0];
    });
}

pub fn one_level_eval_hc<F: PrimeField>(mut evals: &mut Vec<F>, challenge: F) {
    evals.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[0] + challenge * chunk[1];
    });

    // Skip every one other element
    let mut index = 0;
    evals.retain(|v| {
        index += 1;
        (index - 1) % 2 == 1
    });
}

pub fn p_i<F: PrimeField>(evals: &Vec<F>, eq: &Vec<F>) -> Vec<F> {
    if (evals.len() == 1) {
        return vec![evals[0], evals[0], evals[0]];
    }
    //evals coeffs
    let mut coeffs = vec![F::ZERO, F::ZERO, F::ZERO];
    let mut i = 0;
    while (i < evals.len()) {
        coeffs[0] += evals[i] * eq[i];
        coeffs[1] += evals[i + 1] * eq[i] + evals[i] * eq[i + 1];
        coeffs[2] += evals[i + 1] * eq[i + 1];
        i += 2;
    }

    coeffs
}

fn parallel_pi<F: PrimeField>(evals: &Vec<F>, eq: &Vec<F>) -> Vec<F> {
    if (evals.len() == 1) {
        return vec![evals[0], evals[0], evals[0]];
    }
    let mut coeffs = vec![F::ZERO, F::ZERO, F::ZERO];

    // Manually write down the multiplication formular of two linear polynomials
    let mut firsts = vec![F::ZERO; evals.len()];
    firsts.par_iter_mut().enumerate().for_each(|(i, mut f)| {
        if (i % 2 == 0) {
            *f = evals[i] * eq[i];
        }
    });

    let mut seconds = vec![F::ZERO; evals.len()];
    seconds.par_iter_mut().enumerate().for_each(|(i, mut f)| {
        if (i % 2 == 0) {
            *f = evals[i + 1] * eq[i] + evals[i] * eq[i + 1];
        }
    });

    let mut thirds = vec![F::ZERO; evals.len()];
    thirds.par_iter_mut().enumerate().for_each(|(i, mut f)| {
        if (i % 2 == 0) {
            *f = evals[i + 1] * eq[i + 1];
        }
    });

    coeffs[0] = firsts.par_iter().sum();
    coeffs[1] = seconds.par_iter().sum();
    coeffs[2] = thirds.par_iter().sum();

    coeffs
}
/*
fn nd_array_pi<F: PrimeField>(evals: &Vec<F>, eq: &Vec<F>) -> Vec<F> {
    if (evals.len() == 1) {
        return vec![evals[0], evals[0], evals[0]];
    }
    let evals_array = Array1::from(evals);
    let eq_array = Array1::from(eq);

    let evals_evens = Array1::from(evals.par_iter().enumerate().filter(|(i,x)| i%2 == 0).collect::<Vec<F>>());

    let evals_odd = Array1::from(evals.par_iter().enumerate().filter(|(i,x)| i%2 != 0).collect::<Vec<F>>());

    let eq_evens = Array1::from(eq.par_iter().enumerate().filter(|(i,x)| i%2 == 0).collect::<Vec<F>>());

    let eq_odd = Array1::from(eq.par_iter().enumerate().filter(|(i,x)| i%2 != 0).collect::<Vec<F>>());
    let dot1 = evals_array.dot(eq_array);
    let dot2 = evals_odd.dot(eq_even);
    let dot3 = evals_even.dot(eq_odd);
    let dot4 = evals_odd.dot(eq_odd);
    return vec![dot1,dot2 + dot3, dot4];
}
*/
#[test]
fn test_sumcheck() {
    use crate::util::ff_255::ff255::Ft255;
    let i = 25;
    let mut rng = ChaCha8Rng::from_entropy();
    let evals = rand_vec::<Ft255>(1 << i, &mut rng);
    let eq = rand_vec::<Ft255>(1 << i, &mut rng);
    let now = Instant::now();
    let coeffs1 = p_i(&evals, &eq);
    //    println!("original {:?}", now.elapsed());

    let now = Instant::now();
    let coeffs2 = parallel_pi(&evals, &eq);
    //    println!("new {:?}", now.elapsed());
    assert_eq!(coeffs1, coeffs2);
}

fn sum_check_challenge_round<F: PrimeField>(
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

fn sum_check_last_round<F: PrimeField>(
    mut eq: &mut Vec<F>,
    mut bh_values: &mut Vec<F>,
    challenge: F,
) {
    one_level_eval_hc(&mut bh_values, challenge);
    one_level_eval_hc(&mut eq, challenge);
}

fn basefold_one_round_by_interpolation_weights<F: PrimeField>(
    table: &Vec<Vec<(F, F)>>,
    level_index: usize,
    values: &Vec<F>,
    challenge: F,
) -> Vec<F> {
    let level = &table[level_index];
    values
        .par_chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            interpolate2_weights::<F>(
                [(level[i].0, ys[0]), (-(level[i].0), ys[1])],
                level[i].1,
                challenge,
            )
        })
        .collect::<Vec<_>>()
}

fn basefold_one_round_by_interpolation_weights_not_faster<F: PrimeField>(
    table: &Vec<Vec<(F, F)>>,
    table_offset: usize,
    values: &Vec<F>,
    challenge: F,
) -> Vec<F> {
    let level = &table[table.len() - 1 - table_offset];
    let mut new_values = vec![F::ZERO; values.len() >> 1];
    new_values.par_iter_mut().enumerate().for_each(|(i, v)| {
        *v = interpolate2_weights::<F>(
            [
                (level[i].0, values[2 * i]),
                (-(level[i].0), values[2 * i + 1]),
            ],
            level[i].1,
            challenge,
        )
    });
    new_values
}

fn basefold_get_query<F: PrimeField>(
    first_oracle: &Vec<F>,
    oracles: &Vec<Vec<F>>,
    mut x_index: usize,
) -> (Vec<(F, F)>, Vec<usize>) {
    let mut queries = Vec::with_capacity(oracles.len() + 1);
    let mut indices = Vec::with_capacity(oracles.len() + 1);

    let mut p0 = x_index;
    let mut p1 = x_index ^ 1;

    if (p1 < p0) {
        p0 = x_index ^ 1;
        p1 = x_index;
    }
    queries.push((first_oracle[p0], first_oracle[p1]));
    indices.push(p0);
    x_index >>= 1;

    for oracle in oracles {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        queries.push((oracle[p0], oracle[p1]));
        indices.push(p0);
        x_index >>= 1;
    }

    return (queries, indices);
}

fn batch_basefold_get_query<F: PrimeField, H: Hash>(
    comms: &[&BasefoldCommitmentWithData<F, H>],
    oracles: &Vec<Vec<F>>,
    codeword_size: usize,
    mut x_index: usize,
) -> (
    Vec<CodewordSingleQueryResult<F>>,
    Vec<CodewordSingleQueryResult<F>>,
) {
    let mut queries = Vec::with_capacity(oracles.len());

    x_index >>= 1;
    for oracle in oracles {
        let mut p1 = x_index | 1;
        let mut p0 = p1 - 1;
        queries.push(CodewordSingleQueryResult::<F>::new(
            oracle[p0], oracle[p1], p0,
        ));
        x_index >>= 1;
    }

    let comm_queries = comms
        .iter()
        .map(|comm| {
            let x_index = x_index >> (log2_strict(codeword_size) - comm.codeword_size_log());
            let mut p1 = x_index | 1;
            let mut p0 = p1 - 1;
            CodewordSingleQueryResult::<F>::new(
                *comm.get_codeword_entry(p0),
                *comm.get_codeword_entry(p1),
                p0,
            )
        })
        .collect_vec();

    return (queries, comm_queries);
}

fn write_merkle_path<H: Hash, F: PrimeField>(
    path: &MerklePathWithoutLeafOrRoot<H>,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
) {
    path.iter().for_each(|comm| {
        transcript.write_commitment(comm);
    });
}

fn authenticate_merkle_path<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaves: (F, F),
    mut x_index: usize,
) {
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update_field_element(&leaves.0);
    hasher.update_field_element(&leaves.1);
    hasher.finalize_into_reset(&mut hash);

    assert_eq!(hash, path[0][(x_index >> 1) % 2]);
    x_index >>= 1;
    for i in 0..path.len() {
        if (i + 1 == path.len()) {
            break;
        }
        let mut hasher = H::new();
        let mut hash = Output::<H>::default();
        hasher.update(&path[i][0]);
        hasher.update(&path[i][1]);
        hasher.finalize_into_reset(&mut hash);

        assert_eq!(hash, path[i + 1][(x_index >> 1) % 2]);
        x_index >>= 1;
    }
}

fn authenticate_merkle_path_root<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaves: (F, F),
    mut x_index: usize,
    root: &Output<H>,
) {
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update_field_element(&leaves.0);
    hasher.update_field_element(&leaves.1);
    hasher.finalize_into_reset(&mut hash);

    assert_eq!(hash, path[0][(x_index >> 1) % 2]);
    x_index >>= 1;
    for i in 0..path.len() - 1 {
        let mut hasher = H::new();
        let mut hash = Output::<H>::default();
        hasher.update(&path[i][0]);
        hasher.update(&path[i][1]);
        hasher.finalize_into_reset(&mut hash);

        assert_eq!(hash, path[i + 1][(x_index >> 1) % 2]);
        x_index >>= 1;
    }
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update(&path[path.len() - 1][0]);
    hasher.update(&path[path.len() - 1][1]);
    hasher.finalize_into_reset(&mut hash);
    assert_eq!(&hash, root);
}

pub fn interpolate2_weights<F: PrimeField>(points: [(F, F); 2], weight: F, x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    //    assert_ne!(a0, b0);
    // Here weight = 1/(b0-a0). The reason for precomputing it is that inversion is expensive
    a1 + (x - a0) * (b1 - a1) * weight
}

pub fn query_point<F: PrimeField>(
    block_length: usize,
    eval_index: usize,
    mut rng: &mut ChaCha8Rng,
    level: usize,
    mut cipher: &mut ctr::Ctr32LE<aes::Aes128>,
) -> F {
    let level_index = eval_index % (block_length);
    let mut el = query_root_table_from_rng_aes::<F>(
        level,
        (level_index % (block_length >> 1)),
        &mut rng,
        &mut cipher,
    );

    if level_index >= (block_length >> 1) {
        el = -F::ONE * el;
    }

    return el;
}
pub fn query_root_table_from_rng<F: PrimeField>(
    level: usize,
    index: usize,
    rng: &mut ChaCha8Rng,
) -> F {
    let mut level_offset: u128 = 1;
    for lg_m in 1..=level {
        let half_m = 1 << (lg_m - 1);
        level_offset += half_m;
    }
    //this is 512  because of the implementation of random in the ff rust library
    //    let pos = ((level_offset + (index as u128)) * (512))
    let pos = ((level_offset + (index as u128))
        * ((F::NUM_BITS as usize).next_power_of_two() as u128))
        .checked_div(32)
        .unwrap();

    rng.set_word_pos(pos);

    let res = rand_chacha::<F>(rng);

    res
}

pub fn query_root_table_from_rng_aes<F: PrimeField>(
    level: usize,
    index: usize,
    rng: &mut ChaCha8Rng,
    cipher: &mut ctr::Ctr32LE<aes::Aes128>,
) -> F {
    let mut level_offset: u128 = 1;
    for lg_m in 1..=level {
        let half_m = 1 << (lg_m - 1);
        level_offset += half_m;
    }

    let pos = ((level_offset + (index as u128))
        * ((F::NUM_BITS as usize).next_power_of_two() as u128))
        .checked_div(8)
        .unwrap();

    cipher.seek(pos);

    let bytes = (F::NUM_BITS as usize).next_power_of_two() / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    cipher.apply_keystream(&mut dest);

    let res = from_raw_bytes::<F>(&dest);

    res
}

pub fn interpolate2<F: PrimeField>(points: [(F, F); 2], x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    assert_ne!(a0, b0);
    a1 + (x - a0) * (b1 - a1) * (b0 - a0).invert().unwrap()
}

fn degree_2_zero_plus_one<F: PrimeField>(poly: &Vec<F>) -> F {
    poly[0] + poly[0] + poly[1] + poly[2]
}

fn degree_2_eval<F: PrimeField>(poly: &Vec<F>, point: F) -> F {
    poly[0] + point * poly[1] + point * point * poly[2]
}

pub fn interpolate_over_boolean_hypercube<F: PrimeField>(mut evals: Vec<F>) -> Vec<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = log2_strict(evals.len());
    for i in 1..n + 1 {
        let chunk_size = 1 << i;
        evals.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] = chunk[j] - chunk[j - half_chunk];
            }
        });
    }
    reverse_index_bits_in_place(&mut evals);
    evals
}

pub fn multilinear_evaluation_ztoa<F: PrimeField>(poly: &mut Vec<F>, point: &Vec<F>) {
    let n = log2_strict(poly.len());
    //    assert_eq!(point.len(),n);
    for p in point {
        poly.par_chunks_mut(2).for_each(|chunk| {
            chunk[0] = chunk[0] + *p * chunk[1];
            chunk[1] = chunk[0];
        });
        poly.dedup();
    }
}
#[test]
fn bench_multilinear_eval() {
    use crate::util::ff_255::ff255::Ft255;
    for i in 10..27 {
        let mut rng = ChaCha8Rng::from_entropy();
        let mut poly = rand_vec::<Ft255>(1 << i, &mut rng);
        let point = rand_vec::<Ft255>(i, &mut rng);
        let now = Instant::now();
        multilinear_evaluation_ztoa(&mut poly, &point);
        println!(
            "time for multilinear eval degree i {:?} : {:?}",
            i,
            now.elapsed().as_millis()
        );
    }
}
fn from_raw_bytes<F: PrimeField>(bytes: &Vec<u8>) -> F {
    let mut res = F::ZERO;
    bytes.into_iter().for_each(|b| {
        res += F::from(u64::from(*b));
    });
    res
}

#[cfg(test)]
mod test {
    use crate::util::transcript::{
        FieldTranscript, FieldTranscriptRead, FieldTranscriptWrite, InMemoryTranscript,
        TranscriptRead, TranscriptWrite,
    };

    use crate::{
        multilinear::{
            basefold::Basefold,
            test::{run_batch_commit_open_verify, run_commit_open_verify},
        },
        util::{
            hash::{Hash, Keccak256, Output},
            new_fields::{Mersenne127, Mersenne61},
            transcript::{Blake2sTranscript, Keccak256Transcript},
        },
    };
    use halo2_curves::{ff::Field, secp256k1::Fp};
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha12Rng, ChaCha8Rng,
    };
    use std::io;

    use crate::multilinear::basefold::Instant;
    use crate::multilinear::BasefoldExtParams;
    use crate::util::arithmetic::PrimeField;
    use blake2::{digest::FixedOutputReset, Blake2s256};
    use halo2_curves::bn256::{Bn256, Fr};

    type Pcs = Basefold<Fp, Blake2s256, Five>;

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
            return 0;
        }
    }

    #[test]
    fn commit_open_verify() {
        run_commit_open_verify::<_, Pcs, Blake2sTranscript<_>>();
    }

    #[test]
    fn batch_commit_open_verify() {
        run_batch_commit_open_verify::<_, Pcs, Blake2sTranscript<_>>();
    }

    struct PretendHash {}
    #[test]
    fn test_sha3_hashes() {
        use blake2::digest::FixedOutputReset;

        type H = Keccak256;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
        for (i, mut hash) in hashes.iter_mut().enumerate() {
            let mut hasher = H::new();
            hasher.update_field_element(&values[i + i]);
            hasher.update_field_element(&values[i + i + 1]);
            hasher.finalize_into_reset(&mut hash);
        }
        println!("lots of hashes sha3 time {:?}", lots_of_hashes.elapsed());

        let hash_alot = Instant::now();
        let mut hasher = H::new();
        for i in 0..2000 {
            hasher.update_field_element(&values[i]);
        }
        let mut hash = Output::<H>::default();
        hasher.finalize_into_reset(&mut hash);
        println!("hash a lot sha3 time {:?}", hash_alot.elapsed());
    }

    #[test]
    fn test_blake2b_hashes() {
        use blake2::{digest::FixedOutputReset, Blake2b512, Blake2s256};

        type H = Blake2s256;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
        for (i, mut hash) in hashes.iter_mut().enumerate() {
            let mut hasher = H::new();
            hasher.update_field_element(&values[i + i]);
            hasher.update_field_element(&values[i + i + 1]);
            hasher.finalize_into_reset(&mut hash);
        }
        println!("lots of hashes blake2 time {:?}", lots_of_hashes.elapsed());

        let hash_alot = Instant::now();
        let mut hasher = H::new();
        for i in 0..2000 {
            hasher.update_field_element(&values[i]);
        }
        let mut hash = Output::<H>::default();
        hasher.finalize_into_reset(&mut hash);
        println!("hash alot blake2 time {:?}", hash_alot.elapsed());
    }

    #[test]
    fn test_blake2b_no_finalize() {
        use blake2::{digest::FixedOutputReset, Blake2b512, Blake2s256};

        type H = Blake2s256;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
        for (i, mut hash) in hashes.iter_mut().enumerate() {
            let mut hasher = H::new();
            let f1 = values[i + 1].to_repr();
            let f2 = values[i + i + 1].to_repr();
            let data = [f1.as_ref(), f2.as_ref()].concat();
            //	    hasher.update_field_element(&values[i + i]);
            //	    hasher.update_field_element(&values[i+ i + 1]);
            *hash = H::digest(&data);
        }
        println!(
            "lots of hashes blake2 time no finalize{:?}",
            lots_of_hashes.elapsed()
        );

        let hash_alot = Instant::now();
        let mut hasher = H::new();
        for i in 0..2000 {
            hasher.update_field_element(&values[i]);
        }
        let mut hash = Output::<H>::default();
        hasher.finalize_into_reset(&mut hash);
        println!("hash alot blake2 time no finalize{:?}", hash_alot.elapsed());
    }

    #[test]
    fn test_cipher() {
        use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use generic_array::GenericArray;
        use hex_literal::hex;
        type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
        let mut rng = ChaCha12Rng::from_entropy();

        let mut key: [u8; 16] = [042; 16];
        let mut iv: [u8; 16] = [024; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        //	rng.set_word_pos(0);

        let mut key2: [u8; 16] = [042; 16];
        let mut iv2: [u8; 16] = [024; 16];
        rng.fill_bytes(&mut key2);
        rng.fill_bytes(&mut iv2);

        let plaintext = *b"hello world! this is my plaintext.";
        let ciphertext =
            hex!("3357121ebb5a29468bd861467596ce3da59bdee42dcc0614dea955368d8a5dc0cad4");
        let mut buf = plaintext.to_vec();
        let mut buf1 = [0u8; 100];

        let mut cipher = Aes128Ctr64LE::new(
            GenericArray::from_slice(&key[..]),
            GenericArray::from_slice(&iv[..]),
        );
        let hash_time = Instant::now();
        cipher.apply_keystream(&mut buf1[..]);
        println!("aes hash 34 bytes {:?}", hash_time.elapsed());
        println!("buf1 {:?}", buf1);
        for i in 0..40 {
            let now = Instant::now();
            cipher.seek((1 << i) as u64);
            println!("aes seek {:?} : {:?}", (1 << i), now.elapsed());
        }
        let mut bufnew = [0u8; 1];
        cipher.apply_keystream(&mut bufnew);

        println!("byte1 {:?}", bufnew);

        /*
            let mut cipher2 = Aes128Ctr64LE::new(&key.into(),&iv.into());
            let mut buf2 = [0u8; 34];
            for chunk in buf2.chunks_mut(3){
                cipher2.apply_keystream(chunk);
            }

            assert_eq!(buf1,buf2);
        */
        let mut dest: Vec<u8> = vec![0u8; 34];
        let mut rng = ChaCha8Rng::from_entropy();
        let now = Instant::now();
        rng.fill_bytes(&mut dest);
        println!("chacha20 hash 34 bytes {:?}", now.elapsed());
        println!("des {:?}", dest);
        let now = Instant::now();
        rng.set_word_pos(1);

        println!("chacha8 seek {:?}", now.elapsed());

        let mut cipher = Aes128Ctr64LE::new(
            GenericArray::from_slice(&key[..]),
            GenericArray::from_slice(&iv[..]),
        );
        let mut buf2 = vec![0u8; 34];
        let hash_time = Instant::now();

        let now = Instant::now();
        cipher.seek(33u64);
        println!("aes seek {:?}", now.elapsed());
        let mut bufnew = [0u8; 1];
        cipher.apply_keystream(&mut bufnew);

        println!("byte1 {:?}", bufnew);
    }

    #[test]
    fn test_blake2b_simd_hashes() {
        use blake2b_simd::{blake2b, many::update_many, State};
        use ff::PrimeField;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut states = vec![State::new(); 1000];

        for (i, mut hash) in states.iter_mut().enumerate() {
            hash.update(&values[i + i].to_repr().as_ref());
            hash.update(&values[i + i + 1].to_repr().as_ref());
            hash.finalize();
        }
        println!(
            "lots of hashes blake2simd time {:?}",
            lots_of_hashes.elapsed()
        );

        let hash_alot = Instant::now();
        let mut state = State::new();
        for i in 0..2000 {
            state.update(values[i].to_repr().as_ref());
        }
        let hash = state.finalize();
        println!("hash alot blake2simd time {:?}", hash_alot.elapsed());
    }
}

fn reed_solomon_into<F: Field>(input: &[F], mut target: impl AsMut<[F]>, domain: &Vec<F>) {
    target
        .as_mut()
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, target)| *target = horner(input, &domain[i]));
}

fn virtual_open<F: PrimeField>(
    num_vars: usize,
    num_rounds: usize,
    eq: &mut Vec<F>,
    bh_evals: &mut Vec<F>,
    last_oracle: &Vec<F>,
    point: &Vec<F>,
    challenges: &mut Vec<F>,
    table: &Vec<Vec<(F, F)>>,
    sum_check_oracles: &mut Vec<Vec<F>>,
) {
    let mut rng = ChaCha8Rng::from_entropy();
    let rounds = num_vars - num_rounds;

    let mut oracles = Vec::with_capacity(rounds);
    let mut new_oracle = last_oracle;
    // Continue the folding, because sum-check needs a single value in the end
    // not just a low-degree codeword.
    // But there is definitely a better way to evaluate the polynomial at random
    // challenges than locally simulating a sum-check.
    // In fact, all we need to check is that:
    // 1. the last_oracle is the correct encoding of the current bh_evals
    // 2. the current bh_evals * eq produces the claimed target sum
    // We can continue the folding, it's a good idea, but there is no need to compute
    // the polynomial h(X) in every round.
    // TODO: use an alternative protocol.
    for round in 0..rounds {
        let challenge: F = rand_chacha(&mut rng);
        challenges.push(challenge);
        let now = Instant::now();
        sum_check_oracles.push(sum_check_challenge_round(eq, bh_evals, challenge));

        // The verifier only needs the last rows of the table, which are very small.
        // Although in the current code the verification key still contains the complete
        // table. Need to optimize.
        oracles.push(basefold_one_round_by_interpolation_weights::<F>(
            &table,
            log2_strict(new_oracle.len()) - 1,
            &new_oracle,
            challenge,
        ));
        new_oracle = &oracles[round];
    }

    let mut no = new_oracle.clone();
    no.dedup();
    // If the prover is honest, the final oracle should consist of repetitions of
    // the same value. Don't we need to check that? It doesn't hurt the verifier to
    // add this additional check. Just for better chance of being secure.
    assert_eq!(no.len(), 1);

    //verify it information-theoretically
    let mut eq_r_ = F::ONE;
    for i in 0..challenges.len() {
        eq_r_ = eq_r_ * (challenges[i] * point[i] + (F::ONE - challenges[i]) * (F::ONE - point[i]));
    }
    let last_challenge = challenges[challenges.len() - 1];
    assert_eq!(
        degree_2_eval(&sum_check_oracles[challenges.len() - 1], last_challenge),
        eq_r_ * no[0]
    );
}

//outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
fn commit_phase<F: PrimeField, H: Hash>(
    point: &Point<F, MultilinearPolynomial<F>>,
    comm: &BasefoldCommitmentWithData<F, H>,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(F, F)>>,
) -> (
    Vec<MerkleTree<F, H>>,
    Vec<Vec<F>>,
    Vec<Vec<F>>,
    Vec<F>,
    Vec<F>,
    F,
) {
    let mut oracles = Vec::with_capacity(num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut root = comm.to_commitment().root();
    let mut new_oracle = comm.get_codeword();
    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let mut eq = build_eq_x_r_vec::<F>(&point);
    let mut bh_evals = comm.bh_evals.clone();
    // eval is the evaluation of the committed polynomial at r
    let eval = comm
        .bh_evals
        .par_iter()
        .zip(&eq)
        .map(|(a, b)| *a * *b)
        .sum();

    let mut sum_check_oracles = Vec::with_capacity(num_rounds + 1);
    sum_check_oracles.push(sum_check_first_round::<F>(&mut eq, &mut bh_evals));
    // Note that after the sum_check_first_round, every two elements in eq and bh_evals have
    // been transformed into the coefficient forms. More precisely, position [2i] and [2i+1]
    // are used to store the partially evaluated polynomial f(X,binary(i))

    for i in 0..(num_rounds) {
        transcript.write_commitment(&root).unwrap();
        let challenge: F = transcript.squeeze_challenge();
        let sumcheck = Instant::now();
        sum_check_oracles.push(sum_check_challenge_round(&mut eq, &mut bh_evals, challenge));

        oracles.push(basefold_one_round_by_interpolation_weights::<F>(
            &table_w_weights,
            log2_strict(new_oracle.len()) - 1,
            new_oracle,
            challenge,
        ));

        new_oracle = &oracles[i];
        trees.push(MerkleTree::<F, H>::from_leaves(new_oracle.clone()));

        root = trees[i].root();
    }

    // This place sends the root of the last oracle, instead of the encoded message
    // in clear.
    transcript.write_commitment(&root).unwrap();
    return (trees, sum_check_oracles, oracles, bh_evals, eq, eval);
}

//outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
fn batch_commit_phase<F: PrimeField, H: Hash>(
    point: &Point<F, MultilinearPolynomial<F>>,
    comms: &[&BasefoldCommitmentWithData<F, H>],
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(F, F)>>,
    log_rate: usize,
    coeffs: &[F],
) -> (Vec<MerkleTree<F, H>>, Vec<Vec<F>>, Vec<Vec<F>>) {
    assert_eq!(point.len(), num_vars);
    let mut oracles = Vec::with_capacity(num_vars);
    let mut trees = Vec::with_capacity(num_vars);
    let mut running_oracle = vec![F::ZERO; 1 << (num_vars + log_rate)];

    // Before the interaction, collect all the polynomials whose num variables match the
    // max num variables
    let running_oracle_len = running_oracle.len();
    comms
        .iter()
        .enumerate()
        .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
        .for_each(|(index, comm)| {
            running_oracle
                .par_iter_mut()
                .zip_eq(comm.get_codeword().par_iter())
                .for_each(|(mut r, &a)| *r += a * coeffs[index]);
        });
    let mut running_tree = MerkleTree::<F, H>::from_leaves(running_oracle.clone());
    let mut running_root = running_tree.root();

    // Unlike the FRI part, the sum-check part still follows the original procedure,
    // and linearly combine all the polynomials once for all
    let mut sum_of_all_evals_for_sumcheck = vec![F::ZERO; 1 << num_vars];
    comms.iter().enumerate().for_each(|(index, comm)| {
        sum_of_all_evals_for_sumcheck
            .par_iter_mut()
            .enumerate()
            .for_each(|(pos, mut r)| {
                // Evaluating the multilinear polynomial outside of its interpolation hypercube
                // is equivalent to repeating each element in place.
                // Here is the tricky part: the bh_evals are stored in big endian, but we want
                // to align the polynomials to the variable with index 0 before adding them
                // together. So each element is repeated by
                // sum_of_all_evals_for_sumcheck.len() / bh_evals.len() times
                *r += comm.bh_evals[pos >> (num_vars - log2_strict(comm.bh_evals.len()))]
                    * coeffs[index]
            });
    });

    // eq is the evaluation representation of the eq(X,r) polynomial over the hypercube
    let mut eq = build_eq_x_r_vec::<F>(&point);

    let mut sumcheck_messages = Vec::with_capacity(num_rounds + 1);
    let mut last_sumcheck_message =
        sum_check_first_round::<F>(&mut eq, &mut sum_of_all_evals_for_sumcheck);
    sumcheck_messages.push(last_sumcheck_message.clone());

    for i in 0..num_rounds {
        // For the first round, no need to send the running root, because this root is
        // committing to a vector that can be recovered from linearly combining other
        // already-committed vectors.
        transcript.write_field_elements(&last_sumcheck_message);

        let challenge: F = transcript.squeeze_challenge();

        // Fold the current oracle for FRI
        let mut running_oracle = basefold_one_round_by_interpolation_weights::<F>(
            &table_w_weights,
            log2_strict(running_oracle.len()) - 1,
            &running_oracle,
            challenge,
        );
        // Then merge the rest polynomials whose sizes match the current running oracle
        let running_oracle_len = running_oracle.len();
        comms
            .iter()
            .enumerate()
            .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
            .for_each(|(index, comm)| {
                running_oracle
                    .par_iter_mut()
                    .zip_eq(comm.get_codeword().par_iter())
                    .for_each(|(mut r, &a)| *r += a * coeffs[index]);
            });

        if i < num_rounds - 1 {
            last_sumcheck_message =
                sum_check_challenge_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            sumcheck_messages.push(last_sumcheck_message.clone());
            running_tree = MerkleTree::<F, H>::from_leaves(running_oracle.clone());
            running_root = running_tree.root();
            transcript.write_commitment(&running_root).unwrap();

            oracles.push(running_oracle);
            trees.push(running_tree);
        } else {
            // The difference of the last round is that we don't need to compute the message,
            // and we don't interpolate the small polynomials. So after the last round,
            // sum_of_all_evals_for_sumcheck is exactly the evaluation representation of the
            // folded polynomial so far.
            sum_check_last_round(&mut eq, &mut sum_of_all_evals_for_sumcheck, challenge);
            // For the FRI part, we send the current polynomial as the message
            transcript.write_field_elements(&sum_of_all_evals_for_sumcheck);

            if cfg!(feature = "sanity-check") {
                // If the prover is honest, in the last round, the running oracle
                // on the prover side should be exactly the encoding of the folded polynomial.
                reverse_index_bits_in_place(&mut sum_of_all_evals_for_sumcheck);
                reverse_index_bits_in_place(&mut running_oracle);

                let (coeffs, mut bh_evals) =
                    interpolate_over_boolean_hypercube_with_copy(&sum_of_all_evals_for_sumcheck);
                let basecode = encode_rs_basecode(&coeffs, log_rate, coeffs.len());
                assert_eq!(basecode.len(), 1);
                let basecode = basecode[0].clone();
                assert_eq!(basecode, running_oracle);
            }
        }
    }
    return (trees, sumcheck_messages, oracles);
}

fn query_phase<F: PrimeField, H: Hash>(
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    comm: &BasefoldCommitmentWithData<F, H>,
    oracles: &Vec<Vec<F>>,
    num_verifier_queries: usize,
) -> (Vec<(Vec<(F, F)>, Vec<usize>)>, Vec<usize>) {
    let mut queries = transcript.squeeze_challenges(num_verifier_queries);

    // Transform the challenge queries from field elements into integers
    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| {
            let x_rep = (*x_index).to_repr();
            let mut x: &[u8] = x_rep.as_ref();
            let (int_bytes, _) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % comm.codeword_size()).into()
        })
        .collect_vec();

    (
        queries_usize
            .par_iter()
            .map(|x_index| {
                return basefold_get_query::<F>(comm.get_codeword(), &oracles, *x_index);
            })
            .collect(),
        queries_usize,
    )
}

struct CodewordSingleQueryResult<F> {
    left: F,
    right: F,
    index: usize,
}

impl<F> CodewordSingleQueryResult<F> {
    fn new(left: F, right: F, index: usize) -> Self {
        Self { left, right, index }
    }
}

fn batch_query_phase<F: PrimeField, H: Hash>(
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    codeword_size: usize,
    comms: &[&BasefoldCommitmentWithData<F, H>],
    oracles: &Vec<Vec<F>>,
    num_verifier_queries: usize,
) -> (
    Vec<(
        Vec<CodewordSingleQueryResult<F>>,
        Vec<CodewordSingleQueryResult<F>>,
    )>,
    Vec<usize>,
) {
    let mut queries = transcript.squeeze_challenges(num_verifier_queries);

    // Transform the challenge queries from field elements into integers
    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| {
            let x_rep = (*x_index).to_repr();
            let mut x: &[u8] = x_rep.as_ref();
            let (int_bytes, _) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % codeword_size).into()
        })
        .collect_vec();

    (
        queries_usize
            .par_iter()
            .map(|x_index| {
                return batch_basefold_get_query::<F, H>(comms, &oracles, codeword_size, *x_index);
            })
            .collect(),
        queries_usize,
    )
}

fn verifier_query_phase<F: PrimeField, H: Hash>(
    query_challenges: &Vec<F>,
    query_merkle_paths: &Vec<Vec<Vec<Vec<Output<H>>>>>,
    sum_check_oracles: &Vec<Vec<F>>,
    fold_challenges: &Vec<F>,
    queries: &Vec<Vec<&[F]>>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    roots: &Vec<Output<H>>,
    rng: ChaCha8Rng,
    eval: &F,
) -> Vec<usize> {
    let n = (1 << (num_vars + log_rate));
    let mut queries_usize: Vec<usize> = query_challenges
        .par_iter()
        .map(|x_index| {
            let x_repr = (*x_index).to_repr();
            let mut x: &[u8] = x_repr.as_ref();
            let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % n).into()
        })
        .collect();

    // For computing the weights on the fly, because the verifier is incapable of storing
    // the weights.
    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    let mut rng = rng.clone();
    rng.set_word_pos(0);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );

    queries_usize
        .par_iter_mut()
        .enumerate()
        .for_each(|(qi, query_index)| {
            let mut cipher = cipher.clone();
            let mut rng = rng.clone();
            let mut cur_index = *query_index;
            let mut cur_queries = &queries[qi];

            for i in 0..num_rounds {
                let temp = cur_index;
                let mut other_index = cur_index ^ 1;
                if (other_index < cur_index) {
                    cur_index = other_index;
                    other_index = temp;
                }

                assert_eq!(cur_index % 2, 0);

                let ri0 = reverse_bits(cur_index, num_vars + log_rate - i);
                let ri1 = reverse_bits(other_index, num_vars + log_rate - i);
                let now = Instant::now();
                let x0: F = query_point(
                    1 << (num_vars + log_rate - i),
                    ri0,
                    &mut rng,
                    num_vars + log_rate - i - 1,
                    &mut cipher,
                );
                let x1 = -x0;

                let res = interpolate2(
                    [(x0, cur_queries[i][0]), (x1, cur_queries[i][1])],
                    fold_challenges[i],
                );

                assert_eq!(res, cur_queries[i + 1][(cur_index >> 1) % 2]);

                authenticate_merkle_path_root::<H, F>(
                    &query_merkle_paths[qi][i],
                    (cur_queries[i][0], cur_queries[i][1]),
                    cur_index,
                    &roots[i],
                );

                cur_index >>= 1;
            }
        });

    assert_eq!(eval, &degree_2_zero_plus_one(&sum_check_oracles[0]));

    // The sum-check part of the protocol
    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            degree_2_eval(&sum_check_oracles[i], fold_challenges[i]),
            degree_2_zero_plus_one(&sum_check_oracles[i + 1])
        );
    }
    return queries_usize;
}

fn batch_verifier_query_phase<F: PrimeField, H: Hash>(
    query_challenges: &Vec<F>,
    sum_check_oracles: &Vec<Vec<F>>,
    fold_challenges: &Vec<F>,
    queries: &Vec<Vec<Vec<F>>>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    roots: &Vec<Output<H>>,
    rng: ChaCha8Rng,
    eval: &F,
) -> Vec<usize> {
    let n = (1 << (num_vars + log_rate));
    let mut queries_usize: Vec<usize> = query_challenges
        .par_iter()
        .map(|x_index| {
            let x_repr = (*x_index).to_repr();
            let mut x: &[u8] = x_repr.as_ref();
            let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % n).into()
        })
        .collect();

    // For computing the weights on the fly, because the verifier is incapable of storing
    // the weights.
    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    let mut rng = rng.clone();
    rng.set_word_pos(0);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );

    queries_usize
        .par_iter_mut()
        .enumerate()
        .for_each(|(qi, query_index)| {
            let mut cipher = cipher.clone();
            let mut rng = rng.clone();
            let mut cur_index = *query_index;
            let mut oracle_queries = &queries[qi * 2];
            let mut comm_queries = &queries[qi * 2 + 1];

            for i in 0..num_rounds {
                let temp = cur_index;
                let mut other_index = cur_index ^ 1;
                if (other_index < cur_index) {
                    cur_index = other_index;
                    other_index = temp;
                }

                assert_eq!(cur_index % 2, 0);

                let ri0 = reverse_bits(cur_index, num_vars + log_rate - i);
                let ri1 = reverse_bits(other_index, num_vars + log_rate - i);
                let now = Instant::now();
                let x0: F = query_point(
                    1 << (num_vars + log_rate - i),
                    ri0,
                    &mut rng,
                    num_vars + log_rate - i - 1,
                    &mut cipher,
                );
                let x1 = -x0;

                let res = interpolate2(
                    [(x0, oracle_queries[i][0]), (x1, oracle_queries[i][1])],
                    fold_challenges[i],
                );

                assert_eq!(res, oracle_queries[i + 1][(cur_index >> 1) % 2]);

                cur_index >>= 1;
            }
        });

    assert_eq!(eval, &degree_2_zero_plus_one(&sum_check_oracles[0]));

    // The sum-check part of the protocol
    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            degree_2_eval(&sum_check_oracles[i], fold_challenges[i]),
            degree_2_zero_plus_one(&sum_check_oracles[i + 1])
        );
    }
    return queries_usize;
}

//return ((leaf1,leaf2),path), where leaves are queries from codewords
fn query_codeword<F: PrimeField, H: Hash>(
    query: &usize,
    codeword_tree: &MerkleTree<F, H>,
) -> ((F, F), MerklePathWithoutLeafOrRoot<H>) {
    let mut p0 = *query;
    let temp = p0;
    let mut p1 = p0 ^ 1;
    if (p1 < p0) {
        p0 = p1;
        p1 = temp;
    }
    return (
        (*codeword_tree.get_leaf(p0), *codeword_tree.get_leaf(p1)),
        codeword_tree.merkle_path_without_leaf_sibling_or_root(*query),
    );
}

fn get_table<F: PrimeField>(
    poly_size: usize,
    rate: usize,
    rng: &mut ChaCha8Rng,
) -> (Vec<Vec<(F, F)>>, Vec<Vec<F>>) {
    let lg_n: usize = rate + log2_strict(poly_size);

    let now = Instant::now();

    let bytes = (F::NUM_BITS as usize).next_power_of_two() * (1 << lg_n) / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    rng.fill_bytes(&mut dest);

    let flat_table: Vec<F> = dest
        .par_chunks_exact((F::NUM_BITS as usize).next_power_of_two() / 8)
        .map(|chunk| from_raw_bytes::<F>(&chunk.to_vec()))
        .collect::<Vec<_>>();

    assert_eq!(flat_table.len(), 1 << lg_n);

    let mut weights: Vec<F> = flat_table
        .par_iter()
        .map(|el| F::ZERO - *el - *el)
        .collect();

    let mut scratch_space = vec![F::ZERO; weights.len()];
    BatchInverter::invert_with_external_scratch(&mut weights, &mut scratch_space);

    let mut flat_table_w_weights = flat_table
        .iter()
        .zip(weights)
        .map(|(el, w)| (*el, w))
        .collect_vec();

    let mut unflattened_table_w_weights = vec![Vec::new(); lg_n];
    let mut unflattened_table = vec![Vec::new(); lg_n];

    let mut level_weights = flat_table_w_weights[0..2].to_vec();
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

fn get_table_aes<F: PrimeField>(
    poly_size: usize,
    rate: usize,
    rng: &mut ChaCha8Rng,
) -> (Vec<Vec<(F, F)>>, Vec<Vec<F>>) {
    // The size (logarithmic) of the codeword for the polynomial
    let lg_n: usize = rate + log2_strict(poly_size);

    let now = Instant::now();

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
    let bytes = num_of_bytes::<F>(1 << lg_n);
    let mut dest: Vec<u8> = vec![0u8; bytes];
    cipher.apply_keystream(&mut dest[..]);

    // Now, dest is a vector filled with random data for a field vector of size n

    // Collect the bytes into field elements
    let flat_table: Vec<F> = dest
        .par_chunks_exact(num_of_bytes::<F>(1))
        .map(|chunk| from_raw_bytes::<F>(&chunk.to_vec()))
        .collect::<Vec<_>>();

    // Now, flat_table is a field vector of size n, filled with random field elements
    assert_eq!(flat_table.len(), 1 << lg_n);

    // Multiply -2 to every element to get the weights. Now weights = { -2x }
    let mut weights: Vec<F> = flat_table
        .par_iter()
        .map(|el| F::ZERO - *el - *el)
        .collect();

    // Then invert all the elements. Now weights = { -1/2x }
    let mut scratch_space = vec![F::ZERO; weights.len()];
    BatchInverter::invert_with_external_scratch(&mut weights, &mut scratch_space);

    // Zip x and -1/2x together. The result is the list { (x, -1/2x) }
    // What is this -1/2x? It is used in linear interpolation over the domain (x, -x), which
    // involves computing 1/(b-a) where b=-x and a=x, and 1/(b-a) here is exactly -1/2x
    let mut flat_table_w_weights = flat_table
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
