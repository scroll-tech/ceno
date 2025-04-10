use std::collections::BTreeMap;

use crate::{
    Error, Evaluation, Point, PolynomialCommitmentScheme,
    util::{
        hash::write_digest_to_transcript,
        merkle_tree::{Poseidon2ExtMerkleMmcs, poseidon2_merkle_tree},
    },
};
pub use encoding::{EncodingScheme, RSCode, RSCodeDefaultSpec};
use ff_ext::ExtensionField;
use p3::{commit::Mmcs, matrix::dense::DenseMatrix, util::log2_strict_usize};
use query_phase::{batch_query_phase, batch_verifier_query_phase};
use structure::{BasefoldProof, CircuitIndexMeta};
pub use structure::{BasefoldSpec, Digest};
use sumcheck::macros::{entered_span, exit_span};
use transcript::Transcript;
use witness::{RowMajorMatrix, next_pow2_instance_padding};

use itertools::{Itertools, izip};
use serde::{Serialize, de::DeserializeOwned};

use multilinear_extensions::{mle::FieldType, util::ceil_log2};

use rayon::{
    iter::IntoParallelIterator,
    prelude::{IntoParallelRefIterator, ParallelIterator},
};

mod structure;
pub use structure::{
    Basefold, BasefoldCommitment, BasefoldCommitmentWithWitness, BasefoldDefault, BasefoldParams,
    BasefoldProverParams, BasefoldRSParams, BasefoldVerifierParams,
};
mod commit_phase;
use commit_phase::batch_commit_phase;
mod encoding;
use multilinear_extensions::virtual_poly::ArcMultilinearExtension;

mod query_phase;

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    /// Transpose a matrix of field elements, generic over the type of field element
    pub fn transpose_field_type<T: Send + Sync + Copy>(
        matrix: &[FieldType<E>],
    ) -> Result<Vec<FieldType<E>>, Error> {
        let transpose_fn = match matrix[0] {
            FieldType::Ext(_) => Self::get_column_ext,
            FieldType::Base(_) => Self::get_column_base,
            FieldType::Unreachable => unreachable!(),
        };

        let len = matrix[0].len();
        (0..len)
            .into_par_iter()
            .map(|i| (transpose_fn)(matrix, i))
            .collect()
    }

    fn get_column_base(
        matrix: &[FieldType<E>],
        column_index: usize,
    ) -> Result<FieldType<E>, Error> {
        Ok(FieldType::Base(
            matrix
                .par_iter()
                .map(|row| match row {
                    FieldType::Base(content) => Ok(content[column_index]),
                    _ => Err(Error::InvalidPcsParam(
                        "expected base field type".to_string(),
                    )),
                })
                .collect::<Result<Vec<E::BaseField>, Error>>()?,
        ))
    }

    fn get_column_ext(matrix: &[FieldType<E>], column_index: usize) -> Result<FieldType<E>, Error> {
        Ok(FieldType::Ext(
            matrix
                .par_iter()
                .map(|row| match row {
                    FieldType::Ext(content) => Ok(content[column_index]),
                    _ => Err(Error::InvalidPcsParam(
                        "expected ext field type".to_string(),
                    )),
                })
                .collect::<Result<Vec<E>, Error>>()?,
        ))
    }
}

/// Implement the Polynomial Commitment Scheme present in the BaseFold paper
/// https://eprint.iacr.org/2023/1705
///
/// Here is a high-level explanation of the BaseFold PCS.
///
/// BaseFold is the mixture of FRI and Sum-Check for proving the sum-check
/// statement
/// y = \sum_{b\in H} f(b) eq(b, r)
/// where
/// (1) f is the committed multilinear polynomial with n variables
/// (2) H is the n-dimensional hypercube
/// (3) r is the evaluation point (where the polynomial commitment is opened)
/// (4) y is the evaluation result (the opening result)
///
/// To prove this statement, the parties execute the normal sum-check,
/// which reduces the sum-check statement to a evaluation statement of f
/// at random point \alpha sampled during sum-check. Unlike normal sum-check,
/// where this final evaluation statement is delegated to a PCS, in BaseFold
/// this evaluation result is provided by FRI. This is possible because in
/// FRI, the repeated folding of the originally committed codeword is
/// effectively applying the even-odd folding to the message, which is
/// equivalent to applying the evaluating algorithm of multilinear polynomials.
///
/// The commit algorithm is the same as FRI, i.e., encode the polynomial
/// with RS code (or more generally, with a _foldable code_), and commit
/// to the codeword with Merkle tree. The key point is that the encoded
/// message is the coefficient vector (instead of the evaluations over the
/// hypercube), because the FRI folding is working on the coefficients.
///
/// The opening and verification protocol is, similar to FRI, divided into
/// two parts:
/// (1) the committing phase (not to confused with commit algorithm of PCS)
/// (2) the query phase
///
/// The committing phase proceed by interleavingly execute FRI committing phase
/// and the sum-check protocol. More precisely, in each round, the parties
/// execute:
/// (a) The prover sends the partially summed polynomial (sum-check).
/// (b) The verifier samples a challenge (sum-check and FRI).
/// (c) The prover substitutes one variable of the current polynomial
///     at the challenge (sum-check).
/// (d) The prover folds the codeword by the challenge and sends the
///     Merkle root of the folded codeword (FRI).
///
/// At the end of the committing phase:
/// (a) The prover sends the final codeword in the clear (in practice, it
///     suffices to send the message and let the verifier encode it locally
///     to save the proof size).
/// (b) The verifier interprets this last FRI message as a multilinear
///     polynomial, sums it over the hypercube, and compares the sum with
///     the current claimed sum of the sum-check protocol.
///
/// Now the sum-check part of the protocol is finished. The query phase
/// proceed exactly the same as FRI: for each query
/// (a) The verifier samples an index i in the codeword.
/// (b) The prover opens the codeword at i and i XOR 1, and the sequence of
///     folded codewords at the folded positions, i.e., for round k, the
///     positions are (i >> k) and (i >> k) XOR 1.
/// (c) The verifier checks that the folding has been correctly computed
///     at these positions.
impl<E: ExtensionField, Spec: BasefoldSpec<E>> PolynomialCommitmentScheme<E> for Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
    Spec: BasefoldSpec<E, EncodingScheme = RSCode<RSCodeDefaultSpec>>,
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    type Param = BasefoldParams<E, Spec>;
    type ProverParam = BasefoldProverParams<E, Spec>;
    type VerifierParam = BasefoldVerifierParams<E, Spec>;
    type CommitmentWithWitness = BasefoldCommitmentWithWitness<E>;
    type Commitment = BasefoldCommitment<E>;
    type CommitmentChunk = Digest<E>;
    type Proof = BasefoldProof<E>;

    fn setup(poly_size: usize) -> Result<Self::Param, Error> {
        let pp = <Spec::EncodingScheme as EncodingScheme<E>>::setup(log2_strict_usize(poly_size));

        Ok(BasefoldParams { params: pp })
    }

    /// Derive the proving key and verification key from the public parameter.
    /// This step simultaneously trims the parameter for the particular size.
    fn trim(
        pp: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        <Spec::EncodingScheme as EncodingScheme<E>>::trim(pp.params, log2_strict_usize(poly_size))
            .map(|(pp, vp)| {
                (
                    BasefoldProverParams {
                        encoding_params: pp,
                    },
                    BasefoldVerifierParams {
                        encoding_params: vp,
                    },
                )
            })
    }

    fn commit(
        _pp: &Self::ProverParam,
        _rmm: RowMajorMatrix<E::BaseField>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        unimplemented!()
    }

    fn batch_commit(
        pp: &Self::ProverParam,
        rmms: BTreeMap<usize, witness::RowMajorMatrix<<E as ff_ext::ExtensionField>::BaseField>>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        if rmms.is_empty() {
            return Err(Error::InvalidPcsParam(
                "cannot batch commit to zero polynomials".to_string(),
            ));
        }

        let mmcs = poseidon2_merkle_tree::<E>();

        let span = entered_span!("to_mles", profiling_3 = true);
        let (polys, rmm_to_batch_commit, trivial_proofdata, circuit_codeword_index): (
            BTreeMap<usize, Vec<ArcMultilinearExtension<E>>>,
            Vec<_>,
            _,
            _,
        ) = rmms.into_iter().fold(
            (BTreeMap::new(), vec![], BTreeMap::new(), BTreeMap::new()),
            |(
                mut polys,
                mut rmm_to_batch_commit,
                mut trivial_proofdata,
                mut circuit_codeword_index,
            ),
             (index, rmm)| {
                // attach column-based poly
                polys.insert(
                    index,
                    rmm.to_mles().into_iter().map(|p| p.into()).collect_vec(),
                );

                // for smaller polys, we commit it separately as prover will send it as a whole without blowing factor
                if rmm.num_vars() <= Spec::get_basecode_msg_size_log() {
                    let rmm = rmm.into_default_padded_p3_rmm();
                    trivial_proofdata.insert(index, mmcs.commit_matrix(rmm));
                } else {
                    rmm_to_batch_commit.push(rmm);
                    circuit_codeword_index.insert(index, rmm_to_batch_commit.len() - 1);
                }
                (
                    polys,
                    rmm_to_batch_commit,
                    trivial_proofdata,
                    circuit_codeword_index,
                )
            },
        );
        exit_span!(span);

        let span = entered_span!("encode_codeword_and_mle", profiling_3 = true);
        let evals_codewords = rmm_to_batch_commit
            .into_iter()
            .map(|rmm| Spec::EncodingScheme::encode(&pp.encoding_params, rmm))
            .collect::<Result<Vec<DenseMatrix<E::BaseField>>, _>>()?;
        exit_span!(span);

        let span = entered_span!("build mt", profiling_3 = true);
        let (comm, codeword) = mmcs.commit(evals_codewords);
        exit_span!(span);
        let meta_info = polys
            .values()
            .map(|polys| (polys[0].num_vars(), polys.len()))
            .collect_vec();
        Ok(Self::CommitmentWithWitness {
            commit: comm,
            codeword,
            polys,
            meta_info,
            trivial_proofdata,
            circuit_codeword_index,
        })
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        write_digest_to_transcript(&comm.pi_d_digest(), transcript);
        Ok(())
    }

    fn get_pure_commitment(comm: &Self::CommitmentWithWitness) -> Self::Commitment {
        comm.to_commitment()
    }

    /// Open a single polynomial commitment at one point. If the given
    /// commitment with data contains more than one polynomial, this function
    /// will panic.
    fn open(
        _pp: &Self::ProverParam,
        _poly: &ArcMultilinearExtension<E>,
        _comm: &Self::CommitmentWithWitness,
        _point: &[E],
        _eval: &E, // Opening does not need eval, except for sanity check
        _transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        unimplemented!()
    }

    /// Open a batch of polynomial commitments at several points.
    fn batch_open(
        pp: &Self::ProverParam,
        num_instances: &[(usize, usize)],
        fixed_comms: &Self::CommitmentWithWitness,
        witin_comms: &Self::CommitmentWithWitness,
        points: &[Point<E>],
        // TODO this is only for debug purpose
        evals: &[Vec<E>],
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        let span = entered_span!("Basefold::batch_open");

        // sanity check
        // number of point match with commitment length, assuming each commitment are opening under same point
        assert!([points.len(), witin_comms.polys.len(),].iter().all_equal());
        assert!(izip!(&witin_comms.polys, &witin_comms.meta_info,).all(
            |((circuit_index, polys), (num_var, num_polys))| {
                // check num_vars & num_poly match
                polys
                    .iter()
                    .chain(fixed_comms.polys.get(circuit_index).into_iter().flatten())
                    .all(|p| p.num_vars() == *num_var)
                    && polys.len() == *num_polys
            },
        ));
        assert_eq!(num_instances.len(), witin_comms.polys.len());
        assert!(izip!(num_instances, &witin_comms.meta_info).all(
            |((_, num_instance), (num_var, _))| {
                next_pow2_instance_padding(*num_instance).ilog2() as usize == *num_var
            }
        ));

        if cfg!(feature = "sanity-check") {
            // check poly evaluation on point equal eval
            let point_poly_pair = witin_comms
                .polys
                .iter()
                .zip_eq(points)
                .flat_map(|((circuit_index, witin_polys), point)| {
                    let fixed_iter = fixed_comms
                        .polys
                        .get(circuit_index)
                        .into_iter()
                        .flatten()
                        .cloned();
                    let flatten_polys = witin_polys
                        .iter()
                        .cloned()
                        .chain(fixed_iter)
                        .collect::<Vec<ArcMultilinearExtension<E>>>();
                    let points = vec![point.clone(); flatten_polys.len()];
                    izip!(points, flatten_polys)
                })
                .collect::<Vec<(Point<E>, ArcMultilinearExtension<E>)>>();
            assert!(
                point_poly_pair
                    .into_iter()
                    .zip_eq(evals.iter().flatten())
                    .all(|((point, poly), eval)| poly.evaluate(&point) == *eval)
            );
        }

        let max_num_vars = *witin_comms
            .meta_info
            .iter()
            .map(|(num_var, _)| num_var)
            .max()
            .unwrap();

        // identify trivial/non trivial based on size
        let (trivial_witin_polys_and_meta, witin_polys_and_meta) =
            izip!(points, &witin_comms.polys)
                .map(|(point, (circuit_index, polys))| (point, (*circuit_index, polys)))
                .partition(|(_, (_, polys))| {
                    polys[0].num_vars() <= Spec::get_basecode_msg_size_log()
                });

        // Basefold IOP commit phase
        let commit_phase_span = entered_span!("Basefold::open::commit_phase");
        let (trees, commit_phase_proof) = batch_commit_phase::<E, Spec>(
            &pp.encoding_params,
            fixed_comms,
            &witin_comms.codeword,
            witin_polys_and_meta,
            transcript,
            max_num_vars,
            max_num_vars - Spec::get_basecode_msg_size_log(),
        );
        exit_span!(commit_phase_span);

        // for smaller poly, we pass their merkle tree leafs directly
        let commit_trivial_span = entered_span!("Basefold::open::commit_trivial");
        let trivial_proof = if !trivial_witin_polys_and_meta.is_empty() {
            let mmcs = poseidon2_merkle_tree::<E>();
            Some(
                trivial_witin_polys_and_meta
                    .iter()
                    .map(|(_, (circuit_index, _))| {
                        (
                            *circuit_index,
                            mmcs.get_matrices(&witin_comms.trivial_proofdata[circuit_index].1)
                                .into_iter()
                                .take(1)
                                .chain(
                                    // fixed proof is optional
                                    fixed_comms
                                        .trivial_proofdata
                                        .get(circuit_index)
                                        .iter()
                                        .flat_map(|(_, proof_data)| {
                                            mmcs.get_matrices(proof_data).into_iter().take(1)
                                        }),
                                )
                                .cloned()
                                .collect_vec(),
                        )
                    })
                    .collect_vec(),
            )
        } else {
            None
        };
        exit_span!(commit_trivial_span);

        let query_span = entered_span!("Basefold::open::query_phase");
        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let query_opening_proof = batch_query_phase(
            transcript,
            fixed_comms,
            witin_comms,
            &trees,
            Spec::get_number_queries(),
        );
        exit_span!(query_span);

        exit_span!(span);
        Ok(Self::Proof {
            sumcheck_messages: commit_phase_proof.sumcheck_messages,
            commits: commit_phase_proof.commits,
            final_message: commit_phase_proof.final_message,
            query_opening_proof,
            sumcheck_proof: None,
            trivial_proof,
        })
    }

    /// This is a simple version of batch open:
    /// 1. Open at one point
    /// 2. All the polynomials share the same commitment and have the same
    ///    number of variables.
    /// 3. The point is already a random point generated by a sum-check.
    fn simple_batch_open(
        _pp: &Self::ProverParam,
        _polys: &[ArcMultilinearExtension<E>],
        _comm: &Self::CommitmentWithWitness,
        _point: &[E],
        _evals: &[E],
        _transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        unimplemented!()
    }

    fn verify(
        _vp: &Self::VerifierParam,
        _comm: &Self::Commitment,
        _point: &[E],
        _eval: &E,
        _proof: &Self::Proof,
        _transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn batch_verify(
        vp: &Self::VerifierParam,
        num_instances: &[(usize, usize)],
        points: &[Point<E>],
        fixed_comms: &Self::Commitment,
        witin_comms: &Self::Commitment,
        evals: &[Vec<E>],
        proof: &Self::Proof,
        circuit_num_polys: &[(usize, usize)],
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        let mmcs = poseidon2_merkle_tree::<E>();

        assert_eq!(num_instances.len(), points.len());

        let circuit_num_vars = num_instances
            .iter()
            .map(|(index, num_instance)| {
                (
                    *index,
                    next_pow2_instance_padding(*num_instance).ilog2() as usize,
                )
            })
            .collect_vec();

        assert!(
            izip!(&circuit_num_vars, points)
                .all(|((_, circuit_num_var), point)| point.len() == *circuit_num_var)
        );

        // preprocess data into respective group, in particularly, trivials vs non-trivials
        let mut circuit_meta_map = BTreeMap::<usize, CircuitIndexMeta>::new();
        let mut circuit_trivial_meta_map = BTreeMap::<usize, CircuitIndexMeta>::new();
        let mut evals_iter = evals.iter().cloned();
        let (trivial_evals, evals) = izip!(&circuit_num_vars, points).fold(
            (vec![], vec![]),
            |(mut trivial_evals, mut evals), ((circuit_index, num_var), point)| {
                let (expected_witins_num_poly, expected_fixed_num_poly) =
                    &circuit_num_polys[*circuit_index];
                let mut circuit_meta = CircuitIndexMeta {
                    witin_num_vars: *num_var,
                    witin_num_polys: *expected_witins_num_poly,
                    ..Default::default()
                };
                // NOTE: for evals, we concat witin with fixed to make process easier
                if *num_var <= Spec::get_basecode_msg_size_log() {
                    trivial_evals.push(evals_iter.next().unwrap());
                    if *expected_fixed_num_poly > 0 {
                        circuit_meta.fixed_num_vars = *num_var;
                        circuit_meta.fixed_num_polys = *expected_fixed_num_poly;
                        trivial_evals
                            .last_mut()
                            .unwrap()
                            .extend(evals_iter.next().unwrap())
                    }
                    circuit_trivial_meta_map.insert(*circuit_index, circuit_meta);
                } else {
                    evals.push(evals_iter.next().unwrap());
                    if *expected_fixed_num_poly > 0 {
                        circuit_meta.fixed_num_vars = *num_var;
                        circuit_meta.fixed_num_polys = *expected_fixed_num_poly;
                        evals.last_mut().unwrap().extend(evals_iter.next().unwrap());
                    }
                    circuit_meta_map.insert(*circuit_index, circuit_meta);
                }

                (trivial_evals, evals)
            },
        );
        assert!(evals_iter.next().is_none());

        // check trivial proofs
        if !circuit_trivial_meta_map.is_empty() {
            let trivial_fixed_commit =
                BTreeMap::from_iter(fixed_comms.trivial_commits.iter().cloned());
            let trivial_witin_commit =
                BTreeMap::from_iter(witin_comms.trivial_commits.iter().cloned());
            assert!(proof.trivial_proof.is_some());
            assert!(
                circuit_trivial_meta_map
                    .iter()
                    .zip_eq(proof.trivial_proof.as_ref().unwrap())
                    .zip_eq(&witin_comms.trivial_commits)
                    .all(
                        |(((circuit_index1, _), (circuit_index2, _)), (circuit_index3, _))| [
                            circuit_index1,
                            circuit_index2,
                            circuit_index3
                        ]
                        .iter()
                        .all_equal()
                    )
            );

            // 1. check mmcs verify opening
            circuit_trivial_meta_map
                .iter()
                .zip_eq(proof.trivial_proof.as_ref().unwrap())
                .try_for_each(
                    |(
                        (
                            circuit_index,
                            CircuitIndexMeta {
                                fixed_num_polys, ..
                            },
                        ),
                        (_, proof),
                    )| {
                        let witin_commit = trivial_witin_commit
                            .get(circuit_index)
                            .expect("proof must exist");
                        let (commit, _) = mmcs.commit_matrix(proof[0].clone());
                        if commit != *witin_commit {
                            Err(Error::MerkleRootMismatch)?;
                        }
                        if *fixed_num_polys > 0 {
                            let fixed_commit = trivial_fixed_commit
                                .get(circuit_index)
                                .expect("proof must exist");
                            let (commit, _) = mmcs.commit_matrix(proof[1].clone());
                            if commit != *fixed_commit {
                                Err(Error::MerkleRootMismatch)?;
                            }
                        }
                        Ok(())
                    },
                )?;

            // TODO 2. check evaluation equality
        }

        if !circuit_meta_map.is_empty() {
            assert!(
                !proof.final_message.is_empty()
                    && proof
                        .final_message
                        .iter()
                        .map(|final_message| { final_message.len() })
                        .chain(std::iter::once(1 << Spec::get_basecode_msg_size_log()))
                        .all_equal(),
                "final message size should be equal to 1 << Spec::get_basecode_msg_size_log()"
            );
        }

        // verify commit_phase
        let batch_group_size = evals.iter().map(|evals| evals.len()).collect_vec();
        let total_num_polys = batch_group_size.iter().sum();
        let batch_coeffs =
            &transcript.sample_and_append_challenge_pows(total_num_polys, b"batch coeffs");

        let max_num_var = *circuit_num_vars.iter().map(|(_, n)| n).max().unwrap();
        let num_rounds = max_num_var - Spec::get_basecode_msg_size_log();

        let mut fold_challenges: Vec<E> = Vec::with_capacity(max_num_var);
        let commits = &proof.commits;
        let sumcheck_messages = &proof.sumcheck_messages;
        for i in 0..num_rounds {
            transcript.append_field_element_exts(sumcheck_messages[i].as_slice());
            fold_challenges.push(
                transcript
                    .sample_and_append_challenge(b"commit round")
                    .elements,
            );
            if i < num_rounds - 1 {
                write_digest_to_transcript(&commits[i], transcript);
            }
        }
        let final_message = &proof.final_message;
        transcript.append_field_element_exts_iter(proof.final_message.iter().flatten());

        let queries: Vec<_> = transcript.sample_bits_and_append_vec(
            b"query indices",
            Spec::get_number_queries(),
            max_num_var + Spec::get_rate_log(),
        );

        batch_verifier_query_phase::<E, Spec>(
            max_num_var,
            &queries,
            &vp.encoding_params,
            final_message,
            batch_coeffs,
            &proof.query_opening_proof,
            &fixed_comms,
            &witin_comms,
            &circuit_meta_map,
        );

        Ok(())
    }

    fn simple_batch_verify(
        _vp: &Self::VerifierParam,
        _comm: &Self::Commitment,
        _point: &[E],
        _evals: &[E],
        _proof: &Self::Proof,
        _transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        unimplemented!()
        // let timer = start_timer!(|| "Basefold::simple batch verify");
        // let batch_size = evals.len();
        // if let Some(num_polys) = comm.num_polys {
        //     assert_eq!(num_polys, batch_size);
        // }

        // if proof.is_trivial() {
        //     let trivial_proof = proof.trivial_proof.as_ref().unwrap();
        //     let mmcs = poseidon2_merkle_tree::<E>();
        //     let (root, _) = mmcs.commit_matrix(trivial_proof.clone());
        //     if comm.pi_d_digest() == root {
        //         return Ok(());
        //     } else {
        //         return Err(Error::MerkleRootMismatch);
        //     }
        // }

        // let num_vars = point.len();
        // if let Some(comm_num_vars) = comm.num_vars() {
        //     assert_eq!(num_vars, comm_num_vars);
        //     assert!(num_vars >= Spec::get_basecode_msg_size_log());
        // }
        // let num_rounds = num_vars - Spec::get_basecode_msg_size_log();

        // // evals.len() is the batch size, i.e., how many polynomials are being opened together
        // let batch_coeffs =
        //     transcript.sample_and_append_challenge_pows(evals.len(), b"batch coeffs");

        // let mut fold_challenges: Vec<E> = Vec::with_capacity(num_vars);
        // let commits = &proof.commits;
        // let sumcheck_messages = &proof.sumcheck_messages;
        // for i in 0..num_rounds {
        //     transcript.append_field_element_exts(sumcheck_messages[i].as_slice());
        //     fold_challenges.push(
        //         transcript
        //             .sample_and_append_challenge(b"commit round")
        //             .elements,
        //     );
        //     if i < num_rounds - 1 {
        //         write_digest_to_transcript(&commits[i], transcript);
        //     }
        // }
        // let final_message = &proof.final_message[0];
        // transcript.append_field_element_exts(final_message.as_slice());

        // let queries: Vec<_> = transcript.sample_bits_and_append_vec(
        //     b"query indices",
        //     Spec::get_number_queries(),
        //     num_vars + Spec::get_rate_log(),
        // );

        // // coeff is the eq polynomial evaluated at the first challenge.len() variables
        // let coeff = eq_eval(&point[..fold_challenges.len()], &fold_challenges);
        // // Compute eq as the partially evaluated eq polynomial
        // let mut eq = build_eq_x_r_vec(&point[fold_challenges.len()..]);
        // eq.par_iter_mut().for_each(|e| *e *= coeff);

        // simple_batch_verifier_query_phase::<E, Spec>(
        //     queries.as_slice(),
        //     &vp.encoding_params,
        //     &proof.query_opening_proof,
        //     sumcheck_messages,
        //     &fold_challenges,
        //     &batch_coeffs,
        //     num_rounds,
        //     num_vars,
        //     final_message,
        //     commits,
        //     comm,
        //     eq.as_slice(),
        //     evals,
        // );
        // end_timer!(timer);

        // Ok(())
    }

    fn get_arc_mle_witness_from_commitment(
        commitment: &Self::CommitmentWithWitness,
    ) -> Vec<ArcMultilinearExtension<'static, E>> {
        commitment.polys.values().flatten().cloned().collect_vec()
    }
}

#[cfg(test)]
mod test {
    use ff_ext::GoldilocksExt2;

    use crate::{
        basefold::Basefold,
        test_util::{run_commit_open_verify, run_simple_batch_commit_open_verify},
    };

    use super::BasefoldRSParams;

    type PcsGoldilocksRSCode = Basefold<GoldilocksExt2, BasefoldRSParams>;

    #[test]
    fn simple_batch_commit_open_verify_goldilocks() {
        // Both challenge and poly are over base field
        run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(10, 11, 1);
        run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(10, 11, 4);
        // Test trivial proof with small num vars
        run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(4, 6, 4);
    }

    #[test]
    #[ignore = "For benchmarking and profiling only"]
    fn bench_basefold_simple_batch_commit_open_verify_goldilocks() {
        {
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(20, 21);
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(20, 21, 64);
        }
    }
}
