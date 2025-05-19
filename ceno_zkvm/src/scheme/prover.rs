use ff_ext::ExtensionField;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use itertools::{Either, Itertools};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression,
    mle::{ArcMultilinearExtension, IntoMLE, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::build_eq_x_r_vec,
    virtual_polys::VirtualPolynomialsBuilder,
};
use p3::field::{PrimeCharacteristicRing, dot_product};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::iter::Iterator;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProverMessage, IOPProverState},
    util::optimal_sumcheck_threads,
};
use transcript::Transcript;
use witness::{RowMajorMatrix, next_pow2_instance_padding};

use crate::{
    error::ZKVMError,
    scheme::{
        constants::{NUM_FANIN, NUM_FANIN_LOGUP},
        utils::{
            infer_tower_logup_witness, infer_tower_product_witness, masked_mle_split_to_chunks,
            wit_infer_by_expr,
        },
    },
    structs::{
        ProvingKey, TowerProofs, TowerProver, TowerProverSpec, ZKVMProvingKey, ZKVMWitnesses,
    },
    utils::{add_mle_list_by_expr, get_challenge_pows},
};
use multilinear_extensions::{Instance, mle::FieldType};

use super::{PublicValues, ZKVMChipProof, ZKVMProof};

type CreateTableProof<E> = (ZKVMChipProof<E>, HashMap<usize, E>);

pub struct ZKVMProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pk: ZKVMProvingKey<E, PCS>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProver<E, PCS> {
    pub fn new(pk: ZKVMProvingKey<E, PCS>) -> Self {
        ZKVMProver { pk }
    }

    /// create proof for zkvm execution
    #[tracing::instrument(
        skip_all,
        name = "ZKVM_create_proof",
        fields(profiling_1),
        level = "trace"
    )]
    pub fn create_proof(
        &self,
        witnesses: ZKVMWitnesses<E>,
        pi: PublicValues,
        mut transcript: impl Transcript<E>,
    ) -> Result<ZKVMProof<E, PCS>, ZKVMError> {
        let raw_pi = pi.to_vec::<E>();
        let mut pi_evals = ZKVMProof::<E, PCS>::pi_evals(&raw_pi);
        let mut opcode_proofs: BTreeMap<usize, ZKVMChipProof<E>> = BTreeMap::new();
        let mut table_proofs: BTreeMap<usize, ZKVMChipProof<E>> = BTreeMap::new();

        let span = entered_span!("commit_to_pi", profiling_1 = true);
        // including raw public input to transcript
        for v in raw_pi.iter().flatten() {
            transcript.append_field_element(v);
        }
        exit_span!(span);

        let pi: Vec<ArcMultilinearExtension<E>> = raw_pi
            .iter()
            .map(|p| {
                let pi_mle: ArcMultilinearExtension<E> = p.to_vec().into_mle().into();
                pi_mle
            })
            .collect();

        // commit to fixed commitment
        let span = entered_span!("commit_to_fixed_commit", profiling_1 = true);
        if let Some(fixed_commit) = &self.pk.fixed_commit {
            PCS::write_commitment(fixed_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
        }
        exit_span!(span);

        // commit to main traces
        let circuit_name_index_mapping = self
            .pk
            .circuit_pks
            .keys()
            .enumerate()
            .map(|(k, v)| (v, k))
            .collect::<BTreeMap<_, _>>();
        let mut wits_instances = BTreeMap::new();
        let mut wits_rmms = BTreeMap::new();
        let mut structural_wits = BTreeMap::new();

        let mut num_instances = Vec::with_capacity(self.pk.circuit_pks.len());
        for (index, (circuit_name, _)) in self.pk.circuit_pks.iter().enumerate() {
            if let Some(num_instance) = witnesses
                .get_opcode_witness(circuit_name)
                .or_else(|| {
                    witnesses
                        .get_table_witness(circuit_name)
                        .map(|rmms| &rmms[0])
                })
                .map(|rmm| rmm.num_instances())
                .and_then(|num_instance| {
                    if num_instance > 0 {
                        Some(num_instance)
                    } else {
                        None
                    }
                })
            {
                num_instances.push((index, num_instance));
            }
        }

        // write (circuit_size, num_var) to transcript
        for (circuit_size, num_var) in &num_instances {
            transcript.append_message(&circuit_size.to_le_bytes());
            transcript.append_message(&num_var.to_le_bytes());
        }

        let commit_to_traces_span = entered_span!("commit_to_traces", profiling_1 = true);
        // commit to opcode circuits first and then commit to table circuits, sorted by name
        for (circuit_name, mut rmm) in witnesses.into_iter_sorted() {
            let witness_rmm = rmm.remove(0);
            // only table got structural witness
            let structural_witness_rmm = if !rmm.is_empty() {
                rmm.remove(0)
            } else {
                RowMajorMatrix::empty()
            };
            let num_instances = witness_rmm.num_instances();
            wits_instances.insert(circuit_name.clone(), num_instances);
            if num_instances == 0 {
                continue;
            }

            let structural_witness = structural_witness_rmm.to_mles();
            wits_rmms.insert(circuit_name_index_mapping[&circuit_name], witness_rmm);
            structural_wits.insert(
                circuit_name,
                (
                    structural_witness
                        .into_iter()
                        .map(|v| v.into())
                        .collect_vec(),
                    num_instances,
                ),
            );
        }

        debug_assert_eq!(num_instances.len(), wits_rmms.len());

        // batch commit witness
        let span = entered_span!("batch commit to witness", profiling_2 = true);
        let witin_commit_with_witness =
            PCS::batch_commit_and_write(&self.pk.pp, wits_rmms, &mut transcript)
                .map_err(ZKVMError::PCSError)?;
        exit_span!(span);
        // retrieve mle from commitment
        let mut witness_mles = PCS::get_arc_mle_witness_from_commitment(&witin_commit_with_witness);
        let witin_commit = PCS::get_pure_commitment(&witin_commit_with_witness);
        exit_span!(commit_to_traces_span);

        // retrive fixed mle from pk
        let mut fixed_mles =
            PCS::get_arc_mle_witness_from_commitment(self.pk.fixed_commit_wd.as_ref().ok_or(
                ZKVMError::FixedTraceNotFound("there is no fixed trace witness".to_string()),
            )?);

        // squeeze two challenges from transcript
        let challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];
        tracing::debug!("challenges in prover: {:?}", challenges);

        let main_proofs_span = entered_span!("main_proofs", profiling_1 = true);
        let (points, evaluations) = self.pk.circuit_pks.iter().enumerate().try_fold(
            (vec![], vec![]),
            |(mut points, mut evaluations), (index, (circuit_name, pk))| {
                let num_instances = *wits_instances
                    .get(circuit_name)
                    .ok_or(ZKVMError::WitnessNotFound(circuit_name.to_string()))?;
                if num_instances == 0 {
                    // do nothing without point and evaluation insertion
                    return Ok::<(Vec<_>, Vec<Vec<_>>), ZKVMError>((points, evaluations));
                }
                transcript.append_field_element(&E::BaseField::from_u64(index as u64));
                // TODO: add an enum for circuit type either in constraint_system or vk
                let cs = pk.get_cs();
                let witness_mle = witness_mles.drain(..cs.num_witin as usize).collect_vec();
                let is_opcode_circuit = cs.lk_table_expressions.is_empty()
                    && cs.r_table_expressions.is_empty()
                    && cs.w_table_expressions.is_empty();

                if is_opcode_circuit {
                    tracing::debug!(
                        "opcode circuit {} has {} witnesses, {} reads, {} writes, {} lookups",
                        circuit_name,
                        cs.num_witin,
                        cs.r_expressions.len(),
                        cs.w_expressions.len(),
                        cs.lk_expressions.len(),
                    );
                    let (opcode_proof, _) = self.create_chip_proof(
                        circuit_name,
                        pk,
                        vec![],
                        witness_mle,
                        vec![],
                        &pi,
                        num_instances,
                        &mut transcript,
                        &challenges,
                    )?;
                    tracing::info!(
                        "generated proof for opcode {} with num_instances={}",
                        circuit_name,
                        num_instances
                    );
                    points.push(opcode_proof.input_opening_point.clone());
                    evaluations.push(opcode_proof.wits_in_evals.clone());
                    opcode_proofs.insert(index, opcode_proof);
                } else {
                    let fixed_mle = fixed_mles.drain(..cs.num_fixed).collect_vec();
                    let (structural_witness, _) = structural_wits
                        .remove(circuit_name)
                        .ok_or(ZKVMError::WitnessNotFound(circuit_name.clone()))?;
                    assert!(!witness_mle.is_empty());
                    let num_vars = witness_mle[0].num_vars();
                    let (table_proof, pi_in_evals) = self.create_chip_proof(
                        circuit_name,
                        pk,
                        fixed_mle,
                        witness_mle,
                        structural_witness,
                        &pi,
                        1 << num_vars,
                        &mut transcript,
                        &challenges,
                    )?;
                    points.push(table_proof.input_opening_point.clone());
                    evaluations.push(table_proof.wits_in_evals.clone());
                    if cs.num_fixed > 0 {
                        evaluations.push(table_proof.fixed_in_evals.clone());
                    }
                    table_proofs.insert(index, table_proof);
                    for (idx, eval) in pi_in_evals {
                        pi_evals[idx] = eval;
                    }
                };
                Ok((points, evaluations))
            },
        )?;

        // batch opening pcs
        // generate static info from prover key for expected num variable
        let circuit_num_polys = self
            .pk
            .circuit_pks
            .values()
            .map(|pk| (pk.get_cs().num_witin as usize, pk.get_cs().num_fixed))
            .collect_vec();
        let pcs_opening = entered_span!("pcs_opening");
        let mpcs_opening_proof = PCS::batch_open(
            &self.pk.pp,
            &num_instances,
            self.pk.fixed_commit_wd.as_ref(),
            &witin_commit_with_witness,
            &points,
            &evaluations,
            &circuit_num_polys,
            &mut transcript,
        )
        .map_err(ZKVMError::PCSError)?;
        exit_span!(pcs_opening);

        let vm_proof = ZKVMProof::new(
            raw_pi,
            pi_evals,
            opcode_proofs,
            table_proofs,
            witin_commit,
            mpcs_opening_proof,
            // verifier need this information from prover to achieve non-uniform design.
            num_instances,
        );
        exit_span!(main_proofs_span);

        Ok(vm_proof)
    }

    #[allow(clippy::too_many_arguments)]
    /// support batch prove for logup + product arguments each with different num_vars()
    /// side effect: concurrency will be determine based on min(thread, num_vars()),
    /// so suggest dont batch too small table (size < threads) with large table together
    #[tracing::instrument(skip_all, name = "create_chip_proof", fields(table_name=name, profiling_2), level="trace")]
    pub fn create_chip_proof(
        &self,
        name: &str,
        circuit_pk: &ProvingKey<E>,
        fixed: Vec<ArcMultilinearExtension<'_, E>>,
        witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        structural_witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        pi: &[ArcMultilinearExtension<'_, E>],
        num_instances: usize,
        transcript: &mut impl Transcript<E>,
        challenges: &[E; 2],
    ) -> Result<CreateTableProof<E>, ZKVMError> {
        let cs = circuit_pk.get_cs();
        let next_pow2_instances = next_pow2_instance_padding(num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instances);
        let chip_record_alpha = challenges[0];

        let is_opcode_circuit = !cs.lk_expressions.is_empty()
            || !cs.r_expressions.is_empty()
            || !cs.w_expressions.is_empty();

        // sanity check
        assert_eq!(witnesses.len(), cs.num_witin as usize);
        assert_eq!(structural_witnesses.len(), cs.num_structural_witin as usize);
        assert_eq!(fixed.len(), cs.num_fixed);
        // check all witness size are power of 2
        assert!(
            witnesses
                .iter()
                .all(|v| { v.evaluations().len().is_power_of_two() })
        );
        assert!(
            structural_witnesses
                .iter()
                .all(|v| { v.evaluations().len().is_power_of_two() })
        );
        assert!(
            // opcode must have at least one read/write/lookup
            !(cs.r_expressions.is_empty()
                && cs.w_expressions.is_empty()
                && cs.lk_expressions.is_empty())
            ||
                // table must have at least one read/write/lookup
                !(cs.r_table_expressions.is_empty()
                    && cs.w_table_expressions.is_empty()
                    && cs.lk_table_expressions.is_empty())
        );
        assert!(
            cs.r_table_expressions
                .iter()
                .zip_eq(cs.w_table_expressions.iter())
                .all(|(r, w)| r.table_spec.len == w.table_spec.len)
        );

        let wit_inference_span = entered_span!("wit_inference");
        // main constraint: lookup denominator and numerator record witness inference
        let record_span = entered_span!("record");
        let records_wit: Vec<ArcMultilinearExtension<'_, E>> = cs
            .r_table_expressions
            .par_iter()
            .map(|r| &r.expr)
            .chain(cs.r_expressions.par_iter())
            .chain(cs.w_table_expressions.par_iter().map(|w| &w.expr))
            .chain(cs.w_expressions.par_iter())
            .chain(
                cs.lk_table_expressions
                    .par_iter()
                    .map(|lk| &lk.multiplicity),
            )
            .chain(cs.lk_table_expressions.par_iter().map(|lk| &lk.values))
            .chain(cs.lk_expressions.par_iter())
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                wit_infer_by_expr(
                    &fixed,
                    &witnesses,
                    &structural_witnesses,
                    pi,
                    challenges,
                    expr,
                )
            })
            .collect();

        let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
        let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
        let mut remains = records_wit;
        let r_set_wit: Vec<_> = remains.drain(..num_reads).collect();
        let w_set_wit: Vec<_> = remains.drain(..num_writes).collect();
        let lk_n_wit: Vec<_> = remains.drain(..cs.lk_table_expressions.len()).collect();
        let lk_d_wit: Vec<_> = if !cs.lk_table_expressions.is_empty() {
            remains.drain(..cs.lk_table_expressions.len()).collect()
        } else {
            remains.drain(..cs.lk_expressions.len()).collect()
        };

        assert!(remains.is_empty());

        exit_span!(record_span);

        // infer all tower witness after last layer
        let span = entered_span!("tower_witness_last_layer");
        let mut r_set_last_layer = r_set_wit
            .iter()
            .chain(w_set_wit.iter())
            .map(|wit| masked_mle_split_to_chunks(wit, num_instances, NUM_FANIN, E::ONE))
            .collect::<Vec<_>>();
        let w_set_last_layer = r_set_last_layer.split_off(r_set_wit.len());

        let lk_numerator_last_layer = lk_n_wit
            .iter()
            .map(|wit| {
                masked_mle_split_to_chunks(
                    wit,
                    num_instances,
                    NUM_FANIN_LOGUP,
                    // For table circuit, the last layer's length is always two's power
                    // so the padding is not needed, therefore we can use any value here.
                    E::ONE,
                )
            })
            .collect::<Vec<_>>();
        let lk_denominator_last_layer = lk_d_wit
            .iter()
            .map(|wit| {
                let res = masked_mle_split_to_chunks(
                    wit,
                    num_instances,
                    NUM_FANIN_LOGUP,
                    chip_record_alpha,
                );
                assert_eq!(res.len(), NUM_FANIN_LOGUP);
                res
            })
            .collect::<Vec<_>>();
        exit_span!(span);

        let span = entered_span!("tower_tower_witness");
        let r_wit_layers = r_set_last_layer
            .into_iter()
            .zip(r_set_wit.iter())
            .map(|(last_layer, origin_mle)| {
                infer_tower_product_witness(origin_mle.num_vars(), last_layer, NUM_FANIN)
            })
            .collect_vec();
        let w_wit_layers = w_set_last_layer
            .into_iter()
            .zip(w_set_wit.iter())
            .map(|(last_layer, origin_mle)| {
                infer_tower_product_witness(origin_mle.num_vars(), last_layer, NUM_FANIN)
            })
            .collect_vec();
        let lk_wit_layers = if !lk_numerator_last_layer.is_empty() {
            lk_numerator_last_layer
                .into_iter()
                .zip(lk_denominator_last_layer)
                .map(|(lk_n, lk_d)| infer_tower_logup_witness(Some(lk_n), lk_d))
                .collect_vec()
        } else {
            lk_denominator_last_layer
                .into_iter()
                .map(|lk_d| infer_tower_logup_witness(None, lk_d))
                .collect_vec()
        };
        exit_span!(span);
        exit_span!(wit_inference_span);

        if cfg!(test) {
            // sanity check
            assert_eq!(r_wit_layers.len(), cs.r_table_expressions.len());
            assert!(
                r_wit_layers
                    .iter()
                    .zip(r_set_wit.iter()) // depth equals to num_vars
                    .all(|(layers, origin_mle)| layers.len() == origin_mle.num_vars())
            );
            assert!(r_wit_layers.iter().all(|layers| {
                layers.iter().enumerate().all(|(i, w)| {
                    let expected_size = 1 << i;
                    w[0].evaluations().len() == expected_size
                        && w[1].evaluations().len() == expected_size
                })
            }));

            assert_eq!(w_wit_layers.len(), cs.w_table_expressions.len());
            assert!(
                w_wit_layers
                    .iter()
                    .zip(w_set_wit.iter()) // depth equals to num_vars
                    .all(|(layers, origin_mle)| layers.len() == origin_mle.num_vars())
            );
            assert!(w_wit_layers.iter().all(|layers| {
                layers.iter().enumerate().all(|(i, w)| {
                    let expected_size = 1 << i;
                    w[0].evaluations().len() == expected_size
                        && w[1].evaluations().len() == expected_size
                })
            }));

            assert_eq!(lk_wit_layers.len(), cs.lk_table_expressions.len());
            assert!(
                lk_wit_layers
                    .iter()
                    .zip(lk_n_wit.iter()) // depth equals to num_vars
                    .all(|(layers, origin_mle)| layers.len() == origin_mle.num_vars())
            );
            assert!(lk_wit_layers.iter().all(|layers| {
                layers.iter().enumerate().all(|(i, w)| {
                    let expected_size = 1 << i;
                    let (p1, p2, q1, q2) = (&w[0], &w[1], &w[2], &w[3]);
                    p1.evaluations().len() == expected_size
                        && p2.evaluations().len() == expected_size
                        && q1.evaluations().len() == expected_size
                        && q2.evaluations().len() == expected_size
                })
            }));
        }

        let sumcheck_span = entered_span!("sumcheck");
        // product constraint tower sumcheck
        let tower_span = entered_span!("tower");
        // final evals for verifier
        let r_out_evals = r_wit_layers
            .iter()
            .map(|r_wit_layers| {
                r_wit_layers[0]
                    .iter()
                    .map(|mle| mle.get_ext_field_vec()[0])
                    .collect_vec()
            })
            .collect_vec();
        let w_out_evals = w_wit_layers
            .iter()
            .map(|w_wit_layers| {
                w_wit_layers[0]
                    .iter()
                    .map(|mle| mle.get_ext_field_vec()[0])
                    .collect_vec()
            })
            .collect_vec();
        let lk_out_evals = lk_wit_layers
            .iter()
            .map(|lk_wit_layers| {
                lk_wit_layers[0]
                    .iter()
                    .map(|mle| mle.get_ext_field_vec()[0])
                    .collect_vec()
            })
            .collect_vec();

        let (rt_tower, tower_proof) = TowerProver::create_proof(
            // pattern [r1, w1, r2, w2, ...] same pair are chain together
            r_wit_layers
                .into_iter()
                .chain(w_wit_layers.into_iter())
                .map(|wit_layers| TowerProverSpec {
                    witness: wit_layers,
                })
                .collect_vec(),
            lk_wit_layers
                .into_iter()
                .map(|lk_wit_layers| TowerProverSpec {
                    witness: lk_wit_layers,
                })
                .collect_vec(),
            NUM_FANIN_LOGUP,
            transcript,
        );
        assert_eq!(
            rt_tower.len(), // num var length should equal to max_num_instance
            log2_num_instances,
        );
        exit_span!(tower_span);

        // main selector sumcheck / same point sumcheck
        let (input_opening_point, main_sumcheck_proofs) = if is_opcode_circuit {
            let main_sel_span = entered_span!("main_sel");
            let num_threads = optimal_sumcheck_threads(log2_num_instances);
            let alpha_pow = get_challenge_pows(
                num_reads
                    + num_writes
                    + cs.lk_expressions.len()
                    + cs.lk_table_expressions.len()
                    + cs.assert_zero_sumcheck_expressions.len(),
                transcript,
            );
            // create selector: all ONE, but padding ZERO to ceil_log2
            let sel: MultilinearExtension<E> = {
                // TODO sel can be shared if expression count match
                let mut sel = build_eq_x_r_vec(&rt_tower);
                if num_instances < sel.len() {
                    sel.splice(
                        num_instances..sel.len(),
                        std::iter::repeat_n(E::ZERO, sel.len() - num_instances),
                    );
                }
                sel.into_mle()
            };

            // for each j, computes \sum_i coeffs[i] * (mles[i][j] + shifting)
            let linear_combine_mles =
                |coeffs: &[E], mles: &[ArcMultilinearExtension<E>], shifting: E| {
                    assert!(!mles.is_empty());
                    assert_eq!(coeffs.len(), mles.len());

                    let n = mles[0].evaluations().len();

                    // combine into single mle by dot product with coeff
                    (0..n)
                        .into_par_iter()
                        .map(|j| {
                            dot_product::<E, _, _>(
                                mles.iter().map(|mle| match mle.evaluations() {
                                    FieldType::Ext(evals) => evals[j] + shifting,
                                    FieldType::Base(evals) => E::from(evals[j]) + shifting,
                                    _ => unreachable!(),
                                }),
                                // mle_evals.iter().map(|mle_eval| mle_eval[j] + shifting),
                                coeffs.iter().copied(),
                            )
                        })
                        .collect::<Vec<_>>()
                        .into_mle()
                };

            // The relation between the last layer of tower binary tree and read/write/logup records is
            //
            // outs[i][j] = padding + sel[j] * (records[i][j] - padding)
            //
            // it's easy to see the above formula is right because
            //   1. outs[i][j] = padding, if j > num_instances
            //   2. outs[i][j] = records[i][j], otherwise
            //
            // Then we have
            // outs[i](rt) - padding = \sum_j sel[j] * (records[i][j] - padding)

            let mut alpha_offset = 0;
            // r_records_combined is \sum_i alpha^i * (r_records[i][j]-padding) where padding = 1
            let mut r_records_combined: MultilinearExtension<E> = linear_combine_mles(
                &alpha_pow[alpha_offset..alpha_offset + num_reads],
                &r_set_wit,
                E::ONE.neg(),
            );
            alpha_offset += num_reads;

            // w_records_combined is \sum_i alpha^i * (w_records[i][j]-padding) where padding = 1
            let mut w_records_combined: MultilinearExtension<E> = linear_combine_mles(
                &alpha_pow[alpha_offset..(alpha_offset + num_writes)],
                &w_set_wit,
                E::ONE.neg(),
            );
            alpha_offset += num_writes;

            // lk_records_combined is \sum_i alpha^i * (lk_records[i][j]-padding)
            //  where padding = chip_record_alpha
            let mut lk_records_combined: MultilinearExtension<E> = linear_combine_mles(
                &alpha_pow[alpha_offset..(alpha_offset + cs.lk_expressions.len())],
                &lk_d_wit,
                chip_record_alpha.neg(),
            );
            alpha_offset += cs.lk_expressions.len();

            let mut exprs = vec![];
            let mut expr_builder = VirtualPolynomialsBuilder::new(num_threads, log2_num_instances);
            let (sel_expr, r_records_combined, w_records_combined, lk_records_combined) = (
                expr_builder.lift(Either::Left(&sel)),
                expr_builder.lift(Either::Right(&mut r_records_combined)),
                expr_builder.lift(Either::Right(&mut w_records_combined)),
                expr_builder.lift(Either::Right(&mut lk_records_combined)),
            );

            exprs.push(sel_expr * (r_records_combined + w_records_combined + lk_records_combined));

            let mut distrinct_zerocheck_terms_set = BTreeSet::new();
            // degree > 1 zero expression sumcheck
            if !cs.assert_zero_sumcheck_expressions.is_empty() {
                // \sum_t sel(rt, t) * \sum_j alpha_{j} * all_monomial_terms(t)
                for ((expr, name), alpha) in cs
                    .assert_zero_sumcheck_expressions
                    .iter()
                    .zip_eq(cs.assert_zero_sumcheck_expressions_namespace_map.iter())
                    .zip_eq(&alpha_pow[alpha_offset..])
                {
                    // sanity check in debug build and output != instance index for zero check sumcheck poly
                    if cfg!(debug_assertions) {
                        let expected_zero_poly =
                            wit_infer_by_expr(&[], &witnesses, &[], pi, challenges, expr);
                        let top_100_errors = expected_zero_poly
                            .get_base_field_vec()
                            .iter()
                            .enumerate()
                            .filter(|(_, v)| **v != E::BaseField::ZERO)
                            .take(100)
                            .collect_vec();
                        if !top_100_errors.is_empty() {
                            return Err(ZKVMError::InvalidWitness(format!(
                                "degree > 1 zero check virtual poly: expr {name} != 0 on instance indexes: {}...",
                                top_100_errors.into_iter().map(|(i, _)| i).join(",")
                            )));
                        }
                    }

                    distrinct_zerocheck_terms_set.extend(add_mle_list_by_expr(
                        &mut expr_builder,
                        &mut exprs,
                        Some(&sel),
                        witnesses.iter().collect_vec(),
                        expr,
                        challenges,
                        *alpha,
                    ));
                }
            }
            tracing::debug!("main sel sumcheck start");
            let (main_sel_sumcheck_proofs, _) = IOPProverState::prove(
                expr_builder.to_virtual_polys(&[exprs.into_iter().sum()], &[]),
                transcript,
            );
            tracing::debug!("main sel sumcheck end");
            exit_span!(main_sel_span);

            (
                main_sel_sumcheck_proofs.point,
                Some(main_sel_sumcheck_proofs.proofs),
            )
        } else {
            // In table proof, we always skip same point sumcheck for now
            // as tower sumcheck batch product argument/logup in same length

            (rt_tower, None)
        };

        exit_span!(sumcheck_span);
        let span = entered_span!("fixed::evals + witin::evals");
        let mut evals = witnesses
            .par_iter()
            .chain(fixed.par_iter())
            .map(|poly| poly.evaluate(&input_opening_point[..poly.num_vars()]))
            .collect::<Vec<_>>();
        let fixed_in_evals = evals.split_off(witnesses.len());
        let wits_in_evals = evals;

        // evaluate pi if there is instance query
        let mut pi_in_evals: HashMap<usize, E> = HashMap::new();
        if !cs.instance_name_map.is_empty() {
            let span = entered_span!("pi::evals");
            for &Instance(idx) in cs.instance_name_map.keys() {
                let poly = &pi[idx];
                pi_in_evals.insert(idx, poly.evaluate(&input_opening_point[..poly.num_vars()]));
            }
            exit_span!(span);
        }
        exit_span!(span);

        tracing::debug!(
            "[table {}] build opening proof for {} polys",
            name,
            witnesses.len(),
        );

        Ok((
            ZKVMChipProof {
                r_out_evals,
                w_out_evals,
                lk_out_evals,
                main_sumcheck_proofs,
                tower_proof,
                fixed_in_evals,
                wits_in_evals,
                input_opening_point,
            },
            pi_in_evals,
        ))
    }
}

/// TowerProofs
impl<E: ExtensionField> TowerProofs<E> {
    pub fn new(prod_spec_size: usize, logup_spec_size: usize) -> Self {
        TowerProofs {
            proofs: vec![],
            prod_specs_eval: vec![vec![]; prod_spec_size],
            logup_specs_eval: vec![vec![]; logup_spec_size],
            prod_specs_points: vec![vec![]; prod_spec_size],
            logup_specs_points: vec![vec![]; logup_spec_size],
        }
    }
    pub fn push_sumcheck_proofs(&mut self, proofs: Vec<IOPProverMessage<E>>) {
        self.proofs.push(proofs);
    }

    pub fn push_prod_evals_and_point(&mut self, spec_index: usize, evals: Vec<E>, point: Vec<E>) {
        self.prod_specs_eval[spec_index].push(evals);
        self.prod_specs_points[spec_index].push(point);
    }

    pub fn push_logup_evals_and_point(&mut self, spec_index: usize, evals: Vec<E>, point: Vec<E>) {
        self.logup_specs_eval[spec_index].push(evals);
        self.logup_specs_points[spec_index].push(point);
    }

    pub fn prod_spec_size(&self) -> usize {
        self.prod_specs_eval.len()
    }

    pub fn logup_spec_size(&self) -> usize {
        self.logup_specs_eval.len()
    }
}

/// Tower Prover
impl TowerProver {
    #[tracing::instrument(skip_all, name = "tower_prover_create_proof", level = "trace")]
    pub fn create_proof<'a, E: ExtensionField>(
        prod_specs: Vec<TowerProverSpec<'a, E>>,
        logup_specs: Vec<TowerProverSpec<'a, E>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        #[derive(Debug, Clone)]
        enum GroupedMLE<'a, E: ExtensionField> {
            Prod((usize, Vec<MultilinearExtension<'a, E>>)), // usize is the index in prod_specs
            Logup((usize, Vec<MultilinearExtension<'a, E>>)), // usize is the index in logup_specs
        }

        // XXX to sumcheck batched product argument with logup, we limit num_product_fanin to 2
        // TODO mayber give a better naming?
        assert_eq!(num_fanin, 2);

        let (prod_specs_len, logup_specs_len) = (prod_specs.len(), logup_specs.len());
        let mut proofs = TowerProofs::new(prod_specs_len, logup_specs_len);
        let log_num_fanin = ceil_log2(num_fanin);
        // -1 for sliding windows size 2: (cur_layer, next_layer) w.r.t total size
        let max_round_index = prod_specs
            .iter()
            .chain(logup_specs.iter())
            .map(|m| m.witness.len())
            .max()
            .unwrap()
            - 1; // index start from 0

        // generate alpha challenge
        let alpha_pows = get_challenge_pows(
            prod_specs_len +
            // logup occupy 2 sumcheck: numerator and denominator
            logup_specs_len * 2,
            transcript,
        );
        let initial_rt: Point<E> = transcript.sample_and_append_vec(b"product_sum", log_num_fanin);
        let (mut out_rt, mut alpha_pows) = (initial_rt, alpha_pows);

        let mut layer_witness: Vec<Vec<GroupedMLE<'a, E>>> = vec![Vec::new(); max_round_index + 1];

        #[allow(clippy::type_complexity)]
        fn merge_spec_witness<'a, E: ExtensionField>(
            merged: &mut [Vec<GroupedMLE<'a, E>>],
            spec: TowerProverSpec<'a, E>,
            index: usize,
            group_ctor: fn((usize, Vec<MultilinearExtension<'a, E>>)) -> GroupedMLE<'a, E>,
        ) {
            for (round_idx, round_vec) in spec.witness.into_iter().enumerate() {
                merged[round_idx].push(group_ctor((index, round_vec)));
            }
        }

        // merge prod_specs
        for (i, spec) in prod_specs.into_iter().enumerate() {
            merge_spec_witness(&mut layer_witness, spec, i, GroupedMLE::Prod);
        }

        // merge logup_specs
        for (i, spec) in logup_specs.into_iter().enumerate() {
            merge_spec_witness(&mut layer_witness, spec, i, GroupedMLE::Logup);
        }

        // skip(1) for output layer
        for (round, mut layer_witness) in layer_witness.into_iter().enumerate().skip(1) {
            // in first few round we just run on single thread
            let num_threads = optimal_sumcheck_threads(out_rt.len());
            let mut exprs = Vec::<Expression<E>>::with_capacity(prod_specs_len + logup_specs_len);
            let mut expr_builder = VirtualPolynomialsBuilder::new(num_threads, out_rt.len());
            let mut witness_prod_expr = vec![vec![]; prod_specs_len];
            let mut witness_lk_expr = vec![vec![]; logup_specs_len];

            let mut eq: MultilinearExtension<E> = build_eq_x_r_vec(&out_rt).into_mle();
            let eq_expr = expr_builder.lift(Either::Right(&mut eq));

            // processing exprs
            for group_witness in layer_witness.iter_mut() {
                match group_witness {
                    GroupedMLE::Prod((i, layer_polys)) => {
                        let alpha_expr = Expression::Constant(Either::Right(alpha_pows[*i]));
                        // sanity check
                        assert_eq!(layer_polys.len(), num_fanin);
                        assert!(
                            layer_polys
                                .iter()
                                .all(|f| { f.evaluations().len() == 1 << (log_num_fanin * round) })
                        );
                        let layer_polys = layer_polys
                            .iter_mut()
                            .map(|layer_poly| expr_builder.lift(Either::Right(layer_poly)))
                            .collect_vec();
                        witness_prod_expr[*i].extend(layer_polys.clone());
                        let layer_polys_product =
                            layer_polys.into_iter().product::<Expression<E>>();
                        // \sum_s eq(rt, s) * alpha^{i} * ([in_i0[s] * in_i1[s] * .... in_i{num_product_fanin}[s]])
                        exprs.push(eq_expr.clone() * alpha_expr * layer_polys_product);
                    }
                    GroupedMLE::Logup((i, layer_polys)) => {
                        // sanity check
                        assert_eq!(layer_polys.len(), 2 * num_fanin); // p1, p2, q1, q2
                        assert!(
                            layer_polys
                                .iter()
                                .all(|f| f.evaluations().len() == 1 << (log_num_fanin * round)),
                        );

                        let (alpha_numerator, alpha_denominator) = (
                            Expression::Constant(Either::Right(
                                alpha_pows[prod_specs_len + *i * 2], // numerator and denominator
                            )),
                            Expression::Constant(Either::Right(
                                alpha_pows[prod_specs_len + *i * 2 + 1],
                            )),
                        );

                        let (p1, rest) = layer_polys.split_at_mut(1);
                        let (p2, rest) = rest.split_at_mut(1);
                        let (q1, q2) = rest.split_at_mut(1);

                        let (p1, p2, q1, q2) = (
                            expr_builder.lift(Either::Right(&mut p1[0])),
                            expr_builder.lift(Either::Right(&mut p2[0])),
                            expr_builder.lift(Either::Right(&mut q1[0])),
                            expr_builder.lift(Either::Right(&mut q2[0])),
                        );
                        witness_lk_expr[*i].extend(vec![
                            p1.clone(),
                            p2.clone(),
                            q1.clone(),
                            q2.clone(),
                        ]);

                        // \sum_s eq(rt, s) * (alpha_numerator^{i} * (p1 * q2 + p2 * q1) + alpha_denominator^{i} * q1 * q2)
                        exprs.push(
                            eq_expr.clone()
                                * (alpha_numerator * (p1 * q2.clone() + p2 * q1.clone())
                                    + alpha_denominator * q1 * q2),
                        );
                    }
                }
            }

            let wrap_batch_span = entered_span!("wrap_batch");
            let (sumcheck_proofs, state) = IOPProverState::prove(
                expr_builder.to_virtual_polys(&[exprs.into_iter().sum()], &[]),
                transcript,
            );
            exit_span!(wrap_batch_span);

            proofs.push_sumcheck_proofs(sumcheck_proofs.proofs);

            // rt' = r_merge || rt
            let r_merge = transcript.sample_and_append_vec(b"merge", log_num_fanin);
            let rt_prime = [sumcheck_proofs.point, r_merge].concat();

            // generate next round challenge
            let next_alpha_pows = get_challenge_pows(
                prod_specs_len + logup_specs_len * 2, /* logup occupy 2 sumcheck: numerator and denominator */
                transcript,
            );
            let evals = state.get_mle_flatten_final_evaluations();
            // retrieve final evaluation to proof
            for (i, witness_prod_expr) in witness_prod_expr.iter().enumerate().take(prod_specs_len)
            {
                let evals = witness_prod_expr
                    .iter()
                    .map(|expr| match expr {
                        Expression::WitIn(wit_id) => evals[*wit_id as usize],
                        _ => unreachable!(),
                    })
                    .collect_vec();
                if !evals.is_empty() {
                    assert_eq!(evals.len(), num_fanin);
                    proofs.push_prod_evals_and_point(i, evals, rt_prime.clone());
                }
            }
            for (i, witness_lk_expr) in witness_lk_expr.iter().enumerate().take(logup_specs_len) {
                let evals = witness_lk_expr
                    .iter()
                    .map(|expr| match expr {
                        Expression::WitIn(wit_id) => evals[*wit_id as usize],
                        _ => unreachable!(),
                    })
                    .collect_vec();
                if !evals.is_empty() {
                    assert_eq!(evals.len(), 4); // p1, p2, q1, q2
                    proofs.push_logup_evals_and_point(i, evals, rt_prime.clone());
                }
            }
            out_rt = rt_prime;
            alpha_pows = next_alpha_pows;
        }
        let next_rt = out_rt;
        (next_rt, proofs)
    }
}
