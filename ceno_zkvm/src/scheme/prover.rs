use ff_ext::ExtensionField;
use std::collections::{BTreeMap, HashMap};

use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    mle::IntoMLE,
    util::ceil_log2,
    virtual_poly::{ArcMultilinearExtension, build_eq_x_r_vec},
    virtual_polys::VirtualPolynomials,
};
use p3::field::PrimeCharacteristicRing;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProverMessage, IOPProverState},
    util::optimal_sumcheck_threads,
};
use transcript::Transcript;
use witness::{RowMajorMatrix, next_pow2_instance_padding};

use crate::{
    error::ZKVMError,
    expression::Instance,
    scheme::{
        constants::{NUM_FANIN, NUM_FANIN_LOGUP},
        hal::TowerProverSpec,
        utils::{
            infer_tower_logup_witness, infer_tower_product_witness, interleaving_mles_to_mles,
            wit_infer_by_expr,
        },
    },
    structs::{ProofInput, ProvingKey, TowerProofs, TowerProver, ZKVMProvingKey, ZKVMWitnesses},
    utils::{add_mle_list_by_expr, get_challenge_pows},
};

use super::{
    PublicValues, ZKVMOpcodeProof, ZKVMProof, ZKVMTableProof,
    hal::{ProverBackend, ProverDevice},
};

type CreateTableProof<E> = (ZKVMTableProof<E>, HashMap<usize, E>, Point<E>);

pub struct ZKVMProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>, PB, PD> {
    pub pk: ZKVMProvingKey<E, PCS>,
    device: PD,
    _marker: std::marker::PhantomData<PB>,
}

impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    PB: ProverBackend<E = E>,
    PD: ProverDevice<PB>,
> ZKVMProver<E, PCS, PB, PD>
{
    pub fn new(pk: ZKVMProvingKey<E, PCS>, device: PD) -> Self {
        ZKVMProver {
            pk,
            device,
            _marker: std::marker::PhantomData,
        }
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
        pi: PublicValues<u32>,
        mut transcript: impl Transcript<E>,
    ) -> Result<ZKVMProof<E, PCS>, ZKVMError> {
        let raw_pi = pi.to_vec::<E>();
        let mut pi_evals = ZKVMProof::<E, PCS>::pi_evals(&raw_pi);
        let mut opcode_proofs: BTreeMap<usize, ZKVMOpcodeProof<E>> = BTreeMap::new();
        let mut table_proofs: BTreeMap<usize, ZKVMTableProof<E>> = BTreeMap::new();

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
        let (points, evaluations) = self
            .pk
            .circuit_pks
            .iter()
            .enumerate()
            .try_fold((vec![], vec![]), |(mut points, mut evaluations), (index, (circuit_name, pk))| {
                let num_instances = *wits_instances
                .get(circuit_name)
                .ok_or(ZKVMError::WitnessNotFound(circuit_name.to_string()))?;
            if num_instances == 0 {
                // do nothing without point and evaluation insertion
                return Ok::<(Vec<_>, Vec<Vec<_>>), ZKVMError>((points,evaluations));
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
                let (opcode_proof, point) = self.create_opcode_proof(
                    circuit_name,
                    pk,
                    witness_mle,
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
                points.push(point);
                evaluations.push(opcode_proof.wits_in_evals.clone());
                opcode_proofs
                    .insert(index, opcode_proof);
            } else {
                let fixed_mle = fixed_mles.drain(..cs.num_fixed).collect_vec();
                let (structural_witness, structural_num_instances) = structural_wits
                    .remove(circuit_name)
                    .ok_or(ZKVMError::WitnessNotFound(circuit_name.clone()))?;
                let (table_proof, pi_in_evals, point) = self.create_table_proof(
                    circuit_name,
                    pk,
                    fixed_mle,
                    witness_mle,
                    structural_witness,
                    &pi,
                    &mut transcript,
                    &challenges,
                )?;
                points.push(point);
                evaluations.push(table_proof.wits_in_evals.clone());
                if cs.num_fixed > 0 {
                    evaluations.push(table_proof.fixed_in_evals.clone());
                }
                tracing::info!(
                    "generated proof for table {} with num_instances={}, structural_num_instances={}",
                    circuit_name,
                    num_instances,
                    structural_num_instances
                );
                table_proofs.insert(index, table_proof);
                for (idx, eval) in pi_in_evals {
                    pi_evals[idx]= eval;
                }
            };
            Ok((points,evaluations))
            })?;

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
    /// create proof giving witness and num_instances
    /// major flow break down into
    /// 1: witness layer inferring from input -> output
    /// 2: proof (sumcheck reduce) from output to input
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip_all, name = "create_opcode_proof", fields(circuit_name=name,profiling_2), level="trace")]
    pub fn create_opcode_proof(
        &self,
        name: &str,
        circuit_pk: &ProvingKey<E>,
        witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        pi: &[ArcMultilinearExtension<'_, E>],
        num_instances: usize,
        transcript: &mut impl Transcript<E>,
        challenges: &[E; 2],
    ) -> Result<(ZKVMOpcodeProof<E>, Point<E>), ZKVMError> {
        let cs = circuit_pk.get_cs();
        let next_pow2_instances = next_pow2_instance_padding(num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instances);
        let (chip_record_alpha, _) = (challenges[0], challenges[1]);

        // sanity check
        assert_eq!(witnesses.len(), cs.num_witin as usize);
        assert!(
            witnesses
                .iter()
                .all(|v| { v.evaluations().len() == next_pow2_instances })
        );

        let input = ProofInput {
            witness: witnesses,
            public_input: pi.to_vec(),
            num_instances,
        };
        let (prod_specs, logup_spec) = self.device.build_tower_witness(
            input,
            cs.r_expressions.as_slice(),
            cs.w_expressions.as_slice(),
            cs.lk_expressions.as_slice(),
            challenges,
        );
        let (rt_tower, tower_proof) = self
            .device
            .prove_tower_relation(prod_specs, logup_spec, NUM_FANIN, transcript);

        let (input_opening_point, main_sumcheck_proof) = self.device.prove_main_constraints(
            rt_tower.clone(),
            &tower_proof,
            witnesses.clone(),
            pi.to_vec(),
            circuit_pk,
            transcript,
        );
        let span = entered_span!("witin::evals", profiling_3 = true);
        let wits_in_evals: Vec<E> = witnesses
            .par_iter()
            .map(|poly| poly.evaluate(&input_opening_point))
            .collect();
        exit_span!(span);

        let pcs_open_span = entered_span!("pcs_open", profiling_3 = true);
        let opening_dur = std::time::Instant::now();
        tracing::debug!(
            "[opcode {}]: build opening proof for {} polys",
            name,
            witnesses.len()
        );
        tracing::info!(
            "[opcode {}] build opening proof took {:?}",
            name,
            opening_dur.elapsed(),
        );
        exit_span!(pcs_open_span);

        let record_r_out_evals = tower_proof.prod_specs_eval[0][0].clone();
        let record_w_out_evals = tower_proof.prod_specs_eval[1][0].clone();
        let lk_out_evals = tower_proof.logup_specs_eval[0][0].clone();
        let (lk_p1_out_eval, lk_p2_out_eval) =
            (lk_out_evals.pop().unwrap(), lk_out_evals.pop().unwrap());
        let (lk_q1_out_eval, lk_q2_out_eval) =
            (lk_out_evals.pop().unwrap(), lk_out_evals.pop().unwrap());

        Ok((
            ZKVMOpcodeProof {
                record_r_out_evals,
                record_w_out_evals,
                lk_p1_out_eval,
                lk_p2_out_eval,
                lk_q1_out_eval,
                lk_q2_out_eval,
                tower_proof,
                main_sel_sumcheck_proofs: main_sumcheck_proof,
                wits_in_evals,
            },
            input_opening_point,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    /// support batch prove for logup + product arguments each with different num_vars()
    /// side effect: concurrency will be determine based on min(thread, num_vars()),
    /// so suggest dont batch too small table (size < threads) with large table together
    #[tracing::instrument(skip_all, name = "create_table_proof", fields(table_name=name, profiling_2), level="trace")]
    pub fn create_table_proof(
        &self,
        name: &str,
        circuit_pk: &ProvingKey<E>,
        fixed: Vec<ArcMultilinearExtension<'_, E>>,
        witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        structural_witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        pi: &[ArcMultilinearExtension<'_, E>],
        transcript: &mut impl Transcript<E>,
        challenges: &[E; 2],
    ) -> Result<CreateTableProof<E>, ZKVMError> {
        let cs = circuit_pk.get_cs();
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
            !cs.r_table_expressions.is_empty()
                || !cs.w_table_expressions.is_empty()
                || !cs.lk_table_expressions.is_empty()
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
        let mut records_wit: Vec<ArcMultilinearExtension<'_, E>> = cs
            .r_table_expressions
            .par_iter()
            .map(|r| &r.expr)
            .chain(cs.w_table_expressions.par_iter().map(|w| &w.expr))
            .chain(
                cs.lk_table_expressions
                    .par_iter()
                    .map(|lk| &lk.multiplicity),
            )
            .chain(cs.lk_table_expressions.par_iter().map(|lk| &lk.values))
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
        let max_log2_num_instance = records_wit.iter().map(|mle| mle.num_vars()).max().unwrap();
        let min_log2_num_instance = records_wit.iter().map(|mle| mle.num_vars()).min().unwrap();
        let (r_set_wit, remains) = records_wit.split_at_mut(cs.r_table_expressions.len());
        let (w_set_wit, remains) = remains.split_at_mut(cs.w_table_expressions.len());
        let (lk_n_wit, remains) = remains.split_at_mut(cs.lk_table_expressions.len());
        let (lk_d_wit, _empty) = remains.split_at_mut(cs.lk_table_expressions.len());
        assert!(_empty.is_empty());

        exit_span!(record_span);

        // infer all tower witness after last layer
        let span = entered_span!("tower_witness_lk_last_layer");
        let mut r_set_last_layer = r_set_wit
            .iter()
            .chain(w_set_wit.iter())
            .map(|wit| {
                let (first, second) = wit
                    .get_ext_field_vec()
                    .split_at(wit.evaluations().len() / 2);
                let res = vec![
                    first.to_vec().into_mle().into(),
                    second.to_vec().into_mle().into(),
                ];
                assert_eq!(res.len(), NUM_FANIN_LOGUP);
                res
            })
            .collect::<Vec<_>>();
        let w_set_last_layer = r_set_last_layer.split_off(r_set_wit.len());

        let lk_numerator_last_layer = lk_n_wit
            .iter()
            .map(|wit| {
                let (first, second) = wit
                    .get_base_field_vec()
                    .split_at(wit.evaluations().len() / 2);
                let res = vec![
                    first.to_vec().into_mle().into(),
                    second.to_vec().into_mle().into(),
                ];
                assert_eq!(res.len(), NUM_FANIN_LOGUP);
                res
            })
            .collect::<Vec<_>>();
        let lk_denominator_last_layer = lk_d_wit
            .iter_mut()
            .map(|wit| {
                let (first, second) = wit
                    .get_ext_field_vec()
                    .split_at(wit.evaluations().len() / 2);
                let res = vec![
                    first.to_vec().into_mle().into(),
                    second.to_vec().into_mle().into(),
                ];
                assert_eq!(res.len(), NUM_FANIN_LOGUP);
                res
            })
            .collect::<Vec<_>>();
        exit_span!(span);

        let span = entered_span!("tower_witness_lk_layers");
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
        let lk_wit_layers = lk_numerator_last_layer
            .into_iter()
            .zip(lk_denominator_last_layer)
            .map(|(lk_n, lk_d)| infer_tower_logup_witness(Some(lk_n), lk_d))
            .collect_vec();
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
                [
                    r_wit_layers[0][0].get_ext_field_vec()[0],
                    r_wit_layers[0][1].get_ext_field_vec()[0],
                ]
            })
            .collect_vec();
        let w_out_evals = w_wit_layers
            .iter()
            .map(|w_wit_layers| {
                [
                    w_wit_layers[0][0].get_ext_field_vec()[0],
                    w_wit_layers[0][1].get_ext_field_vec()[0],
                ]
            })
            .collect_vec();
        let lk_out_evals = lk_wit_layers
            .iter()
            .map(|lk_wit_layers| {
                [
                    // p1, p2, q1, q2
                    lk_wit_layers[0][0].get_ext_field_vec()[0],
                    lk_wit_layers[0][1].get_ext_field_vec()[0],
                    lk_wit_layers[0][2].get_ext_field_vec()[0],
                    lk_wit_layers[0][3].get_ext_field_vec()[0],
                ]
            })
            .collect_vec();

        let (rt_tower, tower_proof) = TowerProver::create_proof(
            // pattern [r1, w1, r2, w2, ...] same pair are chain together
            r_wit_layers
                .into_iter()
                .zip(w_wit_layers)
                .flat_map(|(r, w)| {
                    vec![
                        TowerProverSpec { witness: r },
                        TowerProverSpec { witness: w },
                    ]
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
            max_log2_num_instance
        );
        exit_span!(tower_span);

        // In table proof, we always skip same point sumcheck for now
        // as tower sumcheck batch product argument/logup in same length
        let is_skip_same_point_sumcheck = true;

        let (input_open_point, same_r_sumcheck_proofs, rw_in_evals, lk_in_evals) =
            if is_skip_same_point_sumcheck {
                (rt_tower, None, vec![], vec![])
            } else {
                // one sumcheck to make them opening on same point r (with different prefix)
                // If all table length are the same, we can skip this sumcheck
                let span = entered_span!("opening_same_point");
                // NOTE: max concurrency will be dominated by smallest table since it will blo
                let num_threads = optimal_sumcheck_threads(min_log2_num_instance);
                let alpha_pow = get_challenge_pows(
                    cs.r_table_expressions.len()
                        + cs.w_table_expressions.len()
                        + cs.lk_table_expressions.len() * 2,
                    transcript,
                );
                let mut alpha_pow_iter = alpha_pow.iter();

                // create eq
                // TODO same size rt lead to same identical poly eq which can be merged together
                let eq = tower_proof
                    .prod_specs_points
                    .iter()
                    .step_by(2) // r,w are in same length therefore share same point
                    .chain(tower_proof.logup_specs_points.iter())
                    .map(|layer_points| {
                        let rt = layer_points.last().unwrap();
                        build_eq_x_r_vec(rt).into_mle().into()
                    })
                    .collect::<Vec<ArcMultilinearExtension<E>>>();

                let (eq_rw, eq_lk) = eq.split_at(cs.r_table_expressions.len());

                let mut virtual_polys =
                    VirtualPolynomials::<E>::new(num_threads, max_log2_num_instance);

                // alpha_r{i} * eq(rt_{i}, s) * r(s) + alpha_w{i} * eq(rt_{i}, s) * w(s)
                for ((r_set_wit, w_set_wit), eq) in r_set_wit
                    .iter()
                    .zip_eq(w_set_wit.iter())
                    .zip_eq(eq_rw.iter())
                {
                    let alpha = alpha_pow_iter.next().unwrap();
                    virtual_polys.add_mle_list(vec![eq, r_set_wit], *alpha);
                    let alpha = alpha_pow_iter.next().unwrap();
                    virtual_polys.add_mle_list(vec![eq, w_set_wit], *alpha);
                }

                // alpha_lkn{i} * eq(rt_{i}, s) * lk_n(s) + alpha_lkd{i} * eq(rt_{i}, s) * lk_d(s)
                for ((lk_n_wit, lk_d_wit), eq) in
                    lk_n_wit.iter().zip_eq(lk_d_wit.iter()).zip_eq(eq_lk.iter())
                {
                    let alpha = alpha_pow_iter.next().unwrap();
                    virtual_polys.add_mle_list(vec![eq, lk_n_wit], *alpha);
                    let alpha = alpha_pow_iter.next().unwrap();
                    virtual_polys.add_mle_list(vec![eq, lk_d_wit], *alpha);
                }

                let (same_r_sumcheck_proofs, state) =
                    IOPProverState::prove(virtual_polys, transcript);
                let evals = state.get_mle_flatten_final_evaluations();
                let mut evals_iter = evals.into_iter();
                let rw_in_evals = cs
                    // r, w table len are identical
                    .r_table_expressions
                    .iter()
                    .flat_map(|_table| {
                        let _eq = evals_iter.next().unwrap(); // skip eq
                        [evals_iter.next().unwrap(), evals_iter.next().unwrap()] // r, w
                    })
                    .collect_vec();
                let lk_in_evals = cs
                    .lk_table_expressions
                    .iter()
                    .flat_map(|_table| {
                        let _eq = evals_iter.next().unwrap(); // skip eq
                        [evals_iter.next().unwrap(), evals_iter.next().unwrap()] // n, d
                    })
                    .collect_vec();
                assert_eq!(evals_iter.count(), 0);

                let input_open_point = same_r_sumcheck_proofs.point.clone();
                assert_eq!(input_open_point.len(), max_log2_num_instance);
                exit_span!(span);

                (
                    input_open_point,
                    Some(same_r_sumcheck_proofs.proofs),
                    rw_in_evals,
                    lk_in_evals,
                )
            };

        exit_span!(sumcheck_span);
        let span = entered_span!("fixed::evals + witin::evals");
        let mut evals = witnesses
            .par_iter()
            .chain(fixed.par_iter())
            .map(|poly| poly.evaluate(&input_open_point[..poly.num_vars()]))
            .collect::<Vec<_>>();
        let fixed_in_evals = evals.split_off(witnesses.len());
        let wits_in_evals = evals;

        // evaluate pi if there is instance query
        let mut pi_in_evals: HashMap<usize, E> = HashMap::new();
        if !cs.instance_name_map.is_empty() {
            let span = entered_span!("pi::evals");
            for &Instance(idx) in cs.instance_name_map.keys() {
                let poly = &pi[idx];
                pi_in_evals.insert(idx, poly.evaluate(&input_open_point[..poly.num_vars()]));
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
            ZKVMTableProof {
                r_out_evals,
                w_out_evals,
                lk_out_evals,
                same_r_sumcheck_proofs,
                rw_in_evals,
                lk_in_evals,
                tower_proof,
                fixed_in_evals,
                wits_in_evals,
            },
            pi_in_evals,
            input_open_point,
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
