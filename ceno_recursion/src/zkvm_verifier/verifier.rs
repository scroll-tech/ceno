use super::binding::{
    ClaimAndPoint, GKRClaimEvaluation, RotationClaim, ZKVMChipProofInputVariable,
    ZKVMProofInputVariable,
};
use crate::{
    arithmetics::{
        PolyEvaluator, UniPolyExtrapolator, assert_ext_arr_eq, challenger_multi_observe, eq_eval,
        eval_ceno_expr_with_instance, eval_wellform_address_vec, mask_arr, reverse,
    },
    basefold_verifier::{
        basefold::{BasefoldCommitmentVariable, RoundOpeningVariable, RoundVariable},
        mmcs::MmcsCommitmentVariable,
        query_phase::PointAndEvalsVariable,
        utils::pow_2,
    },
};
// use crate::basefold_verifier::verifier::batch_verify;
use crate::{
    arithmetics::{
        arr_product, build_eq_x_r_vec_sequential, concat, dot_product as ext_dot_product,
        eq_eval_less_or_equal_than, gen_alpha_pows, nested_product,
    },
    tower_verifier::{
        binding::{PointAndEvalVariable, PointVariable},
        program::{iop_verifier_state_verify, verify_tower_proof},
    },
    transcript::transcript_observe_label,
    zkvm_verifier::binding::{
        EccQuarkProofVariable, GKRProofVariable, LayerProofVariable, SelectorContextVariable,
        SepticExtensionVariable, SepticPointVariable, SumcheckLayerProofVariable,
    },
    basefold_verifier::verifier::batch_verify,
};
use ceno_zkvm::structs::{ComposedConstrainSystem, VerifyingKey, ZKVMVerifyingKey};
use ff_ext::BabyBearExt4;

use gkr_iop::{
    evaluation::EvalExpression,
    gkr::{
        GKRCircuit,
        booleanhypercube::BooleanHypercube,
        layer::{Layer, ROTATION_OPENING_COUNT},
    },
    selector::SelectorType,
};
use itertools::{Itertools, izip};
use mpcs::{Basefold, BasefoldRSParams};
use multilinear_extensions::{
    StructuralWitInType, StructuralWitInType::StackedConstantSequence, expression::Expression,
};
use openvm_native_compiler::prelude::*;
use openvm_native_compiler_derive::iter_zip;
use openvm_native_recursion::challenger::{
    CanObserveVariable, FeltChallenger, duplex::DuplexChallengerVariable,
};
use openvm_stark_backend::p3_field::FieldAlgebra;
use p3::babybear::BabyBear;

type F = BabyBear;
type E = BabyBearExt4;
type Pcs = Basefold<E, BasefoldRSParams>;

const NUM_FANIN: usize = 2;
const SEPTIC_EXTENSION_DEGREE: usize = 7;

pub fn transcript_group_observe_label<C: Config>(
    builder: &mut Builder<C>,
    challenger_group: &mut Vec<DuplexChallengerVariable<C>>,
    label: &[u8],
) {
    for t in challenger_group {
        transcript_observe_label(builder, t, label);
    }
}

pub fn transcript_group_observe_f<C: Config>(
    builder: &mut Builder<C>,
    challenger_group: &mut Vec<DuplexChallengerVariable<C>>,
    f: Felt<C::F>,
) {
    for t in challenger_group {
        t.observe(builder, f);
    }
}

pub fn transcript_group_sample_ext<C: Config>(
    builder: &mut Builder<C>,
    challenger_group: &mut [DuplexChallengerVariable<C>],
) -> Ext<C::F, C::EF> {
    let e: Ext<C::F, C::EF> = challenger_group[0].sample_ext(builder);

    challenger_group.iter_mut().skip(1).for_each(|c| {
        c.sample_ext(builder);
    });

    e
}

pub fn verify_zkvm_proof<C: Config<F = F>>(
    builder: &mut Builder<C>,
    zkvm_proof_input: ZKVMProofInputVariable<C>,
    vk: &ZKVMVerifyingKey<E, Pcs>,
) -> SepticPointVariable<C> {
    let mut challenger = DuplexChallengerVariable::new(builder);
    transcript_observe_label(builder, &mut challenger, b"riscv");

    let prod_r: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
    let prod_w: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
    let logup_sum: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);

    iter_zip!(builder, zkvm_proof_input.raw_pi).for_each(|ptr_vec, builder| {
        let v = builder.iter_ptr_get(&zkvm_proof_input.raw_pi, ptr_vec[0]);
        challenger_multi_observe(builder, &mut challenger, &v);
    });

    iter_zip!(builder, zkvm_proof_input.raw_pi, zkvm_proof_input.pi_evals).for_each(
        |ptr_vec, builder| {
            let raw = builder.iter_ptr_get(&zkvm_proof_input.raw_pi, ptr_vec[0]);
            let eval = builder.iter_ptr_get(&zkvm_proof_input.pi_evals, ptr_vec[1]);
            let raw0 = builder.get(&raw, 0);

            builder.if_eq(raw.len(), Usize::from(1)).then(|builder| {
                let raw0_ext = builder.ext_from_base_slice(&[raw0]);
                builder.assert_ext_eq(raw0_ext, eval);
            });
        },
    );

    builder
        .if_eq(zkvm_proof_input.shard_id.clone(), Usize::from(0))
        .then(|builder| {
            if let Some(fixed_commit) = vk.fixed_commit.as_ref() {
                let commit: crate::basefold_verifier::hash::Hash = fixed_commit.commit().into();
                let commit_array: Array<C, Felt<C::F>> = builder.dyn_array(commit.value.len());

                commit.value.into_iter().enumerate().for_each(|(i, v)| {
                    let v = builder.constant(v);
                    // TODO: put fixed commit to public values
                    // builder.commit_public_value(v);

                    builder.set_value(&commit_array, i, v);
                });

                challenger_multi_observe(builder, &mut challenger, &commit_array);

                let log2_max_codeword_size_felt = builder.constant(C::F::from_canonical_usize(
                    fixed_commit.log2_max_codeword_size,
                ));

                challenger.observe(builder, log2_max_codeword_size_felt);
            }
        });

    builder
        .if_ne(zkvm_proof_input.shard_id.clone(), Usize::from(0))
        .then(|builder| {
            if let Some(fixed_commit) = vk.fixed_no_omc_init_commit.as_ref() {
                let commit: crate::basefold_verifier::hash::Hash = fixed_commit.commit().into();
                let commit_array: Array<C, Felt<C::F>> = builder.dyn_array(commit.value.len());

                commit.value.into_iter().enumerate().for_each(|(i, v)| {
                    let v = builder.constant(v);
                    // TODO: put fixed commit to public values
                    // builder.commit_public_value(v);

                    builder.set_value(&commit_array, i, v);
                });
                challenger_multi_observe(builder, &mut challenger, &commit_array);

                let log2_max_codeword_size_felt = builder.constant(C::F::from_canonical_usize(
                    fixed_commit.log2_max_codeword_size,
                ));

                challenger.observe(builder, log2_max_codeword_size_felt);
            }
        });

    iter_zip!(builder, zkvm_proof_input.chip_proofs).for_each(|ptr_vec, builder| {
        let chip_proofs = builder.iter_ptr_get(&zkvm_proof_input.chip_proofs, ptr_vec[0]);
        let chip_idx = builder.get(&chip_proofs, 0).idx_felt;
        challenger.observe(builder, chip_idx);

        iter_zip!(builder, chip_proofs).for_each(|ptr_vec, builder| {
            let chip_proof = builder.iter_ptr_get(&chip_proofs, ptr_vec[0]);

            iter_zip!(builder, chip_proof.num_instances).for_each(|ptr_vec, builder| {
                let num_instance = builder.iter_ptr_get(&chip_proof.num_instances, ptr_vec[0]);
                let num_instance = builder.unsafe_cast_var_to_felt(num_instance);
                challenger.observe(builder, num_instance);
            });
        });
    });

    challenger_multi_observe(
        builder,
        &mut challenger,
        &zkvm_proof_input.witin_commit.commit.value,
    );
    let log2_max_codeword_size_felt = builder.unsafe_cast_var_to_felt(
        zkvm_proof_input
            .witin_commit
            .log2_max_codeword_size
            .get_var(),
    );
    challenger.observe(builder, log2_max_codeword_size_felt);

    let alpha = challenger.sample_ext(builder);
    let beta = challenger.sample_ext(builder);

    let challenges: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(2);
    builder.set(&challenges, 0, alpha);
    builder.set(&challenges, 1, beta);

    let num_fixed_opening = vk
        .circuit_vks
        .values()
        .filter(|c| c.get_cs().num_fixed() > 0)
        .count();

    let mut unipoly_extrapolator = UniPolyExtrapolator::new(builder);
    let mut poly_evaluator = PolyEvaluator::new(builder);

    let dummy_table_item = alpha;
    let dummy_table_item_multiplicity: Var<C::N> = builder.constant(C::N::ZERO);

    let witin_openings: Array<C, RoundOpeningVariable<C>> =
        builder.dyn_array(zkvm_proof_input.chip_proofs.len());
    let fixed_openings: Array<C, RoundOpeningVariable<C>> =
        builder.dyn_array(zkvm_proof_input.chip_proofs.len());
    let shard_ec_sum = SepticPointVariable {
        x: SepticExtensionVariable {
            vs: builder.dyn_array(7),
        },
        y: SepticExtensionVariable {
            vs: builder.dyn_array(7),
        },
        is_infinity: Usize::uninit(builder),
    };

    let num_chips_verified: Usize<C::N> = builder.eval(C::N::ZERO);
    let num_chips_have_fixed: Usize<C::N> = builder.eval(C::N::ZERO);

    let chip_indices: Array<C, Var<C::N>> = builder.dyn_array(zkvm_proof_input.chip_proofs.len());
    builder
        .range(0, chip_indices.len())
        .for_each(|idx_vec, builder| {
            let i = idx_vec[0];
            let chip_proofs = builder.get(&zkvm_proof_input.chip_proofs, i);
            let chip_idx = builder.get(&chip_proofs, 0).idx;
            builder.set(&chip_indices, i, chip_idx);
        });

    for (i, (circuit_name, chip_vk)) in vk.circuit_vks.iter().enumerate() {
        let circuit_vk = &vk.circuit_vks[circuit_name];
        let chip_id: Var<C::N> = builder.get(&chip_indices, num_chips_verified.get_var());

        builder.if_eq(chip_id, RVar::from(i)).then(|builder| {
            let chip_proofs =
                builder.get(&zkvm_proof_input.chip_proofs, num_chips_verified.get_var());

            iter_zip!(builder, chip_proofs).for_each(|ptr_vec, builder| {
                let chip_proof = builder.iter_ptr_get(&chip_proofs, ptr_vec[0]);
                builder.assert_usize_eq(
                    chip_proof.wits_in_evals.len(),
                    Usize::from(circuit_vk.get_cs().num_witin()),
                );
                builder.assert_usize_eq(
                    chip_proof.fixed_in_evals.len(),
                    Usize::from(circuit_vk.get_cs().num_fixed()),
                );
                builder.assert_usize_eq(
                    chip_proof.r_out_evals.len(),
                    Usize::from(circuit_vk.get_cs().num_reads()),
                );
                builder.assert_usize_eq(
                    chip_proof.w_out_evals.len(),
                    Usize::from(circuit_vk.get_cs().num_writes()),
                );
                builder.assert_usize_eq(
                    chip_proof.lk_out_evals.len(),
                    Usize::from(circuit_vk.get_cs().num_lks()),
                );

                let chip_logup_sum: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
                iter_zip!(builder, chip_proof.lk_out_evals).for_each(|ptr_vec, builder| {
                    let evals = builder.iter_ptr_get(&chip_proof.lk_out_evals, ptr_vec[0]);
                    let p1 = builder.get(&evals, 0);
                    let p2 = builder.get(&evals, 1);
                    let q1 = builder.get(&evals, 2);
                    let q2 = builder.get(&evals, 3);

                    builder.assign(&chip_logup_sum, chip_logup_sum + p1 * q1.inverse());
                    builder.assign(&chip_logup_sum, chip_logup_sum + p2 * q2.inverse());
                });
                challenger.observe(builder, chip_proof.idx_felt);

                if circuit_vk.get_cs().is_with_lk_table() {
                    builder.assign(&logup_sum, logup_sum - chip_logup_sum);
                } else {
                    // getting the number of dummy padding item that we used in this opcode circuit
                    let num_lks: Var<C::N> =
                        builder.eval(C::N::from_canonical_usize(chip_vk.get_cs().num_lks()));

                    // each padding instance contribute to (2^rotation_vars) dummy lookup padding
                    let next_pow2_instance: Var<C::N> =
                        pow_2(builder, chip_proof.log2_num_instances.get_var());
                    let num_padded_instance: Var<C::N> =
                        builder.eval(next_pow2_instance - chip_proof.sum_num_instances.clone());
                    let rotation_var: Var<C::N> = builder.constant(C::N::from_canonical_usize(
                        1 << circuit_vk.get_cs().rotation_vars().unwrap_or(0),
                    ));
                    let rotation_subgroup_size: Var<C::N> =
                        builder.constant(C::N::from_canonical_usize(
                            circuit_vk.get_cs().rotation_subgroup_size().unwrap_or(0),
                        ));
                    builder.assign(&num_padded_instance, num_padded_instance * rotation_var);

                    // each instance contribute to (2^rotation_vars - rotated) dummy lookup padding
                    let num_instance_non_selected: Var<C::N> = builder.eval(
                        chip_proof.sum_num_instances.clone()
                            * (rotation_var - rotation_subgroup_size - C::N::ONE),
                    );
                    let new_multiplicity: Var<C::N> =
                        builder.eval(num_lks * (num_padded_instance + num_instance_non_selected));
                    builder.assign(
                        &dummy_table_item_multiplicity,
                        dummy_table_item_multiplicity + new_multiplicity,
                    );

                    builder.assign(&logup_sum, logup_sum + chip_logup_sum);
                }

                builder.cycle_tracker_start("Verify chip proof");
                let (input_opening_point, chip_shard_ec_sum) = verify_chip_proof(
                    circuit_name,
                    builder,
                    &mut challenger,
                    &chip_proof,
                    &zkvm_proof_input.pi_evals,
                    &zkvm_proof_input.raw_pi,
                    &zkvm_proof_input.raw_pi_num_variables,
                    &challenges,
                    chip_vk,
                    &mut unipoly_extrapolator,
                    &mut poly_evaluator,
                );
                builder.cycle_tracker_end("Verify chip proof");

                let point_clone: Array<C, Ext<C::F, C::EF>> =
                    builder.eval(input_opening_point.clone());

                if circuit_vk.get_cs().num_witin() > 0 {
                    let witin_round: RoundOpeningVariable<C> = builder.eval(RoundOpeningVariable {
                        num_var: input_opening_point.len().get_var(),
                        point_and_evals: PointAndEvalsVariable {
                            point: PointVariable { fs: point_clone },
                            evals: chip_proof.wits_in_evals,
                        },
                    });
                    builder.set_value(&witin_openings, num_chips_verified.get_var(), witin_round);
                }
                if circuit_vk.get_cs().num_fixed() > 0 {
                    let fixed_round: RoundOpeningVariable<C> = builder.eval(RoundOpeningVariable {
                        num_var: input_opening_point.len().get_var(),
                        point_and_evals: PointAndEvalsVariable {
                            point: PointVariable {
                                fs: input_opening_point,
                            },
                            evals: chip_proof.fixed_in_evals,
                        },
                    });

                    builder.set_value(&fixed_openings, num_chips_have_fixed.get_var(), fixed_round);
                    builder.inc(&num_chips_have_fixed);
                }

                let r_out_evals_prod = nested_product(builder, &chip_proof.r_out_evals);
                builder.assign(&prod_r, prod_r * r_out_evals_prod);

                let w_out_evals_prod = nested_product(builder, &chip_proof.w_out_evals);
                builder.assign(&prod_w, prod_w * w_out_evals_prod);

                builder
                    .if_ne(chip_shard_ec_sum.is_infinity.clone(), Usize::from(1))
                    .then(|builder| {
                        add_septic_points_in_place(builder, &shard_ec_sum, &chip_shard_ec_sum);
                    });
            });
            builder.inc(&num_chips_verified);
        });
    }
    builder.assert_eq::<Usize<_>>(num_chips_verified, chip_indices.len());

    let dummy_table_item_multiplicity =
        builder.unsafe_cast_var_to_felt(dummy_table_item_multiplicity);
    builder.assign(
        &logup_sum,
        logup_sum - dummy_table_item_multiplicity * dummy_table_item.inverse(),
    );

    let rounds: Array<C, RoundVariable<C>> = if num_fixed_opening > 0 {
        builder.dyn_array(2)
    } else {
        builder.dyn_array(1)
    };
    builder.set(
        &rounds,
        0,
        RoundVariable {
            commit: zkvm_proof_input.witin_commit,
            openings: witin_openings,
            perm: zkvm_proof_input.witin_perm.clone(),
        },
    );

    if let Some(fixed_commit) = vk.fixed_commit.as_ref() {
        builder
            .if_eq(zkvm_proof_input.shard_id.clone(), Usize::from(0))
            .then(|builder| {
                let commit: crate::basefold_verifier::hash::Hash = fixed_commit.commit().into();
                let commit_array: Array<C, Felt<C::F>> = builder.dyn_array(commit.value.len());

                let log2_max_codeword_size: Var<C::N> = builder.constant(
                    C::N::from_canonical_usize(fixed_commit.log2_max_codeword_size),
                );

                builder.set(
                    &rounds,
                    1,
                    RoundVariable {
                        commit: BasefoldCommitmentVariable {
                            commit: MmcsCommitmentVariable {
                                value: commit_array,
                            },
                            log2_max_codeword_size: log2_max_codeword_size.into(),
                        },
                        openings: fixed_openings.clone(),
                        perm: zkvm_proof_input.fixed_perm.clone(),
                    },
                );
            });
    } else if let Some(fixed_commit) = vk.fixed_no_omc_init_commit.as_ref() {
        builder
            .if_ne(zkvm_proof_input.shard_id.clone(), Usize::from(0))
            .then(|builder| {
                let commit: crate::basefold_verifier::hash::Hash = fixed_commit.commit().into();
                let commit_array: Array<C, Felt<C::F>> = builder.dyn_array(commit.value.len());

                let log2_max_codeword_size: Var<C::N> = builder.constant(
                    C::N::from_canonical_usize(fixed_commit.log2_max_codeword_size),
                );

                builder.set(
                    &rounds,
                    1,
                    RoundVariable {
                        commit: BasefoldCommitmentVariable {
                            commit: MmcsCommitmentVariable {
                                value: commit_array,
                            },
                            log2_max_codeword_size: log2_max_codeword_size.into(),
                        },
                        openings: fixed_openings.clone(),
                        perm: zkvm_proof_input.fixed_perm.clone(),
                    },
                );
            });
    }

    // _debug
    builder.print_debug(666666);
    batch_verify(
        builder,
        zkvm_proof_input.max_num_var,
        zkvm_proof_input.max_width,
        rounds,
        zkvm_proof_input.pcs_proof,
        &mut challenger,
    );

    let empty_arr: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(0);
    let initial_global_state = eval_ceno_expr_with_instance(
        builder,
        &empty_arr,
        &empty_arr,
        &empty_arr,
        &zkvm_proof_input.pi_evals,
        &challenges,
        &vk.initial_global_state_expr,
    );
    builder.assign(&prod_w, prod_w * initial_global_state);

    let finalize_global_state = eval_ceno_expr_with_instance(
        builder,
        &empty_arr,
        &empty_arr,
        &empty_arr,
        &zkvm_proof_input.pi_evals,
        &challenges,
        &vk.finalize_global_state_expr,
    );
    builder.assign(&prod_r, prod_r * finalize_global_state);

    // memory consistency check
    builder.assert_ext_eq(prod_r, prod_w);

    // logup check
    let zero: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    builder.assert_ext_eq(logup_sum, zero);

    shard_ec_sum
}

pub fn verify_chip_proof<C: Config>(
    circuit_name: &str,
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    chip_proof: &ZKVMChipProofInputVariable<C>,
    pi_evals: &Array<C, Ext<C::F, C::EF>>,
    raw_pi: &Array<C, Array<C, Felt<C::F>>>,
    raw_pi_num_variables: &Array<C, Var<C::N>>,
    challenges: &Array<C, Ext<C::F, C::EF>>,
    vk: &VerifyingKey<E>,
    unipoly_extrapolator: &mut UniPolyExtrapolator<C>,
    poly_evaluator: &mut PolyEvaluator<C>,
) -> (Array<C, Ext<C::F, C::EF>>, SepticPointVariable<C>) {
    let composed_cs = vk.get_cs();
    let ComposedConstrainSystem {
        zkvm_v1_css: cs,
        gkr_circuit,
    } = &composed_cs;
    let one: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);

    let r_len = cs.r_expressions.len() + cs.r_table_expressions.len();
    let w_len = cs.w_expressions.len() + cs.w_table_expressions.len();
    let lk_len = cs.lk_expressions.len() + cs.lk_table_expressions.len();
    let num_batched = r_len + w_len + lk_len;

    let r_counts_per_instance: Usize<C::N> = Usize::from(r_len);
    let w_counts_per_instance: Usize<C::N> = Usize::from(w_len);
    let lk_counts_per_instance: Usize<C::N> = Usize::from(lk_len);
    let num_batched: Usize<C::N> = Usize::from(num_batched);

    let log2_num_instances = chip_proof.log2_num_instances.clone();
    if composed_cs.has_ecc_ops() {
        builder.assign(
            &log2_num_instances,
            log2_num_instances.clone() + Usize::from(1),
        );
    }
    let num_var_with_rotation: Usize<C::N> = Usize::Var(Var::uninit(builder));
    builder.assign(
        &num_var_with_rotation,
        log2_num_instances.clone() + Usize::from(composed_cs.rotation_vars().unwrap_or(0)),
    );

    let shard_ec_sum = SepticPointVariable {
        x: SepticExtensionVariable {
            vs: builder.dyn_array(7),
        },
        y: SepticExtensionVariable {
            vs: builder.dyn_array(7),
        },
        is_infinity: Usize::uninit(builder),
    };

    if composed_cs.has_ecc_ops() {
        builder.assert_nonzero(&chip_proof.has_ecc_proof);
        let ecc_proof = &chip_proof.ecc_proof;
        builder.assert_usize_eq(ecc_proof.sum.is_infinity.clone(), Usize::from(0));
        verify_ecc_proof(builder, challenger, ecc_proof, unipoly_extrapolator);
        builder.assign(&shard_ec_sum, ecc_proof.sum.clone());
    } else {
        builder.assign(&shard_ec_sum.is_infinity, Usize::from(1));
    }

    let tower_proof = &chip_proof.tower_proof;
    let num_variables: Array<C, Usize<C::N>> = builder.dyn_array(num_batched);
    builder
        .range(0, num_variables.len())
        .for_each(|idx_vec, builder| {
            builder.set(&num_variables, idx_vec[0], num_var_with_rotation.clone());
        });

    let prod_out_evals: Array<C, Array<C, Ext<C::F, C::EF>>> =
        concat(builder, &chip_proof.r_out_evals, &chip_proof.w_out_evals);
    let num_fanin: Usize<C::N> = Usize::from(NUM_FANIN);

    builder.cycle_tracker_start(format!("verify tower proof for opcode {circuit_name}",).as_str());
    let (_, record_evals, logup_p_evals, logup_q_evals) = verify_tower_proof(
        builder,
        challenger,
        prod_out_evals,
        &chip_proof.lk_out_evals,
        num_variables,
        num_fanin,
        num_var_with_rotation.clone(),
        tower_proof,
        unipoly_extrapolator,
    );
    builder.cycle_tracker_end(format!("verify tower proof for opcode {circuit_name}",).as_str());

    if cs.lk_table_expressions.is_empty() {
        builder
            .range(0, logup_p_evals.len())
            .for_each(|idx_vec, builder| {
                let eval = builder.get(&logup_p_evals, idx_vec[0]).eval;
                builder.assert_ext_eq(eval, one);
            });
    }

    let num_rw_records: Usize<C::N> = builder.eval(r_counts_per_instance + w_counts_per_instance);
    builder.assert_usize_eq(record_evals.len(), num_rw_records.clone());
    builder.assert_usize_eq(logup_p_evals.len(), lk_counts_per_instance.clone());
    builder.assert_usize_eq(logup_q_evals.len(), lk_counts_per_instance.clone());

    // GKR circuit
    let out_evals_len: Usize<C::N> = if cs.lk_table_expressions.is_empty() {
        builder.eval(record_evals.len() + logup_q_evals.len())
    } else {
        builder.eval(record_evals.len() + logup_p_evals.len() + logup_q_evals.len())
    };
    let out_evals: Array<C, PointAndEvalVariable<C>> = builder.dyn_array(out_evals_len.clone());

    builder
        .range(0, record_evals.len())
        .for_each(|idx_vec, builder| {
            let cpt = builder.get(&record_evals, idx_vec[0]);
            builder.set(&out_evals, idx_vec[0], cpt);
        });

    let end: Usize<C::N> = Usize::uninit(builder);
    if !cs.lk_table_expressions.is_empty() {
        builder.assign(&end, record_evals.len() + logup_p_evals.len());
        let p_slice = out_evals.slice(builder, record_evals.len(), end.clone());

        builder
            .range(0, logup_p_evals.len())
            .for_each(|idx_vec, builder| {
                let cpt = builder.get(&logup_p_evals, idx_vec[0]);
                builder.set(&p_slice, idx_vec[0], cpt);
            });
    } else {
        builder.assign(&end, record_evals.len());
    }

    let q_slice = out_evals.slice(builder, end, out_evals_len);
    builder
        .range(0, logup_q_evals.len())
        .for_each(|idx_vec, builder| {
            let cpt = builder.get(&logup_q_evals, idx_vec[0]);
            builder.set(&q_slice, idx_vec[0], cpt);
        });
    let gkr_circuit = gkr_circuit.clone().unwrap();

    let zero_bit_decomps: Array<C, Felt<C::F>> = builder.dyn_array(32);
    let selector_ctxs: Vec<SelectorContextVariable<C>> = if cs.ec_final_sum.is_empty() {
        builder.assert_usize_eq(chip_proof.num_instances.len(), Usize::from(1));
        let num_instances_bit_decomps: Array<C, Array<C, Felt<C::F>>> = builder.dyn_array(1);
        builder.set(
            &num_instances_bit_decomps,
            0,
            chip_proof
                .sum_num_instances_minus_one_bit_decomposition
                .clone(),
        );
        vec![
            SelectorContextVariable {
                offset: Usize::from(0),
                offset_bit_decomps: zero_bit_decomps,
                num_instances: chip_proof.sum_num_instances.clone(),
                num_instances_layered_ns: builder.dyn_array(0), /* Only used in QuarkBinaryTreeLessThan(Expression<E>) */
                num_instances_bit_decomps,
                offset_instance_sum_bit_decomps: chip_proof
                    .sum_num_instances_minus_one_bit_decomposition
                    .clone(),
                num_vars: num_var_with_rotation.clone(),
            };
            gkr_circuit
                .layers
                .first()
                .map(|layer| layer.out_sel_and_eval_exprs.len())
                .unwrap_or(0)
        ]
    } else {
        builder.assert_usize_eq(chip_proof.num_instances.len(), Usize::from(2));

        let num_inst_0_bit_decomps: Array<C, Array<C, Felt<C::F>>> = builder.dyn_array(1);
        let num_inst_1_bit_decomps: Array<C, Array<C, Felt<C::F>>> = builder.dyn_array(1);
        let num_inst_sum_bit_decomps: Array<C, Array<C, Felt<C::F>>> = builder.dyn_array(1);

        builder.set(
            &num_inst_0_bit_decomps,
            0,
            chip_proof.n_inst_0_bit_decomps.clone(),
        );
        builder.set(
            &num_inst_1_bit_decomps,
            0,
            chip_proof.n_inst_1_bit_decomps.clone(),
        );
        builder.set(
            &num_inst_sum_bit_decomps,
            0,
            chip_proof
                .sum_num_instances_minus_one_bit_decomposition
                .clone(),
        );

        vec![
            SelectorContextVariable {
                offset: Usize::from(0),
                offset_bit_decomps: zero_bit_decomps.clone(),
                num_instances: Usize::Var(builder.get(&chip_proof.num_instances, 0)),
                num_instances_layered_ns: builder.dyn_array(0), /* Only used in QuarkBinaryTreeLessThan(Expression<E>) */
                num_instances_bit_decomps: num_inst_0_bit_decomps,
                offset_instance_sum_bit_decomps: chip_proof.n_inst_0_bit_decomps.clone(),
                num_vars: num_var_with_rotation.clone(),
            },
            SelectorContextVariable {
                offset: Usize::Var(builder.get(&chip_proof.num_instances, 0)),
                offset_bit_decomps: chip_proof.n_inst_0_bit_decomps.clone(),
                num_instances: Usize::Var(builder.get(&chip_proof.num_instances, 1)),
                num_instances_layered_ns: builder.dyn_array(0), /* Only used in QuarkBinaryTreeLessThan(Expression<E>) */
                num_instances_bit_decomps: num_inst_1_bit_decomps,
                offset_instance_sum_bit_decomps: chip_proof
                    .sum_num_instances_minus_one_bit_decomposition
                    .clone(),
                num_vars: num_var_with_rotation.clone(),
            },
            SelectorContextVariable {
                offset: Usize::from(0),
                offset_bit_decomps: zero_bit_decomps,
                num_instances: chip_proof.sum_num_instances.clone(),
                num_instances_layered_ns: builder.dyn_array(0), /* Only used in QuarkBinaryTreeLessThan(Expression<E>) */
                num_instances_bit_decomps: num_inst_sum_bit_decomps,
                offset_instance_sum_bit_decomps: chip_proof
                    .sum_num_instances_minus_one_bit_decomposition
                    .clone(),
                num_vars: num_var_with_rotation.clone(),
            },
        ]
    };

    builder.cycle_tracker_start("Verify GKR Circuit");
    let rt = verify_gkr_circuit(
        builder,
        challenger,
        num_var_with_rotation,
        gkr_circuit,
        &chip_proof.gkr_iop_proof,
        challenges,
        pi_evals,
        raw_pi,
        raw_pi_num_variables,
        &out_evals,
        chip_proof,
        selector_ctxs,
        unipoly_extrapolator,
        poly_evaluator,
    );
    builder.cycle_tracker_end("Verify GKR Circuit");

    (rt.fs, shard_ec_sum)
}

pub fn verify_gkr_circuit<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    max_num_variables: Usize<C::N>,
    gkr_circuit: GKRCircuit<E>,
    gkr_proof: &GKRProofVariable<C>,
    challenges: &Array<C, Ext<C::F, C::EF>>,
    pub_io_evals: &Array<C, Ext<C::F, C::EF>>,
    raw_pi: &Array<C, Array<C, Felt<C::F>>>,
    raw_pi_num_variables: &Array<C, Var<C::N>>,
    claims: &Array<C, PointAndEvalVariable<C>>,
    _chip_proof: &ZKVMChipProofInputVariable<C>,
    selector_ctxs: Vec<SelectorContextVariable<C>>,
    unipoly_extrapolator: &mut UniPolyExtrapolator<C>,
    poly_evaluator: &mut PolyEvaluator<C>,
) -> PointVariable<C> {
    let rt = PointVariable {
        fs: builder.dyn_array(0),
    };

    for (i, layer) in gkr_circuit.layers.iter().enumerate() {
        let layer_proof = builder.get(&gkr_proof.layer_proofs, i);
        let layer_challenges: Array<C, Ext<C::F, C::EF>> =
            generate_layer_challenges(builder, challenger, challenges, layer.n_challenges);
        let eval_and_dedup_points: Array<C, ClaimAndPoint<C>> = extract_claim_and_point(
            builder,
            layer,
            claims,
            &layer_challenges,
            &layer_proof.has_rotation,
        );

        if layer.rotation_sumcheck_expression.is_some() {
            builder.assert_usize_eq(
                Usize::from(layer.out_sel_and_eval_exprs.len() + 3),
                eval_and_dedup_points.len(),
            );
        } else {
            builder.assert_usize_eq(
                Usize::from(layer.out_sel_and_eval_exprs.len()),
                eval_and_dedup_points.len(),
            );
        }

        // ZeroCheckLayer verification (might include other layer types in the future)
        let LayerProofVariable {
            main:
                SumcheckLayerProofVariable {
                    proof,
                    evals: main_evals,
                    evals_len_div_3: _main_evals_len_div_3,
                },
            rotation: rotation_proof,
            has_rotation,
        } = layer_proof;

        let expected_main_evals_len: Usize<C::N> = Usize::from(
            layer.n_witin + layer.n_fixed + layer.n_instance + layer.n_structural_witin,
        );
        builder.assert_usize_eq(expected_main_evals_len, main_evals.len());

        if layer.rotation_sumcheck_expression.is_some() {
            builder.if_eq(has_rotation, Usize::from(1)).then(|builder| {
                let first = builder.get(&eval_and_dedup_points, 0);
                builder.assert_usize_eq(first.has_point, Usize::from(1)); // Rotation proof should have at least one point
                let rt = builder.eval(first.point.fs.clone());

                let RotationClaim {
                    left_evals,
                    right_evals,
                    target_evals,
                    left_point,
                    right_point,
                    origin_point,
                } = verify_rotation(
                    builder,
                    challenger,
                    max_num_variables.clone(),
                    layer.rotation_exprs.1.len(),
                    layer.rotation_sumcheck_expression.as_ref().unwrap(),
                    &rotation_proof,
                    layer.rotation_cyclic_subgroup_size,
                    layer.rotation_cyclic_group_log2,
                    rt,
                    challenges,
                    unipoly_extrapolator,
                );

                // extend eval_and_dedup_points by
                //  [
                //     (left_evals, left_point),
                //     (right_evals, right_point),
                //     (target_evals, origin_point),
                //  ]
                let last_idx: Usize<C::N> =
                    builder.eval(eval_and_dedup_points.len() - Usize::from(1));
                builder.set(
                    &eval_and_dedup_points,
                    last_idx.clone(),
                    ClaimAndPoint {
                        evals: target_evals,
                        has_point: Usize::from(1),
                        point: PointVariable { fs: origin_point },
                    },
                );

                builder.assign(&last_idx, last_idx.clone() - Usize::from(1));
                builder.set(
                    &eval_and_dedup_points,
                    last_idx.clone(),
                    ClaimAndPoint {
                        evals: right_evals,
                        has_point: Usize::from(1),
                        point: PointVariable { fs: right_point },
                    },
                );

                builder.assign(&last_idx, last_idx.clone() - Usize::from(1));
                builder.set(
                    &eval_and_dedup_points,
                    last_idx.clone(),
                    ClaimAndPoint {
                        evals: left_evals,
                        has_point: Usize::from(1),
                        point: PointVariable { fs: left_point },
                    },
                );
            });
        }

        let rotation_exprs_len = layer.rotation_exprs.1.len();
        transcript_observe_label(builder, challenger, b"combine subset evals");
        let alpha_pows = gen_alpha_pows(
            builder,
            challenger,
            Usize::from(layer.exprs.len() + rotation_exprs_len * ROTATION_OPENING_COUNT),
        );

        let sigma: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
        let alpha_idx: Usize<C::N> = Usize::Var(Var::uninit(builder));
        builder.assign(&alpha_idx, C::N::from_canonical_usize(0));

        // sigma = \sum_i alpha^i * evals_i
        builder
            .range(0, eval_and_dedup_points.len())
            .for_each(|idx_vec, builder| {
                let ClaimAndPoint {
                    evals,
                    has_point: _,
                    point: _,
                } = builder.get(&eval_and_dedup_points, idx_vec[0]);
                let end_idx: Usize<C::N> = builder.eval(alpha_idx.clone() + evals.len());
                let alpha_slice: Array<C, Ext<<C as Config>::F, <C as Config>::EF>> =
                    alpha_pows.slice(builder, alpha_idx.clone(), end_idx.clone());

                let sub_sum = ext_dot_product(builder, &evals, &alpha_slice);
                builder.assign(&sigma, sigma + sub_sum);
                builder.assign(&alpha_idx, end_idx);
            });

        // sigma = \sum_b sel(b) * zero_expr(b)
        let max_degree = builder.constant(C::F::from_canonical_usize(layer.max_expr_degree + 1));

        let max_num_variables_f = builder.unsafe_cast_var_to_felt(max_num_variables.get_var());

        let (in_point, expected_evaluation) = iop_verifier_state_verify(
            builder,
            challenger,
            &sigma,
            &proof,
            max_num_variables_f,
            max_degree,
            unipoly_extrapolator,
        );

        let structural_witin_offset = layer.n_witin + layer.n_fixed + layer.n_instance;

        // check selector evaluations
        layer
            .out_sel_and_eval_exprs
            .iter()
            .enumerate()
            .for_each(|(idx, (sel_type, _))| {
                let out_point = builder.get(&eval_and_dedup_points, idx).point.fs;
                let ctx = &selector_ctxs[idx];

                let (wit_id, expected_eval) =
                    evaluate_selector(builder, sel_type, &out_point, &in_point, ctx);

                let wit_id = wit_id + structural_witin_offset;
                let main_eval = builder.get(&main_evals, wit_id);
                builder.assert_ext_eq(main_eval, expected_eval);
            });

        let zero_const = builder.constant::<Ext<C::F, C::EF>>(C::EF::ZERO);
        // check structural witin
        for s in &layer.structural_witins {
            let id = s.id;
            let witin_type = s.witin_type;

            let wit_id = id as usize + structural_witin_offset;
            let expected_eval: Ext<C::F, C::EF> = match witin_type {
                StructuralWitInType::EqualDistanceSequence {
                    offset,
                    multi_factor,
                    descending,
                    ..
                } => {
                    let offset =
                        builder.constant::<Ext<C::F, C::EF>>(C::EF::from_canonical_u32(offset));
                    eval_wellform_address_vec(
                        builder,
                        offset,
                        multi_factor as u32,
                        &in_point,
                        descending,
                    )
                }
                StructuralWitInType::EqualDistanceDynamicSequence {
                    multi_factor,
                    descending,
                    offset_instance_id,
                    ..
                } => {
                    // retrieve offset from public values
                    let offset = builder.get(pub_io_evals, offset_instance_id as usize);
                    eval_wellform_address_vec(
                        builder,
                        offset,
                        multi_factor as u32,
                        &in_point,
                        descending,
                    )
                }
                StructuralWitInType::StackedIncrementalSequence { .. } => {
                    let res: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
                    let one_ext: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
                    let r_len = in_point.len();

                    builder
                        .if_ne(r_len.clone(), Usize::from(0))
                        .then(|builder| {
                            builder
                                .if_ne(r_len.clone(), Usize::from(1))
                                .then(|builder| {
                                    builder
                                        .range(1, r_len.clone())
                                        .for_each(|idx_vec, builder| {
                                            let i = idx_vec[0];
                                            let r_i = builder.get(&in_point, i);

                                            let r_slice = &in_point.slice(builder, 0, i);
                                            let eval = eval_wellform_address_vec(
                                                builder, zero_const, 1, r_slice, false,
                                            );
                                            builder
                                                .assign(&res, res * (one_ext - r_i) + eval * r_i);
                                        });
                                });
                        });

                    res
                }
                StructuralWitInType::StackedConstantSequence { .. } => {
                    let res: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
                    let one_ext: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
                    let i_ext: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
                    let r_len = in_point.len();

                    builder
                        .if_ne(r_len.clone(), Usize::from(0))
                        .then(|builder| {
                            builder
                                .if_ne(r_len.clone(), Usize::from(1))
                                .then(|builder| {
                                    builder
                                        .range(1, r_len.clone())
                                        .for_each(|idx_vec, builder| {
                                            let i = idx_vec[0];
                                            let r_i = builder.get(&in_point, i);

                                            builder
                                                .assign(&res, res * (one_ext - r_i) + i_ext * r_i);
                                            builder.assign(&i_ext, i_ext + one_ext);
                                        });
                                });
                        });

                    res
                }
                StructuralWitInType::InnerRepeatingIncrementalSequence { k, .. } => {
                    let r_slice = in_point.slice(builder, k, in_point.len());
                    eval_wellform_address_vec(builder, zero_const, 1, &r_slice, false)
                }
                StructuralWitInType::OuterRepeatingIncrementalSequence { k, .. } => {
                    let r_slice = in_point.slice(builder, 0, k);
                    eval_wellform_address_vec(builder, zero_const, 1, &r_slice, false)
                }
                StructuralWitInType::Empty => continue,
            };

            let main_wit_eval = builder.get(&main_evals, wit_id);
            builder.assert_ext_eq(expected_eval, main_wit_eval);
        }

        let pubio_offset = layer.n_witin + layer.n_fixed;
        for (index, instance) in layer.instance_openings.iter().enumerate() {
            let index: usize = pubio_offset + index;
            let poly = builder.get(raw_pi, instance.0);
            let num_variable = builder.get(raw_pi_num_variables, instance.0);
            let in_point_slice = in_point.slice(builder, 0, num_variable);
            let expected_eval =
                poly_evaluator.evaluate_base_poly_at_point(builder, &poly, &in_point_slice);
            let main_eval = builder.get(&main_evals, index);
            builder.assert_ext_eq(expected_eval, main_eval);
        }

        // TODO: we should store alpha_pows in a bigger array to avoid concatenating them
        let main_sumcheck_challenges_len: Usize<C::N> =
            builder.eval(alpha_pows.len() + Usize::from(2));
        let main_sumcheck_challenges: Array<C, Ext<C::F, C::EF>> =
            builder.dyn_array(main_sumcheck_challenges_len.clone());
        let alpha = builder.get(challenges, 0);
        let beta = builder.get(challenges, 1);
        builder.set(&main_sumcheck_challenges, 0, alpha);
        builder.set(&main_sumcheck_challenges, 1, beta);
        let challenge_slice =
            main_sumcheck_challenges.slice(builder, 2, main_sumcheck_challenges_len);
        builder
            .range(0, alpha_pows.len())
            .for_each(|idx_vec, builder| {
                let alpha = builder.get(&alpha_pows, idx_vec[0]);
                builder.set(&challenge_slice, idx_vec[0], alpha);
            });

        let empty_arr: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(0);
        let got_claim = eval_ceno_expr_with_instance(
            builder,
            &empty_arr,
            &main_evals,
            &empty_arr,
            pub_io_evals,
            &main_sumcheck_challenges,
            layer.main_sumcheck_expression.as_ref().unwrap(),
        );

        builder.assert_ext_eq(got_claim, expected_evaluation);

        // Update claim
        layer
            .in_eval_expr
            .iter()
            .enumerate()
            .for_each(|(idx, pos)| {
                let val = builder.get(&main_evals, idx);
                let new_point: Array<C, Ext<C::F, C::EF>> = builder.eval(in_point.clone());
                let new_point_eval = builder.eval(PointAndEvalVariable {
                    point: PointVariable { fs: new_point },
                    eval: val,
                });
                builder.set_value(claims, *pos, new_point_eval);
            });

        builder.assign(&rt.fs, in_point);
    }

    // GKR Claim
    let input_layer = gkr_circuit.layers.last().unwrap();
    input_layer
        .in_eval_expr
        .iter()
        .enumerate()
        .map(|(poly, pos)| {
            let PointAndEvalVariable { point, eval } = builder.get(claims, *pos);
            GKRClaimEvaluation {
                value: eval,
                point,
                poly: Usize::from(poly),
            }
        })
        .collect_vec();

    rt
}

pub fn verify_rotation<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    max_num_variables: Usize<C::N>,
    num_rotations: usize,
    rotation_sumcheck_expression: &Expression<E>,
    rotation_proof: &SumcheckLayerProofVariable<C>,
    rotation_cyclic_subgroup_size: usize,
    rotation_cyclic_group_log2: usize,
    rt: Array<C, Ext<C::F, C::EF>>,
    challenges: &Array<C, Ext<C::F, C::EF>>,
    unipoly_extrapolator: &mut UniPolyExtrapolator<C>,
) -> RotationClaim<C> {
    builder.cycle_tracker_start("Verify rotation");
    let SumcheckLayerProofVariable {
        proof,
        evals,
        evals_len_div_3: rotation_expr_len,
    } = rotation_proof;

    let rotation_expr_len = Usize::Var(*rotation_expr_len);
    transcript_observe_label(builder, challenger, b"combine subset evals");
    let rotation_alpha_pows = gen_alpha_pows(builder, challenger, Usize::from(num_rotations));
    let rotation_challenges = concat(builder, challenges, &rotation_alpha_pows);
    let sigma: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);

    let max_num_variables = builder.unsafe_cast_var_to_felt(max_num_variables.get_var());
    let max_degree: Felt<C::F> = builder.constant(C::F::TWO);

    let (origin_point, expected_evaluation) = iop_verifier_state_verify(
        builder,
        challenger,
        &sigma,
        proof,
        max_num_variables,
        max_degree,
        unipoly_extrapolator,
    );

    // compute the selector evaluation
    let selector_eval = rotation_selector_eval(
        builder,
        &rt,
        &origin_point,
        rotation_cyclic_subgroup_size,
        rotation_cyclic_group_log2,
    );

    // check the final evaluations.
    let left_evals: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(rotation_expr_len.clone());
    let right_evals: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(rotation_expr_len.clone());
    let target_evals: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(rotation_expr_len.clone());

    let witness_len = Usize::uninit(builder);
    builder.assign(
        &witness_len,
        rotation_expr_len.clone() * Usize::from(2) + Usize::from(1),
    );
    let witnesses: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(witness_len);

    let rvar3 = RVar::from(3);
    let rvar2 = RVar::from(2);
    let one: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
    let last_origin = if rotation_cyclic_group_log2 > 0 {
        builder.get(&origin_point, rotation_cyclic_group_log2 - 1)
    } else {
        one
    };

    builder
        .range(0, rotation_expr_len)
        .for_each(|idx_vec, builder| {
            let left_idx: Var<C::N> = builder.eval(idx_vec[0] * rvar3);
            let right_idx: Var<C::N> = builder.eval(idx_vec[0] * rvar3 + RVar::from(1));
            let target_idx: Var<C::N> = builder.eval(idx_vec[0] * rvar3 + RVar::from(2));

            let left = builder.get(evals, left_idx);
            let right = builder.get(evals, right_idx);
            let target = builder.get(evals, target_idx);

            builder.set(&left_evals, idx_vec[0], left);
            builder.set(&right_evals, idx_vec[0], right);
            builder.set(&target_evals, idx_vec[0], target);

            let claim_witness_idx: Var<C::N> = builder.eval(idx_vec[0] * rvar2);
            let target_witness_idx: Var<C::N> = builder.eval(idx_vec[0] * rvar2 + RVar::from(1));

            let claim: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
            builder.assign(&claim, (one - last_origin) * left + last_origin * right);

            builder.set(&witnesses, claim_witness_idx, claim);
            builder.set(&witnesses, target_witness_idx, target);
        });
    let last_idx = Usize::uninit(builder);
    builder.assign(&last_idx, witnesses.len() - Usize::from(1));
    builder.set(&witnesses, last_idx, selector_eval);

    let empty_arr: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(0);
    let got_claim = eval_ceno_expr_with_instance(
        builder,
        &empty_arr,
        &witnesses,
        &empty_arr,
        &empty_arr,
        &rotation_challenges,
        rotation_sumcheck_expression,
    );

    builder.assert_ext_eq(got_claim, expected_evaluation);

    let (left_point, right_point) =
        get_rotation_points(builder, rotation_cyclic_group_log2, &origin_point);

    builder.cycle_tracker_end("Verify rotation");

    RotationClaim {
        left_evals,
        right_evals,
        target_evals,
        left_point,
        right_point,
        origin_point,
    }
}

/// sel(rx)
/// = (\sum_{b = 0}^{cyclic_subgroup_size - 1} eq(out_point[..cyclic_group_log2_size], b) * eq(in_point[..cyclic_group_log2_size], b))
///     * \prod_{k = cyclic_group_log2_size}^{n - 1} eq(out_point[k], in_point[k])
pub fn rotation_selector_eval<C: Config>(
    builder: &mut Builder<C>,
    out_point: &Array<C, Ext<C::F, C::EF>>,
    in_point: &Array<C, Ext<C::F, C::EF>>,
    rotation_cyclic_subgroup_size: usize,
    cyclic_group_log2_size: usize,
) -> Ext<C::F, C::EF> {
    let bh = BooleanHypercube::new(5);
    let eval: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    let rotation_index = bh
        .into_iter()
        .take(rotation_cyclic_subgroup_size)
        .collect_vec();

    let out_subgroup = out_point.slice(builder, 0, cyclic_group_log2_size);
    let in_subgroup = in_point.slice(builder, 0, cyclic_group_log2_size);
    let out_subgroup_eq = build_eq_x_r_vec_sequential(builder, &out_subgroup);
    let in_subgroup_eq = build_eq_x_r_vec_sequential(builder, &in_subgroup);

    for b in rotation_index {
        let out_v = builder.get(&out_subgroup_eq, b as usize);
        let in_v = builder.get(&in_subgroup_eq, b as usize);
        builder.assign(&eval, eval + in_v * out_v);
    }

    let out_subgroup = out_point.slice(builder, cyclic_group_log2_size, out_point.len());
    let in_subgroup = in_point.slice(builder, cyclic_group_log2_size, in_point.len());

    let one: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
    let zero: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);

    let eq_eval = eq_eval(builder, &out_subgroup, &in_subgroup, one, zero);
    builder.assign(&eval, eval * eq_eval);

    eval
}

pub fn evaluate_selector<C: Config>(
    builder: &mut Builder<C>,
    sel_type: &SelectorType<E>,
    out_point: &Array<C, Ext<C::F, C::EF>>,
    in_point: &Array<C, Ext<C::F, C::EF>>,
    ctx: &SelectorContextVariable<C>,
) -> (usize, Ext<C::F, C::EF>) {
    let (expr, eval) = match sel_type {
        SelectorType::None => {
            let r = builder.constant(C::EF::ZERO);
            return (0, r);
        }
        SelectorType::Whole(expr) => {
            let one = builder.constant(C::EF::ONE);
            let zero = builder.constant(C::EF::ZERO);
            (expr, eq_eval(builder, out_point, in_point, one, zero))
        }
        SelectorType::Prefix(expr) => {
            let start = ctx.offset.clone();
            let end: Usize<C::N> = builder.eval(start.clone() + ctx.num_instances.clone());
            builder.assert_usize_eq(in_point.len(), out_point.len());

            let sel: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);

            builder.if_ne(end, Usize::from(0)).then(|builder| {
                let eq_end = eq_eval_less_or_equal_than(
                    builder,
                    &ctx.offset_instance_sum_bit_decomps,
                    out_point,
                    in_point,
                );
                builder.assign(&sel, eq_end);

                builder
                    .if_ne(start.clone(), Usize::from(0))
                    .then(|builder| {
                        let eq_start = eq_eval_less_or_equal_than(
                            builder,
                            &ctx.offset_bit_decomps,
                            out_point,
                            in_point,
                        );
                        builder.assign(&sel, sel - eq_start);
                    });
            });

            (expr, sel)
        }
        SelectorType::OrderedSparse32 {
            indices,
            expression,
        } => {
            let out_point_slice = out_point.slice(builder, 0, 5);
            let in_point_slice = in_point.slice(builder, 0, 5);
            let out_subgroup_eq = build_eq_x_r_vec_sequential(builder, &out_point_slice);
            let in_subgroup_eq = build_eq_x_r_vec_sequential(builder, &in_point_slice);

            let eval: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
            for idx in indices {
                let out_val = builder.get(&out_subgroup_eq, *idx);
                let in_val = builder.get(&in_subgroup_eq, *idx);
                builder.assign(&eval, eval + out_val * in_val);
            }

            let out_point_slice = out_point.slice(builder, 5, out_point.len());
            let in_point_slice = in_point.slice(builder, 5, in_point.len());
            let n_bits = builder.get(&ctx.num_instances_bit_decomps, 0);

            let sel =
                eq_eval_less_or_equal_than(builder, &n_bits, &out_point_slice, &in_point_slice);
            builder.assign(&eval, eval * sel);

            (expression, eval)
        }
        SelectorType::QuarkBinaryTreeLessThan(expr) => {
            builder.assert_nonzero(&ctx.num_instances);
            builder.assert_nonzero(&out_point.len());
            builder.assert_usize_eq(in_point.len(), out_point.len());

            let prefix_one_seq: Array<C, Usize<C::N>> = builder.dyn_array(out_point.len());
            let prefix_one_seq_minus_one_bits: Array<C, Array<C, Felt<C::F>>> =
                builder.dyn_array(out_point.len());
            let zero_bit_decomp: Array<C, Felt<C::F>> = builder.dyn_array(32);

            let default_n: Usize<C::N> = builder.eval(C::N::ONE);
            let n = builder.get(&ctx.num_instances_layered_ns, 0);
            builder.if_eq(n, Usize::from(0)).then(|builder| {
                builder.assign(&default_n, Usize::from(0));
            });

            builder
                .range(0, prefix_one_seq.len())
                .for_each(|idx_vec, builder| {
                    builder.set(&prefix_one_seq, idx_vec[0], default_n.clone());
                    builder.set(
                        &prefix_one_seq_minus_one_bits,
                        idx_vec[0],
                        zero_bit_decomp.clone(),
                    );
                });
            builder
                .range(1, ctx.num_instances_layered_ns.len())
                .for_each(|idx_vec, builder| {
                    let n = builder.get(&ctx.num_instances_layered_ns, idx_vec[0]);
                    let n_bits = builder.get(&ctx.num_instances_bit_decomps, idx_vec[0]);
                    let target_idx: Usize<C::N> = builder.eval(idx_vec[0] - Usize::from(1));
                    builder.set(&prefix_one_seq, target_idx.clone(), n);
                    builder.set(&prefix_one_seq_minus_one_bits, target_idx, n_bits.clone());
                });

            let prefix_one_seq = reverse(builder, &prefix_one_seq);
            let prefix_one_seq_minus_one_bits = reverse(builder, &prefix_one_seq_minus_one_bits);

            let n_0 = builder.get(&prefix_one_seq, 0);
            let one: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
            let res: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
            builder.if_eq(n_0, Usize::from(1)).then(|builder| {
                let in_point_0 = builder.get(in_point, 0);
                let out_point_0 = builder.get(out_point, 0);
                builder.assign(&res, (one - out_point_0) * (one - in_point_0));
            });

            builder
                .range(1, out_point.len())
                .for_each(|idx_vec, builder| {
                    let i = idx_vec[0];
                    let num_prefix_one_lhs = builder.get(&prefix_one_seq, i);
                    let lhs_res: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
                    let in_point_i = builder.get(in_point, i);
                    let out_point_i = builder.get(out_point, i);

                    builder
                        .if_ne(num_prefix_one_lhs, Usize::from(0))
                        .then(|builder| {
                            let out_point_slice = out_point.slice(builder, 0, i);
                            let in_point_slice = in_point.slice(builder, 0, i);
                            let n_bits = builder.get(&prefix_one_seq_minus_one_bits, i);
                            let eq_eval = eq_eval_less_or_equal_than(
                                builder,
                                &n_bits,
                                &out_point_slice,
                                &in_point_slice,
                            );
                            builder.assign(
                                &lhs_res,
                                (one - out_point_i) * (one - in_point_i) * eq_eval,
                            );
                        });

                    let rhs_res: Ext<C::F, C::EF> = builder.eval(out_point_i * in_point_i * res);
                    builder.assign(&res, lhs_res + rhs_res);
                });

            (expr, res)
        }
    };

    // TODO: just return eval and check it with respect to evals
    let Expression::StructuralWitIn(wit_id, _) = expr else {
        panic!("Wrong selector expression format");
    };
    // let wit_id = wit_id as usize + offset_eq_id;
    // builder.set(evals, wit_id, eval);
    (*wit_id as usize, eval)
}

// TODO: make this as a function of BooleanHypercube
pub fn get_rotation_points<C: Config>(
    builder: &mut Builder<C>,
    _num_vars: usize,
    point: &Array<C, Ext<C::F, C::EF>>,
) -> (Array<C, Ext<C::F, C::EF>>, Array<C, Ext<C::F, C::EF>>) {
    let left: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(point.len());
    let right: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(point.len());
    // left = (0,s0,s1,s2,s3,...)
    // right = (1,s0,1-s1,s2,s3,...)
    builder.range(0, 4).for_each(|idx_vec, builder| {
        let e = builder.get(point, idx_vec[0]);
        let dest_idx: Var<C::N> = builder.eval(idx_vec[0] + RVar::from(1));
        builder.set(&left, dest_idx, e);
        builder.set(&right, dest_idx, e);
    });

    let one: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
    builder.set(&right, 0, one);
    let r1 = builder.get(&right, 2);
    builder.set(&right, 2, one - r1);

    builder.range(5, point.len()).for_each(|idx_vec, builder| {
        let e = builder.get(point, idx_vec[0]);
        builder.set(&left, idx_vec[0], e);
        builder.set(&right, idx_vec[0], e);
    });

    (left, right)
}

pub fn evaluate_gkr_expression<C: Config>(
    builder: &mut Builder<C>,
    expr: &EvalExpression<E>,
    claims: &Array<C, PointAndEvalVariable<C>>,
    challenges: &Array<C, Ext<C::F, C::EF>>,
) -> PointAndEvalVariable<C> {
    match expr {
        EvalExpression::Zero => {
            let point = builder.get(claims, 0).point;
            let eval: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
            PointAndEvalVariable { point, eval }
        }
        EvalExpression::Single(i) => builder.get(claims, *i),
        EvalExpression::Linear(i, c0, c1) => {
            let point = builder.get(claims, *i);

            let eval = builder.eval(point.eval);
            let point = point.point;

            let empty_arr: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(0);
            let c0_eval = eval_ceno_expr_with_instance(
                builder, &empty_arr, &empty_arr, &empty_arr, &empty_arr, challenges, c0,
            );
            let c1_eval = eval_ceno_expr_with_instance(
                builder, &empty_arr, &empty_arr, &empty_arr, &empty_arr, challenges, c1,
            );

            builder.assign(&eval, eval * c0_eval + c1_eval);

            PointAndEvalVariable { point, eval }
        }
        // TODO: we can ignore this part since it's not used right now
        EvalExpression::Partition(parts, indices) => {
            assert!(izip!(indices.iter(), indices.iter().skip(1)).all(|(a, b)| a.0 < b.0));
            let empty_arr: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(0);
            let vars = indices
                .iter()
                .map(|(_, c)| {
                    eval_ceno_expr_with_instance(
                        builder, &empty_arr, &empty_arr, &empty_arr, &empty_arr, challenges, c,
                    )
                })
                .collect_vec();
            let vars_arr: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(vars.len());
            for (i, e) in vars.iter().enumerate() {
                builder.set(&vars_arr, i, *e);
            }
            let parts = parts
                .iter()
                .map(|part| evaluate_gkr_expression(builder, part, claims, challenges))
                .collect_vec();

            assert_eq!(parts.len(), 1 << indices.len());

            if !parts.is_empty() {
                let first_pt = parts[0].point.fs.clone();
                for pt_eval in parts.iter().skip(1) {
                    assert_ext_arr_eq(builder, &first_pt, &pt_eval.point.fs);
                }
            }

            // FIXME: this is WRONG. we should use builder.dyn_array();
            let mut new_point: Vec<Ext<C::F, C::EF>> = vec![];
            builder
                .range(0, parts[0].point.fs.len())
                .for_each(|idx_vec, builder| {
                    let e = builder.get(&parts[0].point.fs, idx_vec[0]);
                    new_point.push(e);
                });
            for (index_in_point, c) in indices {
                let eval = eval_ceno_expr_with_instance(
                    builder, &empty_arr, &empty_arr, &empty_arr, &empty_arr, challenges, c,
                );
                new_point.insert(*index_in_point, eval);
            }

            let new_point_arr: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(new_point.len());
            for (i, e) in new_point.iter().enumerate() {
                builder.set(&new_point_arr, i, *e);
            }
            let eq = build_eq_x_r_vec_sequential(builder, &vars_arr);

            let parts_arr: Array<C, PointAndEvalVariable<C>> = builder.dyn_array(parts.len());
            for (i, pt) in parts.iter().enumerate() {
                builder.set(&parts_arr, i, pt.clone());
            }

            let acc: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
            iter_zip!(builder, parts_arr, eq).for_each(|ptr_vec, builder| {
                let prt = builder.iter_ptr_get(&parts_arr, ptr_vec[0]);
                let eq_v = builder.iter_ptr_get(&eq, ptr_vec[1]);
                builder.assign(&acc, acc + prt.eval * eq_v);
            });

            PointAndEvalVariable {
                point: PointVariable { fs: new_point_arr },
                eval: acc,
            }
        }
    }
}

pub fn extract_claim_and_point<C: Config>(
    builder: &mut Builder<C>,
    layer: &Layer<E>,
    claims: &Array<C, PointAndEvalVariable<C>>,
    challenges: &Array<C, Ext<C::F, C::EF>>,
    has_rotation: &Usize<C::N>,
) -> Array<C, ClaimAndPoint<C>> {
    let r_len: Usize<C::N> = Usize::Var(Var::uninit(builder));
    builder.assign(
        &r_len,
        has_rotation.clone() * Usize::from(3) + Usize::from(layer.out_sel_and_eval_exprs.len()),
    );
    let r = builder.dyn_array(r_len);
    layer
        .out_sel_and_eval_exprs
        .iter()
        .enumerate()
        .for_each(|(i, (_, out_evals))| {
            let evals = out_evals
                .iter()
                .map(|out_eval| evaluate_gkr_expression(builder, out_eval, claims, challenges))
                .collect_vec();

            let point = evals.first().map(|claim| builder.eval(claim.point.clone()));
            let evals_arr: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(evals.len());
            for (j, e) in evals.iter().enumerate() {
                builder.set_value(&evals_arr, j, e.eval);
            }

            if let Some(point) = point {
                builder.set(
                    &r,
                    i,
                    ClaimAndPoint {
                        evals: evals_arr,
                        has_point: Usize::from(1),
                        point,
                    },
                );
            } else {
                let pt = PointVariable {
                    fs: builder.dyn_array(0),
                };
                builder.set(
                    &r,
                    i,
                    ClaimAndPoint {
                        evals: evals_arr,
                        has_point: Usize::from(0),
                        point: pt,
                    },
                );
            }
        });

    r
}

pub fn generate_layer_challenges<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    challenges: &Array<C, Ext<C::F, C::EF>>,
    n_challenges: usize,
) -> Array<C, Ext<C::F, C::EF>> {
    let r = builder.dyn_array(n_challenges + 2);

    let alpha = builder.get(challenges, 0);
    let beta = builder.get(challenges, 1);

    builder.set(&r, 0, alpha);
    builder.set(&r, 1, beta);

    // TODO: skip if n_challenges <= 2
    transcript_observe_label(builder, challenger, b"layer challenge");
    let c = gen_alpha_pows(builder, challenger, Usize::from(n_challenges));

    for i in 0..n_challenges {
        let idx = i + 2;
        let e = builder.get(&c, i);
        builder.set(&r, idx, e);
    }

    r
}

pub fn verify_ecc_proof<C: Config>(
    builder: &mut Builder<C>,
    challenger: &mut DuplexChallengerVariable<C>,
    proof: &EccQuarkProofVariable<C>,
    unipoly_extrapolator: &mut UniPolyExtrapolator<C>,
) {
    let num_vars = proof.num_vars.clone();

    // Derive out_rt
    transcript_observe_label(builder, challenger, b"ecc");
    let out_rt: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(num_vars.clone());
    builder
        .range(0, num_vars.clone())
        .for_each(|idx_vec, builder| {
            let e = challenger.sample_ext(builder);
            builder.set(&out_rt, idx_vec[0], e);
        });

    // Derive alpha_pows
    transcript_observe_label(builder, challenger, b"ecc_alpha");
    let alpha_pows = gen_alpha_pows(
        builder,
        challenger,
        Usize::from(SEPTIC_EXTENSION_DEGREE * 3 + SEPTIC_EXTENSION_DEGREE * 2),
    );

    let one_ext: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
    let zero_ext: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    let three_f: Felt<C::F> = builder.constant(C::F::from_canonical_u32(3));
    let num_vars_f = builder.unsafe_cast_var_to_felt(num_vars.get_var());
    let (rt, sumcheck_expected_evaluation) = iop_verifier_state_verify(
        builder,
        challenger,
        &zero_ext,
        &proof.zerocheck_proof,
        num_vars_f,
        three_f,
        unipoly_extrapolator,
    );

    let cord_slice = proof.evals.slice(builder, 2, proof.evals.len());
    let s0: SepticExtensionVariable<C> =
        cord_slice.slice(builder, 0, SEPTIC_EXTENSION_DEGREE).into();
    let x0: SepticExtensionVariable<C> = cord_slice
        .slice(
            builder,
            SEPTIC_EXTENSION_DEGREE,
            2 * SEPTIC_EXTENSION_DEGREE,
        )
        .into();
    let y0: SepticExtensionVariable<C> = cord_slice
        .slice(
            builder,
            2 * SEPTIC_EXTENSION_DEGREE,
            3 * SEPTIC_EXTENSION_DEGREE,
        )
        .into();
    let x1: SepticExtensionVariable<C> = cord_slice
        .slice(
            builder,
            3 * SEPTIC_EXTENSION_DEGREE,
            4 * SEPTIC_EXTENSION_DEGREE,
        )
        .into();
    let y1: SepticExtensionVariable<C> = cord_slice
        .slice(
            builder,
            4 * SEPTIC_EXTENSION_DEGREE,
            5 * SEPTIC_EXTENSION_DEGREE,
        )
        .into();
    let x3: SepticExtensionVariable<C> = cord_slice
        .slice(
            builder,
            5 * SEPTIC_EXTENSION_DEGREE,
            6 * SEPTIC_EXTENSION_DEGREE,
        )
        .into();
    let y3: SepticExtensionVariable<C> = cord_slice
        .slice(
            builder,
            6 * SEPTIC_EXTENSION_DEGREE,
            7 * SEPTIC_EXTENSION_DEGREE,
        )
        .into();
    let s0_squared = septic_ext_squared(builder, &s0);

    let v1: SepticExtensionVariable<C> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE).into();
    let v2: SepticExtensionVariable<C> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE).into();
    let v3: SepticExtensionVariable<C> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE).into();
    let v4: SepticExtensionVariable<C> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE).into();
    let v5: SepticExtensionVariable<C> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE).into();
    let x0_x1: SepticExtensionVariable<C> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE).into();
    let x0_x3: SepticExtensionVariable<C> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE).into();

    for i in 0..SEPTIC_EXTENSION_DEGREE {
        let x0_i = builder.get(&x0.vs, i);
        let x1_i = builder.get(&x1.vs, i);
        let x3_i = builder.get(&x3.vs, i);
        let y0_i = builder.get(&y0.vs, i);
        let y3_i = builder.get(&y3.vs, i);
        let s0_squared_i = builder.get(&s0_squared.vs, i);

        builder.set(&x0_x1.vs, i, x0_i - x1_i);
        builder.set(&x0_x3.vs, i, x0_i - x3_i);
        builder.set(&v2.vs, i, s0_squared_i - x0_i - x1_i - x3_i);
        builder.set(&v4.vs, i, x3_i - x0_i);
        builder.set(&v5.vs, i, y3_i - y0_i);
    }

    let s0_x0_x1 = septic_ext_mul(builder, &s0, &x0_x1);
    let s0_x0_x3 = septic_ext_mul(builder, &s0, &x0_x3);

    for i in 0..SEPTIC_EXTENSION_DEGREE {
        let s0_x0_x1_i = builder.get(&s0_x0_x1.vs, i);
        let s0_x0_x3_i = builder.get(&s0_x0_x3.vs, i);
        let y0_i = builder.get(&y0.vs, i);
        let y1_i = builder.get(&y1.vs, i);
        let y3_i = builder.get(&y3.vs, i);

        builder.set(&v1.vs, i, s0_x0_x1_i - (y0_i - y1_i));
        builder.set(&v3.vs, i, s0_x0_x3_i - (y0_i + y3_i));
    }

    let mask1 = alpha_pows.slice(builder, 0, SEPTIC_EXTENSION_DEGREE);
    let mask2 = alpha_pows.slice(
        builder,
        SEPTIC_EXTENSION_DEGREE,
        2 * SEPTIC_EXTENSION_DEGREE,
    );
    let mask3 = alpha_pows.slice(
        builder,
        2 * SEPTIC_EXTENSION_DEGREE,
        3 * SEPTIC_EXTENSION_DEGREE,
    );
    let mask4 = alpha_pows.slice(
        builder,
        3 * SEPTIC_EXTENSION_DEGREE,
        4 * SEPTIC_EXTENSION_DEGREE,
    );
    let mask5 = alpha_pows.slice(
        builder,
        4 * SEPTIC_EXTENSION_DEGREE,
        5 * SEPTIC_EXTENSION_DEGREE,
    );

    mask_arr(builder, &v1.vs, &mask1);
    mask_arr(builder, &v2.vs, &mask2);
    mask_arr(builder, &v3.vs, &mask3);
    mask_arr(builder, &v4.vs, &mask4);
    mask_arr(builder, &v5.vs, &mask5);

    let sel_add_expr = SelectorType::<E>::QuarkBinaryTreeLessThan(Expression::StructuralWitIn(
        0,
        StackedConstantSequence { max_value: 0 },
    ));

    let offset_bit_decomps = builder.dyn_array(32);
    let offset_instance_sum_bit_decomps = builder.get(&proof.num_instances_bit_decomps, 0).clone();
    let ctx: SelectorContextVariable<C> = SelectorContextVariable {
        offset: Usize::from(0),
        offset_bit_decomps,
        num_instances: proof.num_instances.clone(),
        num_instances_layered_ns: proof.num_instances_layered_ns.clone(),
        num_instances_bit_decomps: proof.num_instances_bit_decomps.clone(),
        offset_instance_sum_bit_decomps,
        num_vars: proof.num_vars.clone(),
    };

    let (_wit_id, expected_sel_add) = evaluate_selector(builder, &sel_add_expr, &out_rt, &rt, &ctx);

    let proof_eval_0 = builder.get(&proof.evals, 0);
    builder.assert_ext_eq(proof_eval_0, expected_sel_add);

    let eq_eval: Ext<<C as Config>::F, <C as Config>::EF> =
        eq_eval(builder, &out_rt, &rt, one_ext, zero_ext);
    let out_rt_prod = arr_product(builder, &out_rt);
    let rt_prod = arr_product(builder, &rt);
    let expected_sel_bypass: Ext<C::F, C::EF> =
        builder.eval(eq_eval - expected_sel_add - (out_rt_prod * rt_prod));

    let proof_eval_1 = builder.get(&proof.evals, 1);
    builder.assert_ext_eq(proof_eval_1, expected_sel_bypass);

    let add_evaluations: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    let bypass_evaluations: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    for i in 0..SEPTIC_EXTENSION_DEGREE {
        let v1_i = builder.get(&v1.vs, i);
        let v2_i = builder.get(&v2.vs, i);
        let v3_i = builder.get(&v3.vs, i);
        let v4_i = builder.get(&v4.vs, i);
        let v5_i = builder.get(&v5.vs, i);

        builder.assign(&add_evaluations, add_evaluations + v1_i + v2_i + v3_i);
        builder.assign(&bypass_evaluations, bypass_evaluations + v4_i + v5_i);
    }
    let op_evaluation: Ext<C::F, C::EF> =
        builder.eval(add_evaluations * expected_sel_add + bypass_evaluations * expected_sel_bypass);
    builder.assert_ext_eq(sumcheck_expected_evaluation, op_evaluation);
}

pub fn septic_ext_squared<C: Config>(
    builder: &mut Builder<C>,
    a: &SepticExtensionVariable<C>,
) -> SepticExtensionVariable<C> {
    let r: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE);

    let two_ext: Ext<C::F, C::EF> = builder.constant(C::EF::TWO);
    let five_ext: Ext<C::F, C::EF> = builder.constant(C::EF::from_canonical_u32(5));

    for i in 0..SEPTIC_EXTENSION_DEGREE {
        for j in (i + 1)..SEPTIC_EXTENSION_DEGREE {
            let mut index = i + j;

            let i_term = builder.get(&a.vs, i);
            let j_term = builder.get(&a.vs, j);

            let term: Ext<C::F, C::EF> = builder.uninit();
            builder.assign(&term, two_ext * i_term * j_term);

            if index < 7 {
                let r_v = builder.get(&r, index);
                builder.set(&r, index, r_v + term);
            } else {
                index -= 7;
                // x^7 = 2x + 5
                let r_v_i = builder.get(&r, index);
                let r_v_i_1 = builder.get(&r, index + 1);

                builder.set(&r, index, r_v_i + five_ext * term);
                builder.set(&r, index + 1, r_v_i_1 + two_ext * term);
            }
        }
    }

    // i == j: i \in [0, 3]
    let r_0 = builder.get(&r, 0);
    let a_0 = builder.get(&a.vs, 0);
    builder.set(&r, 0, r_0 + a_0 * a_0);

    let r_2 = builder.get(&r, 2);
    let a_1 = builder.get(&a.vs, 1);
    builder.set(&r, 2, r_2 + a_1 * a_1);

    let r_4 = builder.get(&r, 4);
    let a_2 = builder.get(&a.vs, 2);
    builder.set(&r, 4, r_4 + a_2 * a_2);

    let r_6 = builder.get(&r, 6);
    let a_3 = builder.get(&a.vs, 3);
    builder.set(&r, 6, r_6 + a_3 * a_3);

    // a4^2 * x^8 = a4^2 * (2x + 5)x = 5a4^2 * x + 2a4^2 * x^2
    let a_4 = builder.get(&a.vs, 4);
    let term: Ext<C::F, C::EF> = builder.eval(a_4 * a_4);
    let r_1 = builder.get(&r, 1);
    let r_2 = builder.get(&r, 2);
    builder.set(&r, 1, r_1 + five_ext * term);
    builder.set(&r, 2, r_2 + two_ext * term);

    // a5^2 * x^10 = a5^2 * (2x + 5)x^3 = 5a5^2 * x^3 + 2a5^2 * x^4
    let a_5 = builder.get(&a.vs, 5);
    let term: Ext<C::F, C::EF> = builder.eval(a_5 * a_5);
    let r_3 = builder.get(&r, 3);
    let r_4 = builder.get(&r, 4);
    builder.set(&r, 3, r_3 + five_ext * term);
    builder.set(&r, 4, r_4 + two_ext * term);

    // a6^2 * x^12 = a6^2 * (2x + 5)x^5 = 5a6^2 * x^5 + 2a6^2 * x^6
    let a_6 = builder.get(&a.vs, 6);
    let term: Ext<C::F, C::EF> = builder.eval(a_6 * a_6);
    let r_5 = builder.get(&r, 5);
    let r_6 = builder.get(&r, 6);
    builder.set(&r, 5, r_5 + five_ext * term);
    builder.set(&r, 6, r_6 + two_ext * term);

    r.into()
}

pub fn septic_ext_mul<C: Config>(
    builder: &mut Builder<C>,
    a: &SepticExtensionVariable<C>,
    b: &SepticExtensionVariable<C>,
) -> SepticExtensionVariable<C> {
    let r: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE);
    let two_ext: Ext<C::F, C::EF> = builder.constant(C::EF::TWO);
    let five_ext: Ext<C::F, C::EF> = builder.constant(C::EF::from_canonical_u32(5));

    for i in 0..SEPTIC_EXTENSION_DEGREE {
        for j in 0..SEPTIC_EXTENSION_DEGREE {
            let mut index = i + j;

            let a_term = builder.get(&a.vs, i);
            let b_term = builder.get(&b.vs, j);

            let term: Ext<C::F, C::EF> = builder.uninit();
            builder.assign(&term, a_term * b_term);

            if index < 7 {
                let r_v = builder.get(&r, index);
                builder.set(&r, index, r_v + term);
            } else {
                index -= 7;
                // x^7 = 2x + 5
                let r_v_i = builder.get(&r, index);
                let r_v_i_1 = builder.get(&r, index + 1);

                builder.set(&r, index, r_v_i + five_ext * term);
                builder.set(&r, index + 1, r_v_i_1 + two_ext * term);
            }
        }
    }

    r.into()
}

// return a + b
pub fn septic_ext_add<C: Config>(
    builder: &mut Builder<C>,
    a: &SepticExtensionVariable<C>,
    b: &SepticExtensionVariable<C>,
) -> SepticExtensionVariable<C> {
    let vs: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE);
    for i in 0..SEPTIC_EXTENSION_DEGREE {
        let a_i = builder.get(&a.vs, i);
        let b_i = builder.get(&b.vs, i);

        builder.set(&vs, i, a_i + b_i);
    }
    SepticExtensionVariable { vs }
}

// return a - b
pub fn septic_ext_sub<C: Config>(
    builder: &mut Builder<C>,
    a: &SepticExtensionVariable<C>,
    b: &SepticExtensionVariable<C>,
) -> SepticExtensionVariable<C> {
    let vs: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE);
    for i in 0..SEPTIC_EXTENSION_DEGREE {
        let a_i = builder.get(&a.vs, i);
        let b_i = builder.get(&b.vs, i);

        builder.set(&vs, i, a_i - b_i);
    }
    SepticExtensionVariable { vs }
}

const INVERTER_COEFF_LEN: usize = SEPTIC_EXTENSION_DEGREE * SEPTIC_EXTENSION_DEGREE;
const Z_POW_PS: [u32; INVERTER_COEFF_LEN] = [
    1, 0, 0, 0, 0, 0, 0, 954599710, 1359279693, 566669999, 1982781815, 1735718361, 1174868538,
    1120871770, 862825265, 597046311, 978840770, 1790138282, 1044777201, 835869808, 1342179023,
    596273169, 658837454, 1515468261, 367059247, 781278880, 1544222616, 155490465, 557608863,
    1173670028, 1749546888, 1086464137, 803900099, 1288818584, 1184677604, 763416381, 1252567168,
    628856225, 1771903394, 650712211, 19417363, 57990258, 1734711039, 1749813853, 1227235221,
    1707730636, 424560395, 1007029514, 498034669,
];
const Z_POW_P_SQUARES: [u32; INVERTER_COEFF_LEN] = [
    1, 0, 0, 0, 0, 0, 0, 1013489358, 1619071628, 304593143, 1949397349, 1564307636, 327761151,
    415430835, 209824426, 1313900768, 38410482, 256593180, 1708830551, 1244995038, 1555324019,
    1475628651, 777565847, 704492386, 1218528120, 1245363405, 475884575, 649166061, 550038364,
    948935655, 68722023, 1251345762, 1692456177, 1177958698, 350232928, 882720258, 821925756,
    199955840, 812002876, 1484951277, 1063138035, 491712810, 738287111, 1955364991, 552724293,
    1175775744, 341623997, 1454022463, 408193320,
];

pub fn frobenius<C: Config>(
    builder: &mut Builder<C>,
    input: &SepticExtensionVariable<C>,
    is_double: bool,
) -> SepticExtensionVariable<C> {
    let vs: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE);

    let v0 = builder.get(&input.vs, 0);
    let v1 = builder.get(&input.vs, 1);
    let v2 = builder.get(&input.vs, 2);
    let v3 = builder.get(&input.vs, 3);
    let v4 = builder.get(&input.vs, 4);
    let v5 = builder.get(&input.vs, 5);
    let v6 = builder.get(&input.vs, 6);

    for i in 0..SEPTIC_EXTENSION_DEGREE {
        let coeff = if is_double {
            &[
                Z_POW_P_SQUARES[i],
                Z_POW_P_SQUARES[SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_P_SQUARES[2 * SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_P_SQUARES[3 * SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_P_SQUARES[4 * SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_P_SQUARES[5 * SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_P_SQUARES[6 * SEPTIC_EXTENSION_DEGREE + i],
            ]
        } else {
            &[
                Z_POW_PS[i],
                Z_POW_PS[SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_PS[2 * SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_PS[3 * SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_PS[4 * SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_PS[5 * SEPTIC_EXTENSION_DEGREE + i],
                Z_POW_PS[6 * SEPTIC_EXTENSION_DEGREE + i],
            ]
        };

        builder.set(
            &vs,
            i,
            v0 * C::EF::from_canonical_u32(coeff[0])
                + v1 * C::EF::from_canonical_u32(coeff[1])
                + v2 * C::EF::from_canonical_u32(coeff[2])
                + v3 * C::EF::from_canonical_u32(coeff[3])
                + v4 * C::EF::from_canonical_u32(coeff[4])
                + v5 * C::EF::from_canonical_u32(coeff[5])
                + v6 * C::EF::from_canonical_u32(coeff[6]),
        );
    }

    SepticExtensionVariable { vs }
}

pub fn norm_sub<C: Config>(
    builder: &mut Builder<C>,
    input: &SepticExtensionVariable<C>,
) -> SepticExtensionVariable<C> {
    let a_frobenius = frobenius(builder, input, false);
    let b_double_frobenius = frobenius(builder, input, true);
    let a = septic_ext_mul(builder, &a_frobenius, &b_double_frobenius);
    let b = frobenius(builder, &a, true);
    let c = frobenius(builder, &b, true);

    let a_x_b = septic_ext_mul(builder, &a, &b);
    septic_ext_mul(builder, &a_x_b, &c)
}

pub fn invert<C: Config>(
    builder: &mut Builder<C>,
    input: &SepticExtensionVariable<C>,
) -> SepticExtensionVariable<C> {
    let x = norm_sub(builder, input);
    let input_mul_x = septic_ext_mul(builder, &x, input);
    let norm: Ext<C::F, C::EF> = builder.get(&input_mul_x.vs, 0);
    let norm_inv: Ext<C::F, C::EF> = builder.eval(norm.inverse());
    let vs: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE);
    for i in 0..SEPTIC_EXTENSION_DEGREE {
        let x_i = builder.get(&x.vs, i);
        builder.set(&vs, i, x_i * norm_inv);
    }

    SepticExtensionVariable { vs }
}

// Double a septic point in place
pub fn double_septic_points_in_place<C: Config>(
    builder: &mut Builder<C>,
    pt: &SepticPointVariable<C>,
) {
    let x1_sqr = septic_ext_squared(builder, &pt.x);

    let x1_sqr_x_3_plus_2: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE);
    let x1_sqr_0 = builder.get(&x1_sqr.vs, 0);
    builder.set(
        &x1_sqr_x_3_plus_2,
        0,
        x1_sqr_0 * C::EF::from_canonical_u32(3) + C::EF::ONE,
    );
    for i in 1..SEPTIC_EXTENSION_DEGREE {
        let x1_sqr_i = builder.get(&x1_sqr.vs, i);
        builder.set(
            &x1_sqr_x_3_plus_2,
            i,
            x1_sqr_i * C::EF::from_canonical_u32(3),
        );
    }

    let y1_x_2: Array<C, Ext<C::F, C::EF>> = builder.dyn_array(SEPTIC_EXTENSION_DEGREE);
    for i in 0..SEPTIC_EXTENSION_DEGREE {
        let y_i = builder.get(&pt.y.vs, i);
        builder.set(&y1_x_2, i, y_i * C::EF::TWO);
    }

    let y1_x_2_inv = invert(builder, &SepticExtensionVariable { vs: y1_x_2 });
    let slope = septic_ext_mul(
        builder,
        &SepticExtensionVariable {
            vs: x1_sqr_x_3_plus_2,
        },
        &y1_x_2_inv,
    );
    let slope_squared = septic_ext_squared(builder, &slope);
    let x3 = septic_ext_sub(builder, &slope_squared, &pt.x);
    let x3 = septic_ext_sub(builder, &x3, &pt.x);

    let x1_x3 = septic_ext_sub(builder, &pt.x, &x3);
    let slope_x_x1_x3 = septic_ext_mul(builder, &slope, &x1_x3);
    let y3 = septic_ext_sub(builder, &slope_x_x1_x3, &pt.y);

    builder.assign(&pt.x, x3);
    builder.assign(&pt.y, y3);
    builder.assign(&pt.is_infinity, Usize::from(0));
}

// Modify left septic point in place
pub fn add_septic_points_in_place<C: Config>(
    builder: &mut Builder<C>,
    left: &SepticPointVariable<C>,
    right: &SepticPointVariable<C>,
) {
    builder
        .if_eq(left.is_infinity.clone(), Usize::from(1))
        .then_or_else(
            |builder| {
                builder.assign(&left.x, right.x.clone());
                builder.assign(&left.y, right.y.clone());
                builder.assign(&left.is_infinity, right.is_infinity.clone());
            },
            |builder| {
                builder
                    .if_ne(right.is_infinity.clone(), Usize::from(1))
                    .then(|builder| {
                        let x_diff = septic_ext_sub(builder, &right.x, &left.x);
                        let y_diff = septic_ext_sub(builder, &right.y, &left.y);
                        let is_x_same = x_diff.is_zero(builder);

                        builder.if_eq(is_x_same, Usize::from(1)).then_or_else(
                            |builder| {
                                let is_y_same = y_diff.is_zero(builder);

                                builder.if_eq(is_y_same, Usize::from(1)).then_or_else(
                                    |builder| {
                                        double_septic_points_in_place(builder, left);
                                    },
                                    |builder| {
                                        let y_sum = septic_ext_add(builder, &right.y, &left.y);
                                        let is_y_sum_zero = y_sum.is_zero(builder);
                                        builder.assert_usize_eq(is_y_sum_zero, Usize::from(1));
                                        let zero_ext_arr: Array<C, Ext<C::F, C::EF>> =
                                            builder.dyn_array(SEPTIC_EXTENSION_DEGREE);
                                        builder.assign(&left.x, zero_ext_arr.clone());
                                        builder.assign(&left.y, zero_ext_arr.clone());
                                        builder.assign(&left.is_infinity, Usize::from(1));
                                    },
                                );
                            },
                            |builder| {
                                let x_diff_inv = invert(builder, &x_diff);
                                let slope = septic_ext_mul(builder, &y_diff, &x_diff_inv);
                                let x_sum = septic_ext_add(builder, &right.x, &left.x);
                                let slope_squared = septic_ext_squared(builder, &slope);
                                let x = septic_ext_sub(builder, &slope_squared, &x_sum);
                                let x_diff = septic_ext_sub(builder, &left.x, &x);
                                let slope_mul_x_diff = septic_ext_mul(builder, &slope, &x_diff);
                                let y = septic_ext_sub(builder, &slope_mul_x_diff, &left.y);

                                builder.assign(&left.x, x);
                                builder.assign(&left.y, y);
                                builder.assign(&left.is_infinity, Usize::from(0));
                            },
                        );
                    });
            },
        );
}
