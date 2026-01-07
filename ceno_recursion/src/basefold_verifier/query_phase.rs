use ff_ext::{BabyBearExt4, ExtensionField, PoseidonField};
use mpcs::basefold::structure::QueryOpeningProof as InnerQueryOpeningProof;
use openvm_native_compiler::{asm::AsmConfig, prelude::*};
use openvm_native_compiler_derive::iter_zip;
use openvm_native_recursion::{
    hints::{Hintable, VecAutoHintable},
    vars::HintSlice,
};
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use p3::{
    commit::ExtensionMmcs,
    field::{Field, FieldAlgebra},
};
use serde::Deserialize;

use super::{basefold::*, extension_mmcs::*, mmcs::*, rs::*, utils::*};
use crate::{
    arithmetics::eq_eval_with_index,
    tower_verifier::{binding::*, program::interpolate_uni_poly},
};

pub type F = BabyBear;
pub type E = BabyBearExt4;
pub type InnerConfig = AsmConfig<F, E>;

use p3::fri::{
    BatchOpening as InnerBatchOpening, CommitPhaseProofStep as InnerCommitPhaseProofStep,
};

/// We have to define a struct similar to p3_fri::BatchOpening as
/// the trait `Hintable` is defined in another crate inside OpenVM
#[derive(Deserialize)]
pub struct BatchOpening {
    pub opened_values: Vec<Vec<F>>,
    pub opening_proof: MmcsProof,
}

impl
    From<
        InnerBatchOpening<
            <E as ExtensionField>::BaseField,
            <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
        >,
    > for BatchOpening
{
    fn from(
        inner: InnerBatchOpening<
            <E as ExtensionField>::BaseField,
            <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
        >,
    ) -> Self {
        Self {
            opened_values: inner.opened_values,
            opening_proof: inner.opening_proof,
        }
    }
}

#[derive(DslVariable, Clone)]
pub struct BatchOpeningVariable<C: Config> {
    pub opened_values: HintSlice<C>,
    pub opening_proof: HintSlice<C>,
}

impl Hintable<InnerConfig> for BatchOpening {
    type HintVariable = BatchOpeningVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let opened_values = read_hint_slice(builder);
        let opening_proof = read_hint_slice(builder);

        BatchOpeningVariable {
            opened_values,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(vec![
            vec![F::from_canonical_usize(self.opened_values.len())],
            self.opened_values
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
        ]);
        stream.extend(vec![
            vec![F::from_canonical_usize(self.opening_proof.len())],
            self.opening_proof
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
        ]);
        stream
    }
}

impl VecAutoHintable for BatchOpening {}

/// TODO: use `openvm_native_recursion::fri::types::FriCommitPhaseProofStepVariable` instead
#[derive(Deserialize)]
pub struct CommitPhaseProofStep {
    pub sibling_value: E,
    pub opening_proof: MmcsProof,
}

pub type ExtMmcs<E> = ExtensionMmcs<
    <E as ExtensionField>::BaseField,
    E,
    <<E as ExtensionField>::BaseField as PoseidonField>::MMCS,
>;
impl From<InnerCommitPhaseProofStep<E, ExtMmcs<E>>> for CommitPhaseProofStep {
    fn from(inner: InnerCommitPhaseProofStep<E, ExtMmcs<E>>) -> Self {
        Self {
            sibling_value: inner.sibling_value,
            opening_proof: inner.opening_proof,
        }
    }
}

#[derive(DslVariable, Clone)]
pub struct CommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: HintSlice<C>,
}

impl VecAutoHintable for CommitPhaseProofStep {}

impl Hintable<InnerConfig> for CommitPhaseProofStep {
    type HintVariable = CommitPhaseProofStepVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let sibling_value = E::read(builder);
        let opening_proof = read_hint_slice(builder);

        CommitPhaseProofStepVariable {
            sibling_value,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.sibling_value.write());
        stream.extend(vec![
            vec![F::from_canonical_usize(self.opening_proof.len())],
            self.opening_proof
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
        ]);
        stream
    }
}

#[derive(Deserialize)]
pub struct QueryOpeningProof {
    pub input_proofs: Vec<BatchOpening>,
    pub commit_phase_openings: Vec<CommitPhaseProofStep>,
}

impl From<InnerQueryOpeningProof<E>> for QueryOpeningProof {
    fn from(proof: InnerQueryOpeningProof<E>) -> Self {
        Self {
            input_proofs: proof
                .input_proofs
                .into_iter()
                .map(|proof| proof.into())
                .collect(),
            commit_phase_openings: proof
                .commit_phase_openings
                .into_iter()
                .map(|proof| proof.into())
                .collect(),
        }
    }
}

#[derive(DslVariable, Clone)]
pub struct QueryOpeningProofVariable<C: Config> {
    pub input_proofs: Array<C, BatchOpeningVariable<C>>,
    pub commit_phase_openings: Array<C, CommitPhaseProofStepVariable<C>>,
}

pub(crate) type QueryOpeningProofs = Vec<QueryOpeningProof>;
pub(crate) type QueryOpeningProofsVariable<C> = Array<C, QueryOpeningProofVariable<C>>;

impl VecAutoHintable for QueryOpeningProof {}

impl Hintable<InnerConfig> for QueryOpeningProof {
    type HintVariable = QueryOpeningProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let input_proofs = Vec::<BatchOpening>::read(builder);
        let commit_phase_openings = Vec::<CommitPhaseProofStep>::read(builder);
        QueryOpeningProofVariable {
            input_proofs,
            commit_phase_openings,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.input_proofs.write());
        stream.extend(self.commit_phase_openings.write());
        stream
    }
}

#[derive(Deserialize)]
// NOTE: Different from PointAndEval in tower_verifier!
pub struct PointAndEvals {
    pub point: Point,
    pub evals: Vec<E>,
}
impl Hintable<InnerConfig> for PointAndEvals {
    type HintVariable = PointAndEvalsVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let point = Point::read(builder);
        let evals = Vec::<E>::read(builder);
        PointAndEvalsVariable { point, evals }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.point.write());
        stream.extend(self.evals.write());
        stream
    }
}
impl VecAutoHintable for PointAndEvals {}

#[derive(DslVariable, Clone)]
pub struct PointAndEvalsVariable<C: Config> {
    pub point: PointVariable<C>,
    pub evals: Array<C, Ext<C::F, C::EF>>,
}

#[derive(Deserialize)]
pub struct QueryPhaseVerifierInput {
    // pub t_inv_halves: Vec<Vec<<E as ExtensionField>::BaseField>>,
    pub max_num_var: usize,
    // This is the maximum width of all the opened values in the query openings. The reason
    // for providing this information is to allow us to allocate a single all-zero buffer that is
    // sufficiently large to pass to the `fri_single_reduced_opening_eval` chip.
    pub max_width: usize,
    pub batch_coeffs: Vec<E>,
    pub fold_challenges: Vec<E>,
    pub indices: Vec<usize>,
    pub proof: BasefoldProof,
    pub rounds: Vec<Round>,
}

impl Hintable<InnerConfig> for QueryPhaseVerifierInput {
    type HintVariable = QueryPhaseVerifierInputVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        // let t_inv_halves = Vec::<Vec<F>>::read(builder);
        let max_num_var = Usize::Var(usize::read(builder));
        let max_width = Usize::Var(usize::read(builder));
        let batch_coeffs = Vec::<E>::read(builder);
        let fold_challenges = Vec::<E>::read(builder);
        let indices = Vec::<usize>::read(builder);
        let proof = BasefoldProof::read(builder);
        let rounds = Vec::<Round>::read(builder);

        QueryPhaseVerifierInputVariable {
            // t_inv_halves,
            max_num_var,
            max_width,
            batch_coeffs,
            fold_challenges,
            indices,
            proof,
            rounds,
        }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        // stream.extend(self.t_inv_halves.write());
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.max_num_var));
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.max_width));
        stream.extend(self.batch_coeffs.write());
        stream.extend(self.fold_challenges.write());
        stream.extend(self.indices.write());
        stream.extend(self.proof.write());
        stream.extend(self.rounds.write());
        stream
    }
}

#[derive(DslVariable, Clone)]
pub struct QueryPhaseVerifierInputVariable<C: Config> {
    // pub t_inv_halves: Array<C, Array<C, Felt<C::F>>>,
    pub max_num_var: Usize<C::N>,
    // See `QueryPhaseVerifierInput` for explaining the purpose of this field.
    pub max_width: Usize<C::N>,
    pub batch_coeffs: Array<C, Ext<C::F, C::EF>>,
    pub fold_challenges: Array<C, Ext<C::F, C::EF>>,
    pub indices: Array<C, Var<C::N>>,
    pub proof: BasefoldProofVariable<C>,
    pub rounds: Array<C, RoundVariable<C>>,
}

#[derive(DslVariable, Clone)]
pub struct PackedCodeword<C: Config> {
    pub low: Ext<C::F, C::EF>,
    pub high: Ext<C::F, C::EF>,
}

#[derive(DslVariable, Clone)]
pub struct RoundContextVariable<C: Config> {
    pub(crate) opened_values_buffer: Array<C, Array<C, Felt<C::F>>>,
    pub(crate) log2_heights: Array<C, Var<C::N>>,
    pub(crate) minus_alpha_offsets: Array<C, Ext<C::F, C::EF>>,
    pub(crate) dimensions: Array<C, Var<C::N>>,
}

pub(crate) fn batch_verifier_query_phase<C: Config>(
    builder: &mut Builder<C>,
    input: QueryPhaseVerifierInputVariable<C>,
) {
    let inv_2: Felt<C::F> = builder.constant(C::F::from_canonical_u32(0x3c000001));
    let two_adic_generators_inverses: Array<C, Felt<C::F>> = builder.dyn_array(28);
    for (index, val) in [
        0x1usize, 0x78000000, 0x67055c21, 0x5ee99486, 0xbb4c4e4, 0x2d4cc4da, 0x669d6090,
        0x17b56c64, 0x67456167, 0x688442f9, 0x145e952d, 0x4fe61226, 0x4c734715, 0x11c33e2a,
        0x62c3d2b1, 0x77cad399, 0x54c131f4, 0x4cabd6a6, 0x5cf5713f, 0x3e9430e8, 0xba067a3,
        0x18adc27d, 0x21fd55bc, 0x4b859b3d, 0x3bd57996, 0x4483d85a, 0x3a26eef8, 0x1a427a41,
    ]
    .iter()
    .enumerate()
    {
        let generator_inverse = builder.constant(C::F::from_canonical_usize(*val).inverse());
        builder.set_value(&two_adic_generators_inverses, index, generator_inverse);
    }
    let zero: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    let zero_flag: Var<C::N> = builder.constant(C::N::ZERO);
    let two: Var<C::N> = builder.constant(C::N::TWO);
    let two_felt: Felt<C::F> = builder.constant(C::F::TWO);

    // encode_small
    let final_message = &input.proof.final_message;
    let final_rmm_values_len = builder.get(final_message, 0).len();
    let final_rmm_values = builder.dyn_array(final_rmm_values_len.clone());

    let all_zeros = builder.dyn_array(input.max_width.clone());
    iter_zip!(builder, all_zeros).for_each(|ptr_vec, builder| {
        builder.set_value(&all_zeros, ptr_vec[0], zero);
    });

    builder
        .range(0, final_rmm_values_len.clone())
        .for_each(|i_vec, builder| {
            let i = i_vec[0];
            let row_len = final_message.len();
            let sum = builder.constant(C::EF::ZERO);
            builder.range(0, row_len).for_each(|j_vec, builder| {
                let j = j_vec[0];
                let row = builder.get(final_message, j);
                let row_j = builder.get(&row, i);
                builder.assign(&sum, sum + row_j);
            });
            builder.set_value(&final_rmm_values, i, sum);
        });

    let final_rmm = RowMajorMatrixVariable {
        values: final_rmm_values,
        width: builder.eval(Usize::from(1)),
    };
    let final_codeword = encode_small(builder, final_rmm);

    let log2_max_codeword_size: Var<C::N> =
        builder.eval(input.max_num_var.clone() + Usize::from(get_rate_log()));

    let alpha: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
    builder
        .if_ne(input.batch_coeffs.len(), C::N::ONE)
        .then(|builder| {
            let batch_coeff = builder.get(&input.batch_coeffs, 1);
            builder.assign(&alpha, batch_coeff);
        });

    let initial_cur_num_var: Var<C::N> = builder.eval(input.max_num_var.clone());
    let initial_log2_height: Var<C::N> =
        builder.eval(initial_cur_num_var + Usize::from(get_rate_log() - 1));
    builder.assert_eq::<Var<C::N>>(
        input.proof.commits.len() + Usize::from(1),
        input.fold_challenges.len(),
    );

    iter_zip!(builder, input.indices, input.proof.query_opening_proof).for_each(
        |ptr_vec, builder| {
            // TODO: change type of input.indices to be `Array<C, Array<C, Var<C::N>>>`
            let idx = builder.iter_ptr_get(&input.indices, ptr_vec[0]);
            let idx = builder.unsafe_cast_var_to_felt(idx);
            let idx_bits = builder.num2bits_f(idx, C::N::bits() as u32);
            // assert idx_bits[log2_max_codeword_size..] == 0
            builder
                .range(log2_max_codeword_size, idx_bits.len())
                .for_each(|i_vec, builder| {
                    let bit = builder.get(&idx_bits, i_vec[0]);
                    builder.assert_eq::<Var<_>>(bit, Usize::from(0));
                });
            let idx_bits = idx_bits.slice(builder, 1, log2_max_codeword_size);

            let reduced_codeword_by_height: Array<C, PackedCodeword<C>> =
                builder.dyn_array(log2_max_codeword_size);
            // initialize reduced_codeword_by_height with zeroes
            iter_zip!(builder, reduced_codeword_by_height).for_each(|ptr_vec, builder| {
                let zero_codeword = PackedCodeword {
                    low: zero,
                    high: zero,
                };
                builder.set_value(&reduced_codeword_by_height, ptr_vec[0], zero_codeword);
            });
            let query = builder.iter_ptr_get(&input.proof.query_opening_proof, ptr_vec[1]);

            builder.cycle_tracker_start("Batching and first FRI round");
            let batch_coeffs_offset: Var<C::N> = builder.constant(C::N::ZERO);
            builder
                .range(0, input.rounds.len())
                .for_each(|idx_vec, builder| {
                    let batch_opening = builder.get(&query.input_proofs, idx_vec[0]);
                    let round = builder.get(&input.rounds, idx_vec[0]);
                    let opened_values = batch_opening.opened_values;
                    let perm_opened_values = builder.dyn_array(opened_values.length.clone());
                    let opening_proof = batch_opening.opening_proof;
                    let opening_idxes: Array<C, Var<C::N>> =
                        builder.dyn_array(round.openings.len());
                    let opened_values_offset: Var<C::N> = builder.constant(C::N::ZERO);

                    builder
                        .range(0, round.openings.len())
                        .for_each(|i_vec, builder| {
                            let opening = builder.get(&round.openings, i_vec[0]);

                            builder.if_ne(opening.num_var, zero_flag).then(|builder| {
                                builder.set(&opening_idxes, opened_values_offset, i_vec[0]);
                                builder.assign(
                                    &opened_values_offset,
                                    opened_values_offset + Usize::from(1),
                                );
                            });
                        });

                    let dimensions: Array<C, Var<C::N>> =
                        builder.dyn_array(opened_values.length.clone());

                    builder
                        .range(0, opened_values.length.clone())
                        .for_each(|i_vec, builder| {
                            let i = i_vec[0];
                            let opening_idx = builder.get(&opening_idxes, i_vec[0]);
                            let opening = builder.get(&round.openings, opening_idx.clone());
                            let log2_height: Var<C::N> =
                                builder.eval(opening.num_var + Usize::from(get_rate_log() - 1));

                            // The linear combination is by (alpha^offset, ..., alpha^(offset+width-1)), which is equal to
                            // alpha^offset * (1, ..., alpha^(width-1))
                            let width = opening.point_and_evals.evals.len();
                            let opened_value_len: Var<C::N> = builder.eval(width.clone() * two);
                            let opened_values_buffer = builder.dyn_array(opened_value_len);
                            let alpha_offset =
                                builder.get(&input.batch_coeffs, batch_coeffs_offset);
                            let minus_alpha_offset: Ext<C::F, C::EF> = builder.eval(-alpha_offset);

                            let low_values = opened_values_buffer.slice(builder, 0, width.clone());
                            let high_values = opened_values_buffer.slice(
                                builder,
                                width.clone(),
                                opened_values_buffer.len(),
                            );

                            let end: Var<C::N> = builder.eval(batch_coeffs_offset + width.clone());
                            let batch_coeffs =
                                &input.batch_coeffs.slice(builder, batch_coeffs_offset, end);
                            builder.assign(&batch_coeffs_offset, end);

                            let all_zeros_slice = all_zeros.slice(builder, 0, width.clone());
                            let low = builder.fri_single_reduced_opening_eval(
                                alpha,
                                opened_values.id.get_var(),
                                zero_flag,
                                &low_values,
                                &all_zeros_slice,
                            );
                            let high = builder.fri_single_reduced_opening_eval(
                                alpha,
                                opened_values.id.get_var(),
                                zero_flag,
                                &high_values,
                                &all_zeros_slice,
                            );

                            builder.assign(&low, low * minus_alpha_offset);
                            builder.assign(&high, high * minus_alpha_offset);

                            let codeword: PackedCodeword<C> = PackedCodeword { low, high };
                            let codeword_acc =
                                builder.get(&reduced_codeword_by_height, log2_height);

                            // reduced_openings[log2_height] += codeword
                            builder.assign(&codeword_acc.low, codeword_acc.low + codeword.low);
                            builder.assign(&codeword_acc.high, codeword_acc.high + codeword.high);
                            builder.set_value(
                                &reduced_codeword_by_height,
                                log2_height,
                                codeword_acc,
                            );

                            // reorder opened values according to the permutation
                            let permuted_j = builder.get(&round.perm, opening_idx);
                            builder.set_value(
                                &perm_opened_values,
                                permuted_j,
                                opened_values_buffer,
                            );
                            builder.set_value(&dimensions, permuted_j, log2_height);
                        });

                    // i >>= (log2_max_codeword_size - commit.log2_max_codeword_size);
                    let bits_shift: Var<C::N> =
                        builder.eval(log2_max_codeword_size - round.commit.log2_max_codeword_size);
                    let reduced_idx_bits = idx_bits.slice(builder, bits_shift, idx_bits.len());

                    // verify input mmcs
                    let mmcs_verifier_input = MmcsVerifierInputVariable {
                        commit: round.commit.commit.clone(),
                        dimensions,
                        index_bits: reduced_idx_bits,
                        opened_values: perm_opened_values,
                        proof: opening_proof,
                    };

                    // _debug
                    // mmcs_verify_batch(builder, mmcs_verifier_input);
                });
            builder.cycle_tracker_end("Batching and first FRI round");

            let opening_ext = query.commit_phase_openings;

            // fold 1st codeword
            let cur_num_var: Var<C::N> = builder.eval(initial_cur_num_var);
            let log2_height: Var<C::N> = builder.eval(initial_log2_height);

            let r = builder.get(&input.fold_challenges, 0);
            let codeword = builder.get(&reduced_codeword_by_height, log2_height);
            let coeff = verifier_folding_coeffs_level(
                builder,
                &two_adic_generators_inverses,
                log2_height,
                &idx_bits,
                inv_2,
            );
            let folded = codeword_fold_with_challenge::<C>(
                builder,
                codeword.low,
                codeword.high,
                r,
                coeff,
                inv_2,
            );

            // check commit phases
            let commits = &input.proof.commits;
            builder.assert_eq::<Var<C::N>>(commits.len(), opening_ext.len());
            builder.cycle_tracker_start("FRI rounds");
            let i: Var<C::N> = builder.constant(C::N::ZERO);
            iter_zip!(builder, commits, opening_ext).for_each(|ptr_vec, builder| {
                let commit = builder.iter_ptr_get(commits, ptr_vec[0]);
                let commit_phase_step = builder.iter_ptr_get(&opening_ext, ptr_vec[1]);
                let i_plus_one = builder.eval_expr(i + Usize::from(1));

                let sibling_value = commit_phase_step.sibling_value;
                let proof = commit_phase_step.opening_proof;

                builder.assign(&cur_num_var, cur_num_var - Usize::from(1));
                builder.assign(&log2_height, log2_height - Usize::from(1));

                let folded_idx = builder.get(&idx_bits, i);
                let new_involved_packed_codeword =
                    builder.get(&reduced_codeword_by_height, log2_height);

                // Note that previous coeff is
                //   1/2 * generator_of_order(2^{level + 2})^{-prev_index}
                // = 1/2 * generator_of_order(2^{level + 2})^{-(index+2^level*prev_bit)}
                // = 1/2 * omega^{-2^(MAX - (level + 2)) * (index+2^level*prev_bit)}
                // where generator_of_order(2^k) returns the generator of order 2^k, which is omega^{2^(MAX - k)}
                // since omega is the generator of order 2^MAX, where MAX is the two-adicity of this field.
                // Here prev_bit is the most significant bit of prev_index, and index is removing this bit
                // from prev_index.
                //
                // So prev ^ 2 = 1/4 * omega^{-2^(MAX - (level + 2)) * 2 * (index+2^level*prev_bit)}
                //             = 1/4 * omega^{-2^(MAX - (level + 1)) * (index+2^level*prev_bit)}
                //             = 1/4 * omega^{-2^(MAX - (level + 1)) * index - 2^(MAX - (level + 1)) * 2^level*prev_bit}
                //             = 1/2 * curr * omeag^{- 2^(MAX - 1) * prev_bit}
                //             = 1/2 * curr * generator_of_order(2)^{-prev_bit}
                // Note that generator_of_order(2) is exactly -1, so
                // prev ^ 2 = 1/2 * curr * (-1)^{-prev_bit}
                // which gives us
                // curr = 2 * prev^2 * (-1)^{prev_bit}
                // Note that we haven't multplied the (-1)^{prev_bit} in the following line.
                // Because `folded_idx` is just the `prev_bit`, so we reuse the following `if_eq` and multiply -1
                // in the branch where `folded_idx` is != 0.
                builder.assign(&coeff, coeff * coeff * two_felt);

                builder.if_eq(folded_idx, Usize::from(0)).then_or_else(
                    |builder| {
                        builder.assign(&folded, folded + new_involved_packed_codeword.low);
                    },
                    |builder| {
                        builder.assign(&folded, folded + new_involved_packed_codeword.high);
                        builder.assign(&coeff, -coeff);
                    },
                );

                // leafs
                let leafs = builder.dyn_array(2);
                let sibling_idx = builder.eval_expr(RVar::from(1) - folded_idx);
                builder.set_value(&leafs, folded_idx, folded);
                builder.set_value(&leafs, sibling_idx, sibling_value);

                // idx >>= 1
                let idx_pair = idx_bits.slice(builder, i_plus_one, idx_bits.len());

                // mmcs_ext.verify_batch
                let dimensions = builder.dyn_array(1);
                let opened_values = builder.dyn_array(1);
                builder.set_value(&opened_values, 0, leafs.clone());
                builder.set_value(&dimensions, 0, log2_height);
                let ext_mmcs_verifier_input = ExtMmcsVerifierInputVariable {
                    commit: commit.clone(),
                    dimensions,
                    index_bits: idx_pair.clone(),
                    opened_values,
                    proof,
                };
                ext_mmcs_verify_batch::<C>(builder, ext_mmcs_verifier_input);

                let r = builder.get(&input.fold_challenges, i_plus_one);
                let left = builder.get(&leafs, 0);
                let right = builder.get(&leafs, 1);
                let new_folded =
                    codeword_fold_with_challenge(builder, left, right, r, coeff, inv_2);
                builder.assign(&folded, new_folded);
                builder.assign(&i, i_plus_one);
            });
            builder.cycle_tracker_end("FRI rounds");
            // assert that final_value[i] = folded
            let final_idx: Var<C::N> = builder.constant(C::N::ZERO);
            builder
                .range(commits.len(), idx_bits.len())
                .for_each(|i_vec, builder| {
                    let i = i_vec[0];
                    let bit = builder.get(&idx_bits, i);
                    builder.assign(
                        &final_idx,
                        final_idx * SymbolicVar::from(C::N::from_canonical_u16(2)) + bit,
                    );
                });
            let final_value = builder.get(&final_codeword.values, final_idx);
            builder.assert_eq::<Ext<C::F, C::EF>>(final_value, folded);
        },
    );

    // 1. check initial claim match with first round sumcheck value
    let batch_coeffs_offset: Var<C::N> = builder.constant(C::N::ZERO);
    let expected_sum: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    iter_zip!(builder, input.rounds).for_each(|ptr_vec, builder| {
        let round = builder.iter_ptr_get(&input.rounds, ptr_vec[0]);
        iter_zip!(builder, round.openings).for_each(|ptr_vec, builder| {
            let opening = builder.iter_ptr_get(&round.openings, ptr_vec[0]);
            // TODO: filter out openings with num_var >= get_basecode_msg_size_log::<C>()
            builder.if_ne(opening.num_var, zero_flag).then(|builder| {
                let var_diff: Var<C::N> =
                    builder.eval(input.max_num_var.get_var() - opening.num_var);
                let scalar_var = pow_2(builder, var_diff);
                let scalar = builder.unsafe_cast_var_to_felt(scalar_var);
                iter_zip!(builder, opening.point_and_evals.evals).for_each(|ptr_vec, builder| {
                    let eval = builder.iter_ptr_get(&opening.point_and_evals.evals, ptr_vec[0]);
                    let coeff = builder.get(&input.batch_coeffs, batch_coeffs_offset);
                    let val: Ext<C::F, C::EF> = builder.eval(eval * coeff * scalar);
                    builder.assign(&expected_sum, expected_sum + val);
                    builder.assign(&batch_coeffs_offset, batch_coeffs_offset + Usize::from(1));
                });
            });
        });
    });
    let sum: Ext<C::F, C::EF> = {
        let sumcheck_evals = builder.get(&input.proof.sumcheck_proof, 0).evaluations;
        let eval0 = builder.get(&sumcheck_evals, 0);
        let eval1 = builder.get(&sumcheck_evals, 1);
        builder.eval(eval0 + eval1)
    };
    builder.assert_eq::<Ext<C::F, C::EF>>(expected_sum, sum);

    // 2. check every round of sumcheck match with prev claims
    let fold_len_minus_one: Var<C::N> = builder.eval(input.fold_challenges.len() - Usize::from(1));
    builder
        .range(0, fold_len_minus_one)
        .for_each(|i_vec, builder| {
            let i = i_vec[0];
            let evals = builder.get(&input.proof.sumcheck_proof, i).evaluations;
            let challenge = builder.get(&input.fold_challenges, i);
            let left = interpolate_uni_poly(builder, &evals, challenge);
            let i_plus_one = builder.eval_expr(i + Usize::from(1));
            let next_evals = builder
                .get(&input.proof.sumcheck_proof, i_plus_one)
                .evaluations;
            let eval0 = builder.get(&next_evals, 0);
            let eval1 = builder.get(&next_evals, 1);
            let right: Ext<C::F, C::EF> = builder.eval(eval0 + eval1);
            builder.assert_eq::<Ext<C::F, C::EF>>(left, right);
        });

    // 3. check final evaluation are correct
    let final_evals = builder
        .get(&input.proof.sumcheck_proof, fold_len_minus_one)
        .evaluations;
    let final_challenge = builder.get(&input.fold_challenges, fold_len_minus_one);
    let left = interpolate_uni_poly(builder, &final_evals, final_challenge);
    let right: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
    let one: Var<C::N> = builder.constant(C::N::ONE);
    let j: Var<C::N> = builder.constant(C::N::ZERO);
    // \sum_i eq(p, [r,i]) * f(r,i)
    iter_zip!(builder, input.rounds).for_each(|ptr_vec, builder| {
        let round = builder.iter_ptr_get(&input.rounds, ptr_vec[0]);
        // TODO: filter out openings with num_var >= get_basecode_msg_size_log::<C>()
        iter_zip!(builder, round.openings).for_each(|ptr_vec, builder| {
            let opening = builder.iter_ptr_get(&round.openings, ptr_vec[0]);

            builder.if_ne(opening.num_var, zero_flag).then(|builder| {
                let point_and_evals = &opening.point_and_evals;
                let point = &point_and_evals.point;

                let num_vars_evaluated: Var<C::N> =
                    builder.eval(point.fs.len() - Usize::from(get_basecode_msg_size_log()));
                let final_message = builder.get(&input.proof.final_message, j);

                // coeff is the eq polynomial evaluated at the first challenge.len() variables
                let ylo = builder.eval(input.fold_challenges.len() - num_vars_evaluated);
                let coeff = eq_eval_with_index(
                    builder,
                    &point.fs,
                    &input.fold_challenges,
                    Usize::from(0),
                    Usize::Var(ylo),
                    Usize::Var(num_vars_evaluated),
                );

                // compute \sum_i eq(p[..num_vars_evaluated], r) * eq(p[num_vars_evaluated..], i) * f(r,i)
                //
                // We always assume that num_vars_evaluated is equal to p.len()
                // so that the above sum only has one item and the final evaluation vector has only one element.
                builder.assert_eq::<Var<C::N>>(final_message.len(), one);

                let final_message = builder.get(&final_message, 0);
                let dot_prod: Ext<C::F, C::EF> = builder.eval(final_message * coeff);

                builder.assign(&right, right + dot_prod);
                builder.assign(&j, j + Usize::from(1));
            });
        });
    });
    builder.assert_eq::<Var<C::N>>(j, input.proof.final_message.len());
    builder.assert_eq::<Ext<C::F, C::EF>>(left, right);
}

#[cfg(test)]
pub mod tests {
    use ff_ext::{BabyBearExt4, FromUniformBytes};
    use itertools::Itertools;
    use mpcs::{
        BasefoldDefault, BasefoldRSParams, BasefoldSpec, PCSFriParam, PolynomialCommitmentScheme,
        pcs_batch_commit, pcs_trim, util::hash::write_digest_to_transcript,
    };
    use openvm_circuit::arch::{SystemConfig, VmExecutor, instructions::program::Program};
    use openvm_instructions::exe::VmExe;
    use openvm_native_circuit::{Native, NativeConfig};
    use openvm_native_compiler::asm::AsmBuilder;
    use openvm_native_recursion::hints::Hintable;
    use openvm_stark_backend::p3_challenger::GrindingChallenger;
    use openvm_stark_sdk::p3_baby_bear::BabyBear;
    use rand::thread_rng;
    use transcript::{BasicTranscript, Transcript};

    type F = BabyBear;
    type E = BabyBearExt4;
    type Pcs = BasefoldDefault<E>;

    use crate::{
        basefold_verifier::{
            basefold::{Round, RoundOpening},
            query_phase::PointAndEvals,
        },
        tower_verifier::binding::Point,
    };

    use super::{QueryPhaseVerifierInput, batch_verifier_query_phase};

    pub fn build_batch_verifier_query_phase(
        input: QueryPhaseVerifierInput,
    ) -> (Program<BabyBear>, Vec<Vec<BabyBear>>) {
        // build test program
        let mut builder = AsmBuilder::<F, E>::default();
        let query_phase_input = QueryPhaseVerifierInput::read(&mut builder);
        batch_verifier_query_phase(&mut builder, query_phase_input);
        builder.halt();
        let program = builder.compile_isa();

        // prepare input
        let mut witness_stream: Vec<Vec<F>> = Vec::new();
        witness_stream.extend(input.write());

        (program, witness_stream)
    }

    fn construct_test(dimensions: Vec<(usize, usize)>) {
        let mut rng = thread_rng();

        // setup PCS
        let pp = Pcs::setup(1 << 20, mpcs::SecurityLevel::Conjecture100bits).unwrap();
        let (pp, vp) = pcs_trim::<E, Pcs>(pp, 1 << 20).unwrap();

        let mut num_total_polys = 0;
        let (matrices, mles): (Vec<_>, Vec<_>) = dimensions
            .into_iter()
            .map(|(num_vars, width)| {
                let m = witness::RowMajorMatrix::<F>::rand(&mut rng, 1 << num_vars, width);
                let mles = m.to_mles();
                num_total_polys += width;

                (m, mles)
            })
            .unzip();

        // commit to matrices
        let pcs_data = pcs_batch_commit::<E, Pcs>(&pp, matrices).unwrap();
        let comm = Pcs::get_pure_commitment(&pcs_data);

        let point_and_evals = mles
            .iter()
            .map(|mles| {
                let point = E::random_vec(mles[0].num_vars(), &mut rng);
                let evals = mles.iter().map(|mle| mle.evaluate(&point)).collect_vec();

                (point, evals)
            })
            .collect_vec();

        // batch open
        let mut transcript = BasicTranscript::<E>::new(&[]);
        let rounds = vec![(&pcs_data, point_and_evals.clone())];
        let opening_proof = Pcs::batch_open(&pp, rounds, &mut transcript).unwrap();

        // batch verify
        let mut transcript = BasicTranscript::<E>::new(&[]);
        let rounds = vec![(
            comm,
            point_and_evals
                .iter()
                .map(|(point, evals)| (point.len(), (point.clone(), evals.clone())))
                .collect_vec(),
        )];
        Pcs::batch_verify(&vp, rounds.clone(), &opening_proof, &mut transcript)
            .expect("Native verification failed");

        let mut transcript = BasicTranscript::<E>::new(&[]);
        let batch_coeffs =
            transcript.sample_and_append_challenge_pows(num_total_polys, b"batch coeffs");

        let max_num_var = point_and_evals
            .iter()
            .map(|(point, _)| point.len())
            .max()
            .unwrap();
        let max_width = point_and_evals
            .iter()
            .map(|(_, evals)| evals.len())
            .max()
            .unwrap();
        let num_rounds = max_num_var; // The final message is of length 1

        // prepare folding challenges via sumcheck round msg + FRI commitment
        let mut fold_challenges: Vec<E> = Vec::with_capacity(num_rounds);
        let commits = &opening_proof.commits;

        let sumcheck_messages = opening_proof.sumcheck_proof.as_ref().unwrap();
        for i in 0..num_rounds {
            transcript.append_field_element_exts(sumcheck_messages[i].evaluations.as_slice());
            fold_challenges.push(
                transcript
                    .sample_and_append_challenge(b"commit round")
                    .elements,
            );
            if i < num_rounds - 1 {
                write_digest_to_transcript(&commits[i], &mut transcript);
            }
        }
        transcript.append_field_element_exts_iter(opening_proof.final_message.iter().flatten());

        // check pow
        let pow_bits = vp.get_pow_bits_by_level(mpcs::PowStrategy::FriPow);
        if pow_bits > 0 {
            assert!(transcript.check_witness(pow_bits, opening_proof.pow_witness));
        }

        let queries: Vec<_> = transcript.sample_bits_and_append_vec(
            b"query indices",
            <BasefoldRSParams as BasefoldSpec<E>>::get_number_queries(),
            max_num_var + <BasefoldRSParams as BasefoldSpec<E>>::get_rate_log(),
        );

        let query_input = QueryPhaseVerifierInput {
            max_num_var,
            max_width,
            fold_challenges,
            batch_coeffs,
            indices: queries,
            proof: opening_proof.into(),
            rounds: rounds
                .into_iter()
                .map(|round| Round {
                    commit: round.0.into(),
                    openings: round
                        .1
                        .into_iter()
                        .map(|(num_var, (point, evals))| RoundOpening {
                            num_var,
                            point_and_evals: PointAndEvals {
                                point: Point { fs: point },
                                evals,
                            },
                        })
                        .collect(),
                })
                .collect(),
        };
        let (program, witness) = build_batch_verifier_query_phase(query_input);

        let system_config = SystemConfig::default()
            .with_public_values(4)
            .with_max_segment_len((1 << 25) - 100);
        let config = NativeConfig::new(system_config, Native);

        let executor = VmExecutor::<BabyBear, NativeConfig>::new(config).unwrap();
        let exe = VmExe::new(program);
        let interpreter = executor.instance(&exe).unwrap();
        interpreter
            .execute(witness, None)
            .expect("constructed test should pass");
    }

    #[test]
    fn test_simple_batch() {
        for num_var in 5..20 {
            construct_test(vec![(num_var, 20)]);
        }
    }

    #[test]
    fn test_decreasing_batch() {
        construct_test(vec![
            (14, 20),
            (14, 40),
            (13, 30),
            (12, 30),
            (11, 10),
            (10, 15),
        ]);
    }

    #[test]
    fn test_random_batch() {
        construct_test(vec![(10, 20), (12, 30), (11, 10), (12, 15)]);
    }
}
