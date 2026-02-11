// The crate sha extend circuit is modified from succinctlabs/sp1 under MIT license

// The MIT License (MIT)

// Copyright (c) 2023 Succinct Labs

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use std::{array, borrow::BorrowMut, mem::size_of};

use derive::AlignedBorrow;
use ff_ext::{ExtensionField, SmallField};
use gkr_iop::{
    OutEvalGroups, ProtocolBuilder, ProtocolWitnessGenerator, chip::Chip,
    circuit_builder::CircuitBuilder, error::CircuitBuilderError, selector::SelectorType,
};
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr, WitIn, util::max_usable_threads};
use p3::field::{FieldAlgebra, TwoAdicField};
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    prelude::ParallelSlice,
};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::MemoryExpr,
    gadgets::{
        Add4Operation, FixedRotateRightOperation, FixedShiftRightOperation, Word, XorOperation,
    },
    precompiles::{SelectorTypeLayout, utils::merge_u8_slice_to_u16_limbs_pairs_and_extend},
    witness::LkMultiplicity,
};

pub const SHA_EXTEND_ROUNDS: usize = 48;

#[derive(Clone, Debug, AlignedBorrow)]
#[repr(C)]
pub struct ShaExtendWitCols<T> {
    /// Inputs to `s0`.
    pub w_i_minus_15: Word<T>,
    pub w_i_minus_15_rr_7: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rr_18: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rs_3: FixedShiftRightOperation<T>,
    pub s0_intermediate: XorOperation<T>,

    /// `s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)`.
    pub s0: XorOperation<T>,

    /// Inputs to `s1`.
    pub w_i_minus_2: Word<T>,
    pub w_i_minus_2_rr_17: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rr_19: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rs_10: FixedShiftRightOperation<T>,
    pub s1_intermediate: XorOperation<T>,

    /// `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)`.
    pub s1: XorOperation<T>,

    /// Inputs to `s2`.
    pub w_i_minus_16: Word<T>,
    pub w_i_minus_7: Word<T>,

    /// `w[i] := w[i-16] + s0 + w[i-7] + s1`.
    pub s2: Add4Operation<T>,
}

impl<F: SmallField + TwoAdicField> ShaExtendWitCols<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(&mut self, instance: &ShaExtendWitInstance, blu: &mut LkMultiplicity) {
        // `s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift
        // 3)`.
        let w_i_minus_15 = instance.w_i_minus_15;
        self.w_i_minus_15 = Word::from(w_i_minus_15);
        let w_i_minus_15_rr_7 = self.w_i_minus_15_rr_7.populate(blu, w_i_minus_15, 7);
        let w_i_minus_15_rr_18 = self.w_i_minus_15_rr_18.populate(blu, w_i_minus_15, 18);
        let w_i_minus_15_rs_3 = self.w_i_minus_15_rs_3.populate(blu, w_i_minus_15, 3);
        let s0_intermediate =
            self.s0_intermediate
                .populate(blu, w_i_minus_15_rr_7, w_i_minus_15_rr_18);
        let s0 = self.s0.populate(blu, s0_intermediate, w_i_minus_15_rs_3);

        // `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift
        // 10)`.
        let w_i_minus_2 = instance.w_i_minus_2;
        self.w_i_minus_2 = Word::from(w_i_minus_2);
        let w_i_minus_2_rr_17 = self.w_i_minus_2_rr_17.populate(blu, w_i_minus_2, 17);
        let w_i_minus_2_rr_19 = self.w_i_minus_2_rr_19.populate(blu, w_i_minus_2, 19);
        let w_i_minus_2_rs_10 = self.w_i_minus_2_rs_10.populate(blu, w_i_minus_2, 10);
        let s1_intermediate =
            self.s1_intermediate
                .populate(blu, w_i_minus_2_rr_17, w_i_minus_2_rr_19);
        let s1 = self.s1.populate(blu, s1_intermediate, w_i_minus_2_rs_10);

        // Compute `s2`.
        let w_i_minus_7 = instance.w_i_minus_7;
        let w_i_minus_16 = instance.w_i_minus_16;
        self.w_i_minus_7 = Word::from(w_i_minus_7);
        self.w_i_minus_16 = Word::from(w_i_minus_16);
        self.s2.populate(blu, w_i_minus_16, s0, w_i_minus_7, s1);
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ShaExtendLayer<WitT> {
    pub wits: ShaExtendWitCols<WitT>,
}

#[derive(Clone, Debug)]
pub struct ShaExtendLayout<E: ExtensionField> {
    pub layer_exprs: ShaExtendLayer<WitIn>,
    pub selector_type_layout: SelectorTypeLayout<E>,
    pub input32_exprs: [MemoryExpr<E>; 4],
    pub output32_expr: MemoryExpr<E>,
    pub n_fixed: usize,
    pub n_committed: usize,
    pub n_structural_witin: usize,
    pub n_challenges: usize,
}

impl<E: ExtensionField> ShaExtendLayout<E> {
    fn new(cb: &mut CircuitBuilder<E>) -> Self {
        let wits = ShaExtendWitCols {
            w_i_minus_15: Word::create(cb, || "ShaExtendLayer::w_i_minus_15"),
            w_i_minus_15_rr_7: FixedRotateRightOperation::create(
                cb,
                || "ShaExtendLayer::w_i_minus_15_rr_7",
            ),
            w_i_minus_15_rr_18: FixedRotateRightOperation::create(
                cb,
                || "ShaExtendLayer::w_i_minus_15_rr_18",
            ),
            w_i_minus_15_rs_3: FixedShiftRightOperation::create(
                cb,
                || "ShaExtendLayer::w_i_minus_15_rs_3",
            ),
            s0_intermediate: XorOperation::create(cb, || "ShaExtendLayer::s0_intermediate"),
            s0: XorOperation::create(cb, || "ShaExtendLayer::s0"),
            w_i_minus_2: Word::create(cb, || "ShaExtendLayer::w_i_minus_2"),
            w_i_minus_2_rr_17: FixedRotateRightOperation::create(
                cb,
                || "ShaExtendLayer::w_i_minus_2_rr_17",
            ),
            w_i_minus_2_rr_19: FixedRotateRightOperation::create(
                cb,
                || "ShaExtendLayer::w_i_minus_2_rr_19",
            ),
            w_i_minus_2_rs_10: FixedShiftRightOperation::create(
                cb,
                || "ShaExtendLayer::w_i_minus_2_rs_10",
            ),
            s1_intermediate: XorOperation::create(cb, || "ShaExtendLayer::s1_intermediate"),
            s1: XorOperation::create(cb, || "ShaExtendLayer::s1"),
            w_i_minus_16: Word::create(cb, || "ShaExtendLayer::w_i_minus_16"),
            w_i_minus_7: Word::create(cb, || "ShaExtendLayer::w_i_minus_7"),
            s2: Add4Operation::create(cb, || "ShaExtendLayer::s2"),
        };

        let sel_all = cb.create_placeholder_structural_witin(|| "sha_extend_sel_all");

        let selector_type_layout = SelectorTypeLayout {
            sel_first: None,
            sel_last: None,
            sel_all: SelectorType::<E>::Prefix(sel_all.expr()),
        };

        let input32_exprs: [MemoryExpr<E>; 4] =
            array::from_fn(|_| array::from_fn(|_| Expression::WitIn(0)));
        let output32_expr: MemoryExpr<E> = array::from_fn(|_| Expression::WitIn(0));

        Self {
            layer_exprs: ShaExtendLayer { wits },
            selector_type_layout,
            input32_exprs,
            output32_expr,
            n_fixed: 0,
            n_committed: 0,
            n_structural_witin: 6,
            n_challenges: 0,
        }
    }
}

impl<E: ExtensionField> ProtocolBuilder<E> for ShaExtendLayout<E> {
    type Params = ();

    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        _params: Self::Params,
    ) -> Result<Self, CircuitBuilderError> {
        let mut layout = Self::new(cb);
        let wits = &layout.layer_exprs.wits;

        // Compute `s0`.
        // w[i-15] rightrotate 7.
        wits.w_i_minus_15_rr_7.eval(cb, wits.w_i_minus_15, 7)?;
        // w[i-15] rightrotate 18.
        wits.w_i_minus_15_rr_18.eval(cb, wits.w_i_minus_15, 18)?;
        // w[i-15] rightshift 3.
        wits.w_i_minus_15_rs_3.eval(cb, wits.w_i_minus_15, 3)?;
        // (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18)
        wits.s0_intermediate.eval(
            cb,
            wits.w_i_minus_15_rr_7.value,
            wits.w_i_minus_15_rr_18.value,
        )?;
        // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        wits.s0
            .eval(cb, wits.s0_intermediate.value, wits.w_i_minus_15_rs_3.value)?;

        // Compute `s1`.
        // w[i-2] rightrotate 17.
        wits.w_i_minus_2_rr_17.eval(cb, wits.w_i_minus_2, 17)?;
        // w[i-2] rightrotate 19.
        wits.w_i_minus_2_rr_19.eval(cb, wits.w_i_minus_2, 19)?;
        // w[i-2] rightshift 10.
        wits.w_i_minus_2_rs_10.eval(cb, wits.w_i_minus_2, 10)?;
        // (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19)
        wits.s1_intermediate.eval(
            cb,
            wits.w_i_minus_2_rr_17.value,
            wits.w_i_minus_2_rr_19.value,
        )?;
        // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        wits.s1
            .eval(cb, wits.s1_intermediate.value, wits.w_i_minus_2_rs_10.value)?;

        // s2 (or w[i]):= w[i-16] + s0 + w[i-7] + s1.
        wits.s2.eval(
            cb,
            wits.w_i_minus_16,
            wits.s0.value,
            wits.w_i_minus_7,
            wits.s1.value,
        )?;

        let mut input32_exprs = Vec::with_capacity(4);
        for w in [
            &wits.w_i_minus_2,
            &wits.w_i_minus_7,
            &wits.w_i_minus_15,
            &wits.w_i_minus_16,
        ] {
            merge_u8_slice_to_u16_limbs_pairs_and_extend(&w.0, &mut input32_exprs);
        }
        layout.input32_exprs = input32_exprs.try_into().unwrap();
        let mut output32_expr = Vec::with_capacity(1);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.s2.value.0, &mut output32_expr);
        layout.output32_expr = output32_expr.pop().unwrap();

        Ok(layout)
    }

    fn finalize(&mut self, cb: &mut CircuitBuilder<E>) -> (OutEvalGroups, Chip<E>) {
        self.n_fixed = cb.cs.num_fixed;
        self.n_committed = cb.cs.num_witin as usize;
        self.n_structural_witin = cb.cs.num_structural_witin as usize;
        self.n_challenges = 0;

        cb.cs.r_selector = Some(self.selector_type_layout.sel_all.clone());
        cb.cs.w_selector = Some(self.selector_type_layout.sel_all.clone());
        cb.cs.lk_selector = Some(self.selector_type_layout.sel_all.clone());
        cb.cs.zero_selector = Some(self.selector_type_layout.sel_all.clone());

        let w_len = cb.cs.w_expressions.len();
        let r_len = cb.cs.r_expressions.len();
        let lk_len = cb.cs.lk_expressions.len();
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();
        (
            [
                (0..r_len).collect_vec(),
                (r_len..r_len + w_len).collect_vec(),
                (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
                (0..zero_len).collect_vec(),
            ],
            Chip::new_from_cb(cb, self.n_challenges),
        )
    }
}

#[derive(Clone, Debug)]
pub struct ShaExtendWitInstance {
    pub w_i_minus_2: u32,
    pub w_i_minus_7: u32,
    pub w_i_minus_15: u32,
    pub w_i_minus_16: u32,
}

#[derive(Clone, Debug)]
pub struct ShaExtendInstance {
    pub witin: ShaExtendWitInstance,
}

#[derive(Clone, Debug, Default)]
pub struct ShaExtendTrace {
    pub instances: Vec<ShaExtendInstance>,
}

impl<E: ExtensionField> ProtocolWitnessGenerator<E> for ShaExtendLayout<E> {
    type Trace = ShaExtendTrace;

    fn fixed_witness_group(&self) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::new(0, 0, InstancePaddingStrategy::Default)
    }

    fn phase1_witness_group(
        &self,
        phase1: Self::Trace,
        wits: [&mut RowMajorMatrix<E::BaseField>; 2],
        lk_multiplicity: &mut LkMultiplicity,
    ) {
        let (wits_start, num_wit_cols) = (
            self.layer_exprs.wits.w_i_minus_15.0[0].id as usize,
            size_of::<ShaExtendWitCols<u8>>(),
        );
        let [wits, structural_wits] = wits;
        let num_instances = wits.num_instances();
        let nthreads = max_usable_threads();
        let num_instance_per_batch = num_instances.div_ceil(nthreads).max(1);
        let raw_witin_iter = wits.par_batch_iter_mut(num_instance_per_batch);
        let raw_structural_wits_iter = structural_wits.par_batch_iter_mut(num_instance_per_batch);
        raw_witin_iter
            .zip_eq(raw_structural_wits_iter)
            .zip_eq(phase1.instances.par_chunks(num_instance_per_batch))
            .for_each(|((rows, eqs), instances)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                rows.chunks_mut(self.n_committed)
                    .zip_eq(eqs.chunks_mut(self.n_structural_witin))
                    .zip_eq(instances.iter())
                    .for_each(|((rows, eqs), phase1_instance)| {
                        let sel_all_structural_witin =
                            self.selector_type_layout.sel_all.selector_expr().id();
                        eqs[sel_all_structural_witin] = E::BaseField::ONE;

                        let cols: &mut ShaExtendWitCols<E::BaseField> =
                            rows[wits_start..][..num_wit_cols].borrow_mut();
                        cols.populate(&phase1_instance.witin, &mut lk_multiplicity);
                    });
            });
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit_builder::ConstraintSystem;

    use super::*;

    use std::sync::Arc;

    use ceno_emul::{SHA_EXTEND_WORDS, WORD_SIZE};
    use ff_ext::BabyBearExt4;
    use gkr_iop::{
        cpu::{CpuBackend, CpuProver},
        gkr::{GKRProverOutput, layer::Layer},
        selector::SelectorContext,
    };
    use itertools::Itertools;
    use mpcs::BasefoldDefault;
    use multilinear_extensions::{mle::PointAndEval, util::ceil_log2};
    use p3::{babybear::BabyBear, matrix::Matrix};
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use sumcheck::util::optimal_sumcheck_threads;
    use transcript::{BasicTranscript, Transcript};
    use witness::next_pow2_instance_padding;

    fn test_sha_extend_helper(num_instances: usize) {
        type E = BabyBearExt4;
        type Pcs = BasefoldDefault<E>;

        let mut cs = ConstraintSystem::<E>::new(|| "sha_extend_test");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);
        let mut layout =
            ShaExtendLayout::<E>::build_layer_logic(&mut cb, ()).expect("build_layer_logic failed");
        let (out_evals, mut chip) = layout.finalize(&mut cb);
        let layer = Layer::from_circuit_builder(
            &cb,
            "sha_extend".to_string(),
            layout.n_challenges,
            out_evals,
        );
        chip.add_layer(layer);
        let gkr_circuit = chip.gkr_circuit();

        let mut rng = StdRng::seed_from_u64(1);
        let mut instances = Vec::new();
        let mut expected_outputs = Vec::new();

        for _ in 0..num_instances {
            let mut words = [0u32; SHA_EXTEND_WORDS];
            for word in words.iter_mut().take(16) {
                *word = rng.next_u32();
            }
            sha_extend(&mut words);
            for j in 16..SHA_EXTEND_ROUNDS + 16 {
                instances.push(ShaExtendInstance {
                    witin: ShaExtendWitInstance {
                        w_i_minus_2: words[j - 2],
                        w_i_minus_7: words[j - 7],
                        w_i_minus_15: words[j - 15],
                        w_i_minus_16: words[j - 16],
                    },
                });
            }
            expected_outputs.push(words[16..].to_vec());
        }

        let num_instances = num_instances * SHA_EXTEND_ROUNDS;
        let mut phase1 = RowMajorMatrix::new(
            num_instances,
            layout.n_committed,
            InstancePaddingStrategy::Default,
        );
        let mut structural = RowMajorMatrix::new(
            num_instances,
            layout.n_structural_witin,
            InstancePaddingStrategy::Default,
        );
        let mut lk_multiplicity = LkMultiplicity::default();
        layout.phase1_witness_group(
            ShaExtendTrace { instances },
            [&mut phase1, &mut structural],
            &mut lk_multiplicity,
        );

        let out_index = layout.layer_exprs.wits.s2.value.0[0].id as usize;
        for (instance_idx, expected_output) in expected_outputs.iter().enumerate() {
            for (round_idx, expected_word_u32) in
                expected_output.iter().take(SHA_EXTEND_ROUNDS).enumerate()
            {
                let row_idx = instance_idx * SHA_EXTEND_ROUNDS + round_idx;
                let output_word: [_; WORD_SIZE] = phase1.row_slice(row_idx)
                    [out_index..out_index + 4]
                    .to_vec()
                    .try_into()
                    .unwrap();
                let expected_word = Word::<BabyBear>::from(*expected_word_u32);
                assert_eq!(
                    output_word, expected_word.0,
                    "mismatch at instance {}, round {}",
                    instance_idx, round_idx
                );
            }
        }

        let num_instances_rounds = next_pow2_instance_padding(num_instances);
        let log2_num_instance_rounds = ceil_log2(num_instances_rounds);
        let num_threads = optimal_sumcheck_threads(log2_num_instance_rounds);
        let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");
        let challenges = [
            prover_transcript.read_challenge().elements,
            prover_transcript.read_challenge().elements,
        ];

        let phase1_witness_group = phase1.to_mles().into_iter().map(Arc::new).collect_vec();
        let structural_witness = structural.to_mles().into_iter().map(Arc::new).collect_vec();
        let fixed = layout
            .fixed_witness_group()
            .to_mles()
            .into_iter()
            .map(Arc::new)
            .collect_vec();

        let (gkr_witness, gkr_output) =
            crate::scheme::utils::gkr_witness::<E, Pcs, CpuBackend<E, Pcs>, CpuProver<_>>(
                &gkr_circuit,
                &phase1_witness_group,
                &structural_witness,
                &fixed,
                &[],
                &[],
                &challenges,
                None,
            );

        let out_evals = {
            let mut point = Vec::with_capacity(log2_num_instance_rounds);
            point.extend(
                prover_transcript
                    .sample_vec(log2_num_instance_rounds)
                    .to_vec(),
            );

            let out_evals = gkr_output
                .0
                .par_iter()
                .map(|wit| {
                    let point = point[point.len() - wit.num_vars()..point.len()].to_vec();
                    PointAndEval {
                        point: point.clone(),
                        eval: wit.evaluate(&point),
                    }
                })
                .collect::<Vec<_>>();

            if out_evals.is_empty() {
                vec![PointAndEval {
                    point: point[point.len() - log2_num_instance_rounds..point.len()].to_vec(),
                    eval: E::ZERO,
                }]
            } else {
                out_evals
            }
        };

        let selector_ctxs =
            vec![SelectorContext::new(0, num_instances, log2_num_instance_rounds); 1];
        let GKRProverOutput { gkr_proof, .. } = gkr_circuit
            .prove::<CpuBackend<E, Pcs>, CpuProver<_>>(
                num_threads,
                log2_num_instance_rounds,
                gkr_witness,
                &out_evals,
                &[],
                &challenges,
                &mut prover_transcript,
                &selector_ctxs,
                None,
            )
            .expect("sha extend prove failed");

        let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");
        let challenges = [
            verifier_transcript.read_challenge().elements,
            verifier_transcript.read_challenge().elements,
        ];
        let mut point = Vec::with_capacity(log2_num_instance_rounds);
        point.extend(
            verifier_transcript
                .sample_vec(log2_num_instance_rounds)
                .to_vec(),
        );

        gkr_circuit
            .verify(
                log2_num_instance_rounds,
                gkr_proof,
                &out_evals,
                &[],
                &[],
                &challenges,
                &mut verifier_transcript,
                &selector_ctxs,
            )
            .expect("sha extend verify failed");
    }

    #[test]
    fn test_sha_extend() {
        test_sha_extend_helper(4);
    }

    #[test]
    fn test_sha_extend_non_pow2() {
        test_sha_extend_helper(5);
    }

    fn sha_extend(w: &mut [u32; SHA_EXTEND_WORDS]) {
        for i in 16..SHA_EXTEND_WORDS {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
    }
}
