// The crate fp circuit is modified from succinctlabs/sp1 under MIT license

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

use std::{array, borrow::BorrowMut, marker::PhantomData, mem::size_of};

use derive::AlignedBorrow;
use ff_ext::ExtensionField;
use generic_array::{GenericArray, sequence::GenericSequence};
use gkr_iop::{
    OutEvalGroups, ProtocolBuilder, ProtocolWitnessGenerator, chip::Chip,
    circuit_builder::CircuitBuilder, error::CircuitBuilderError, selector::SelectorType,
};
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr, WitIn, util::max_usable_threads};
use num::BigUint;
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    prelude::ParallelSlice,
};
use sp1_curves::{
    params::{Limbs, NumWords},
    polynomial::Polynomial,
    weierstrass::FpOpField,
};
use typenum::Unsigned;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::MemoryExpr,
    gadgets::{FieldOperation, field_op::FieldOpCols, range::FieldLtCols},
    precompiles::{SelectorTypeLayout, utils::merge_u8_slice_to_u16_limbs_pairs_and_extend},
    witness::LkMultiplicity,
};

pub const fn num_fp_cols<P: FpOpField>() -> usize {
    size_of::<FpOpWitCols<u8, P>>()
}

#[derive(Debug, Clone)]
pub struct FpOpInstance<P: FpOpField> {
    pub x: BigUint,
    pub y: BigUint,
    pub op: FieldOperation,
    _marker: PhantomData<P>,
}

impl<P: FpOpField> FpOpInstance<P> {
    pub fn new(x: BigUint, y: BigUint, op: FieldOperation) -> Self {
        Self {
            x,
            y,
            op,
            _marker: PhantomData,
        }
    }
}

pub struct FpOpTrace<P: FpOpField> {
    pub instances: Vec<FpOpInstance<P>>,
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FpOpWitCols<T, P: FpOpField> {
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub x_limbs: Limbs<T, P::Limbs>,
    pub y_limbs: Limbs<T, P::Limbs>,
    pub output: FieldOpCols<T, P>,
    pub output_range_check: FieldLtCols<T, P>,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct FpOpLayer<WitT, P: FpOpField> {
    pub wits: FpOpWitCols<WitT, P>,
}

#[derive(Clone, Debug)]
pub struct FpOpLayout<E: ExtensionField, P: FpOpField> {
    pub layer_exprs: FpOpLayer<WitIn, P>,
    pub selector_type_layout: SelectorTypeLayout<E>,
    pub input32_exprs: [GenericArray<MemoryExpr<E>, <P as NumWords>::WordsFieldElement>; 2],
    pub output32_exprs: GenericArray<MemoryExpr<E>, <P as NumWords>::WordsFieldElement>,
    pub n_fixed: usize,
    pub n_committed: usize,
    pub n_structural_witin: usize,
    pub n_challenges: usize,
}

impl<E: ExtensionField, P: FpOpField> FpOpLayout<E, P> {
    fn new(cb: &mut CircuitBuilder<E>) -> Self {
        let wits = FpOpWitCols {
            is_add: cb.create_witin(|| "fp_op_is_add"),
            is_sub: cb.create_witin(|| "fp_op_is_sub"),
            is_mul: cb.create_witin(|| "fp_op_is_mul"),
            x_limbs: Limbs(GenericArray::generate(|_| cb.create_witin(|| "fp_op_x"))),
            y_limbs: Limbs(GenericArray::generate(|_| cb.create_witin(|| "fp_op_y"))),
            output: FieldOpCols::create(cb, || "fp_op_output"),
            output_range_check: FieldLtCols::create(cb, || "fp_op_output_range"),
        };

        let eq = cb.create_placeholder_structural_witin(|| "fp_op_structural_witin");
        let sel = SelectorType::Prefix(eq.expr());
        let selector_type_layout = SelectorTypeLayout {
            sel_first: None,
            sel_last: None,
            sel_all: sel.clone(),
        };

        let input32_exprs: [GenericArray<MemoryExpr<E>, <P as NumWords>::WordsFieldElement>; 2] =
            array::from_fn(|_| {
                GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)))
            });
        let output32_exprs: GenericArray<MemoryExpr<E>, <P as NumWords>::WordsFieldElement> =
            GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));

        Self {
            layer_exprs: FpOpLayer { wits },
            selector_type_layout,
            input32_exprs,
            output32_exprs,
            n_fixed: 0,
            n_committed: 0,
            n_structural_witin: 0,
            n_challenges: 0,
        }
    }

    fn populate_row(
        instance: &FpOpInstance<P>,
        cols: &mut FpOpWitCols<E::BaseField, P>,
        lk_multiplicity: &mut LkMultiplicity,
    ) {
        cols.is_add = E::BaseField::from_canonical_u8((instance.op == FieldOperation::Add) as u8);
        cols.is_sub = E::BaseField::from_canonical_u8((instance.op == FieldOperation::Sub) as u8);
        cols.is_mul = E::BaseField::from_canonical_u8((instance.op == FieldOperation::Mul) as u8);
        cols.x_limbs = P::to_limbs_field(&instance.x);
        cols.y_limbs = P::to_limbs_field(&instance.y);

        let modulus = P::modulus();
        let output = cols.output.populate_with_modulus(
            lk_multiplicity,
            &instance.x,
            &instance.y,
            &modulus,
            instance.op,
        );
        cols.output_range_check
            .populate(lk_multiplicity, &output, &modulus);
    }
}

impl<E: ExtensionField, P: FpOpField> ProtocolBuilder<E> for FpOpLayout<E, P> {
    type Params = ();

    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        _params: Self::Params,
    ) -> Result<Self, CircuitBuilderError> {
        let mut layout = FpOpLayout::new(cb);
        let wits = &layout.layer_exprs.wits;

        cb.assert_bit(|| "fp_op_is_add_bool", wits.is_add.expr())?;
        cb.assert_bit(|| "fp_op_is_sub_bool", wits.is_sub.expr())?;
        cb.assert_bit(|| "fp_op_is_mul_bool", wits.is_mul.expr())?;
        cb.require_one(
            || "fp_op_one_hot",
            wits.is_add.expr() + wits.is_sub.expr() + wits.is_mul.expr(),
        )?;

        let modulus: Polynomial<Expression<E>> = P::to_limbs_expr::<E>(&P::modulus()).into();
        let zero = E::BaseField::ZERO.expr();

        wits.output.eval_variable(
            cb,
            &wits.x_limbs,
            &wits.y_limbs,
            &modulus,
            wits.is_add.expr(),
            wits.is_sub.expr(),
            wits.is_mul.expr(),
            zero,
        )?;
        wits.output_range_check
            .eval(cb, &wits.output.result, &modulus)?;

        let mut x_input32 = Vec::with_capacity(<P as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.x_limbs.0, &mut x_input32);
        let x_input32 = x_input32.try_into().unwrap();

        let mut y_input32 = Vec::with_capacity(<P as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.y_limbs.0, &mut y_input32);
        let y_input32 = y_input32.try_into().unwrap();

        let mut output32 = Vec::with_capacity(<P as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.output.result.0, &mut output32);
        let output32 = output32.try_into().unwrap();

        layout.input32_exprs = [x_input32, y_input32];
        layout.output32_exprs = output32;

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

impl<E: ExtensionField, P: FpOpField> ProtocolWitnessGenerator<E> for FpOpLayout<E, P> {
    type Trace = FpOpTrace<P>;

    fn fixed_witness_group(&self) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::new(0, 0, InstancePaddingStrategy::Default)
    }

    fn phase1_witness_group(
        &self,
        phase1: Self::Trace,
        wits: [&mut RowMajorMatrix<E::BaseField>; 2],
        lk_multiplicity: &mut LkMultiplicity,
    ) {
        let (wits_start, num_wit_cols) =
            (self.layer_exprs.wits.is_add.id as usize, num_fp_cols::<P>());
        let [wits, structural_wits] = wits;
        let num_instances = wits.num_instances();
        let nthreads = max_usable_threads();
        let num_instance_per_batch = num_instances.div_ceil(nthreads).max(1);
        let raw_witin_iter = wits.par_batch_iter_mut(num_instance_per_batch);
        let raw_structural_wits_iter = structural_wits.par_batch_iter_mut(num_instance_per_batch);
        raw_witin_iter
            .zip_eq(raw_structural_wits_iter)
            .zip_eq(phase1.instances.par_chunks(num_instance_per_batch))
            .for_each(|((rows, eqs), phase1_instances)| {
                let mut lk_multiplicity = lk_multiplicity.clone();
                rows.chunks_mut(self.n_committed)
                    .zip_eq(eqs.chunks_mut(self.n_structural_witin))
                    .zip_eq(phase1_instances)
                    .for_each(|((row, eqs), phase1_instance)| {
                        let cols: &mut FpOpWitCols<E::BaseField, P> =
                            row[wits_start..][..num_wit_cols].borrow_mut();
                        Self::populate_row(phase1_instance, cols, &mut lk_multiplicity);
                        for x in eqs.iter_mut() {
                            *x = E::BaseField::ONE;
                        }
                    });
            });
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use ff_ext::{BabyBearExt4, SmallField};
    use gkr_iop::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        cpu::{CpuBackend, CpuProver},
        gkr::{GKRProverOutput, layer::Layer},
        selector::SelectorContext,
    };
    use itertools::Itertools;
    use mpcs::BasefoldDefault;
    use multilinear_extensions::{mle::PointAndEval, util::ceil_log2};
    use num::BigUint;
    use rand::RngCore;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use sp1_curves::weierstrass::{bls12_381::Bls12381BaseField, bn254::Bn254BaseField};
    use std::sync::Arc;
    use sumcheck::util::optimal_sumcheck_threads;
    use transcript::{BasicTranscript, Transcript};
    use witness::{InstancePaddingStrategy, RowMajorMatrix};

    use crate::witness::LkMultiplicity;

    fn random_mod<P: FpOpField>() -> BigUint {
        let mut bytes = vec![0u8; P::NB_LIMBS + 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        BigUint::from_bytes_le(&bytes) % P::modulus()
    }

    fn test_fp_ops_helper<P: FpOpField>(count: usize) {
        type E = BabyBearExt4;
        type Pcs = BasefoldDefault<E>;

        let mut cs = ConstraintSystem::<E>::new(|| "fp_op_test");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);
        let mut layout =
            FpOpLayout::<E, P>::build_layer_logic(&mut cb, ()).expect("build_layer_logic failed");
        let (out_evals, mut chip) = layout.finalize(&mut cb);
        let layer =
            Layer::from_circuit_builder(&cb, "fp_op".to_string(), layout.n_challenges, out_evals);
        chip.add_layer(layer);
        let gkr_circuit = chip.gkr_circuit();

        let instances = (0..count)
            .map(|i| {
                let x = random_mod::<P>();
                let y = random_mod::<P>();
                let op = if i % 2 == 0 {
                    FieldOperation::Add
                } else {
                    FieldOperation::Mul
                };
                FpOpInstance::<P>::new(x, y, op)
            })
            .collect_vec();

        let mut phase1 = RowMajorMatrix::new(
            instances.len(),
            layout.n_committed,
            InstancePaddingStrategy::Default,
        );
        let mut structural = RowMajorMatrix::new(
            instances.len(),
            layout.n_structural_witin,
            InstancePaddingStrategy::Default,
        );
        let mut lk_multiplicity = LkMultiplicity::default();
        layout.phase1_witness_group(
            FpOpTrace::<P> {
                instances: instances.clone(),
            },
            [&mut phase1, &mut structural],
            &mut lk_multiplicity,
        );

        let output_index = layout.layer_exprs.wits.output.result.0[0].id as usize;
        for (row, inst) in phase1
            .iter_rows()
            .take(instances.len())
            .zip(instances.iter())
        {
            let out_bytes = row[output_index..][..P::NB_LIMBS]
                .iter()
                .map(|c| c.to_canonical_u64() as u8)
                .collect_vec();
            let got = BigUint::from_bytes_le(&out_bytes);

            let modulus = P::modulus();
            let expected = match inst.op {
                FieldOperation::Add => (&inst.x + &inst.y) % &modulus,
                FieldOperation::Mul => (&inst.x * &inst.y) % &modulus,
                FieldOperation::Sub | FieldOperation::Div => unreachable!(),
            };
            assert_eq!(got, expected);
        }

        phase1.padding_by_strategy();
        structural.padding_by_strategy();

        let num_instances = instances.len();
        let log2_num_instance = ceil_log2(num_instances);
        let num_threads = optimal_sumcheck_threads(log2_num_instance);
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
            );

        let out_evals = {
            let mut point = Vec::with_capacity(log2_num_instance);
            point.extend(prover_transcript.sample_vec(log2_num_instance).to_vec());

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
                    point: point[point.len() - log2_num_instance..point.len()].to_vec(),
                    eval: E::ZERO,
                }]
            } else {
                out_evals
            }
        };

        let selector_ctxs = vec![SelectorContext::new(0, num_instances, log2_num_instance); 1];
        let GKRProverOutput { gkr_proof, .. } = gkr_circuit
            .prove::<CpuBackend<E, Pcs>, CpuProver<_>>(
                num_threads,
                log2_num_instance,
                gkr_witness,
                &out_evals,
                &[],
                &challenges,
                &mut prover_transcript,
                &selector_ctxs,
            )
            .expect("fp_op prove failed");

        let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");
        let challenges = [
            verifier_transcript.read_challenge().elements,
            verifier_transcript.read_challenge().elements,
        ];
        let mut point = Vec::with_capacity(log2_num_instance);
        point.extend(verifier_transcript.sample_vec(log2_num_instance).to_vec());

        gkr_circuit
            .verify(
                log2_num_instance,
                gkr_proof,
                &out_evals,
                &[],
                &[],
                &challenges,
                &mut verifier_transcript,
                &selector_ctxs,
            )
            .expect("fp_op verify failed");
    }

    #[test]
    fn test_bls12381_fp_ops() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| test_fp_ops_helper::<Bls12381BaseField>(8))
            .expect("spawn fp_ops test thread failed")
            .join()
            .expect("fp_ops test thread panicked");
    }

    #[test]
    fn test_bls12381_fp_ops_nonpow2() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| test_fp_ops_helper::<Bls12381BaseField>(7))
            .expect("spawn fp_ops test thread failed")
            .join()
            .expect("fp_ops test thread panicked");
    }

    #[test]
    fn test_bn254_fp_ops() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| test_fp_ops_helper::<Bn254BaseField>(8))
            .expect("spawn fp_ops test thread failed")
            .join()
            .expect("fp_ops test thread panicked");
    }

    #[test]
    fn test_bn254_fp_ops_nonpow2() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| test_fp_ops_helper::<Bn254BaseField>(7))
            .expect("spawn fp_ops test thread failed")
            .join()
            .expect("fp_ops test thread panicked");
    }
}
