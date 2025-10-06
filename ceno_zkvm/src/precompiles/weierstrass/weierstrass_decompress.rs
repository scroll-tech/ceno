// The crate weierstrass add circuit is modified from succinctlabs/sp1 under MIT license

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

use std::{array, fmt::Debug, marker::PhantomData, sync::Arc};

use ceno_emul::{ByteAddr, MemOp, StepRecord};
use core::{borrow::BorrowMut, mem::size_of};
use derive::AlignedBorrow;
use ff_ext::{ExtensionField, SmallField};
use generic_array::{GenericArray, sequence::GenericSequence, typenum::Unsigned};
use gkr_iop::{
    OutEvalGroups, ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    cpu::{CpuBackend, CpuProver},
    error::{BackendError, CircuitBuilderError},
    gkr::{GKRCircuit, GKRProof, GKRProverOutput, layer::Layer, mock::MockProver},
    selector::SelectorType,
};
use itertools::{Itertools, izip};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression, StructuralWitInType, ToExpr, WitIn,
    macros::{entered_span, exit_span},
    util::{ceil_log2, max_usable_threads},
};
use num::{BigUint, One, Zero};
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    prelude::{IntoParallelRefIterator, ParallelSlice},
};
use sp1_curves::{
    CurveType, EllipticCurve,
    params::{FieldParameters, Limbs, NumLimbs, NumWords},
    polynomial::Polynomial,
    weierstrass::{
        WeierstrassParameters,
        secp256k1::{secp256k1_decompress, secp256k1_sqrt},
        secp256r1::{secp256r1_decompress, secp256r1_sqrt},
    },
};
use sumcheck::util::optimal_sumcheck_threads;
use transcript::{BasicTranscript, Transcript};
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    chip_handler::MemoryExpr,
    error::ZKVMError,
    gadgets::{
        FieldOperation, field_inner_product::FieldInnerProductCols, field_op::FieldOpCols,
        field_sqrt::FieldSqrtCols, range::FieldLtCols,
    },
    instructions::riscv::{
        constants::UINT_LIMBS,
        insn_base::{StateInOut, WriteMEM},
    },
    precompiles::{
        SelectorTypeLayout, utils::merge_u8_slice_to_u16_limbs_pairs_and_extend,
        weierstrass::EllipticCurveDecompressInstance,
    },
    scheme::utils::gkr_witness,
    structs::PointAndEval,
    witness::LkMultiplicity,
};

#[derive(Clone, Debug, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassDecompressWitCols<WitT, P: FieldParameters + NumLimbs + NumWords> {
    pub sign_bit: WitT,
    pub(crate) x_limbs: Limbs<WitT, P::Limbs>,
    pub(crate) y_limbs: Limbs<WitT, P::Limbs>,
    pub(crate) old_output32: GenericArray<[WitT; UINT_LIMBS], P::WordsFieldElement>,
    pub(crate) range_x: FieldLtCols<WitT, P>,
    pub(crate) neg_y_range_check: FieldLtCols<WitT, P>,
    pub(crate) x_2: FieldOpCols<WitT, P>,
    pub(crate) x_3: FieldOpCols<WitT, P>,
    pub(crate) ax_plus_b: FieldInnerProductCols<WitT, P>,
    pub(crate) x_3_plus_b_plus_ax: FieldOpCols<WitT, P>,
    pub(crate) pos_y: FieldSqrtCols<WitT, P>,
    pub(crate) neg_y: FieldOpCols<WitT, P>,
}

/// Weierstrass decompress is implemented by a single layer.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct WeierstrassDecompressLayer<WitT, P: FieldParameters + NumWords> {
    pub wits: WeierstrassDecompressWitCols<WitT, P>,
}

#[derive(Clone, Debug)]
pub struct WeierstrassDecompressLayout<E: ExtensionField, EC: EllipticCurve> {
    pub layer_exprs: WeierstrassDecompressLayer<WitIn, EC::BaseField>,
    pub selector_type_layout: SelectorTypeLayout<E>,
    pub input32_exprs: GenericArray<MemoryExpr<E>, <EC::BaseField as NumWords>::WordsFieldElement>,
    pub old_output32_exprs:
        GenericArray<MemoryExpr<E>, <EC::BaseField as NumWords>::WordsFieldElement>,
    pub output32_exprs: GenericArray<MemoryExpr<E>, <EC::BaseField as NumWords>::WordsFieldElement>,
    pub n_fixed: usize,
    pub n_committed: usize,
    pub n_structural_witin: usize,
    pub n_challenges: usize,
}

impl<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters>
    WeierstrassDecompressLayout<E, EC>
{
    fn new(cb: &mut CircuitBuilder<E>) -> Self {
        match EC::CURVE_TYPE {
            CurveType::Secp256k1 | CurveType::Secp256r1 => {}
            _ => panic!("Unsupported curve"),
        }

        let wits = WeierstrassDecompressWitCols {
            sign_bit: cb.create_bit(|| "sign_bit").unwrap(),
            x_limbs: Limbs(GenericArray::generate(|_| cb.create_witin(|| "x"))),
            y_limbs: Limbs(GenericArray::generate(|_| cb.create_witin(|| "y"))),
            old_output32: GenericArray::generate(|i| {
                array::from_fn(|j| cb.create_witin(|| format!("old_output32_{}_{}", i, j)))
            }),
            range_x: FieldLtCols::create(cb, || "range_x"),
            neg_y_range_check: FieldLtCols::create(cb, || "neg_y_range_check"),
            x_2: FieldOpCols::create(cb, || "x_2"),
            x_3: FieldOpCols::create(cb, || "x_3"),
            ax_plus_b: FieldInnerProductCols::create(cb, || "ax_plus_b"),
            x_3_plus_b_plus_ax: FieldOpCols::create(cb, || "x_3_plus_b_plus_ax"),
            pos_y: FieldSqrtCols::create(cb, || "y"),
            neg_y: FieldOpCols::create(cb, || "neg_y"),
        };

        let eq = cb.create_structural_witin(
            || "weierstrass_decompress_eq",
            StructuralWitInType::EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: 0,
                descending: false,
            },
        );
        let selector_type_layout = SelectorTypeLayout {
            sel_mem_read: SelectorType::Prefix(E::BaseField::ZERO, eq.expr()),
            sel_mem_write: SelectorType::Prefix(E::BaseField::ZERO, eq.expr()),
            sel_lookup: SelectorType::Prefix(E::BaseField::ZERO, eq.expr()),
            sel_zero: SelectorType::Prefix(E::BaseField::ZERO, eq.expr()),
        };

        let input32_exprs: GenericArray<
            MemoryExpr<E>,
            <EC::BaseField as NumWords>::WordsFieldElement,
        > = GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));
        let old_output32_exprs: GenericArray<
            MemoryExpr<E>,
            <EC::BaseField as NumWords>::WordsFieldElement,
        > = GenericArray::generate(|_| {
            array::from_fn(|i| cb.create_witin(|| format!("old_output32_{}", i)).expr())
        });
        let output32_exprs: GenericArray<
            MemoryExpr<E>,
            <EC::BaseField as NumWords>::WordsFieldElement,
        > = GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));

        Self {
            layer_exprs: WeierstrassDecompressLayer { wits },
            selector_type_layout,
            input32_exprs,
            old_output32_exprs,
            output32_exprs,
            n_fixed: 0,
            n_committed: 0,
            n_structural_witin: 0,
            n_challenges: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate(
        record: &mut LkMultiplicity,
        cols: &mut WeierstrassDecompressWitCols<E::BaseField, EC::BaseField>,
        instance: &EllipticCurveDecompressInstance<EC::BaseField>,
    ) {
        cols.sign_bit = E::BaseField::from_bool(instance.sign_bit);
        cols.old_output32 = GenericArray::generate(|i| {
            [
                E::BaseField::from_canonical_u32(instance.old_y_words[i] & ((1 << 16) - 1)),
                E::BaseField::from_canonical_u32((instance.old_y_words[i] >> 16) & ((1 << 16) - 1)),
            ]
        });

        let x = &instance.x;
        // Y = sqrt(x^3 + ax + b)
        cols.x_limbs = EC::BaseField::to_limbs_field(x);
        cols.range_x.populate(record, x, &EC::BaseField::modulus());
        let x_2 = cols.x_2.populate(record, x, x, FieldOperation::Mul);
        let x_3 = cols.x_3.populate(record, &x_2, x, FieldOperation::Mul);
        let b = EC::b_int();
        let a = EC::a_int();
        let param_vec = vec![a, b];
        let x_vec = vec![x.clone(), BigUint::one()];
        let ax_plus_b = cols.ax_plus_b.populate(record, &param_vec, &x_vec);
        let x_3_plus_b_plus_ax =
            cols.x_3_plus_b_plus_ax
                .populate(record, &x_3, &ax_plus_b, FieldOperation::Add);

        let sqrt_fn = match EC::CURVE_TYPE {
            CurveType::Secp256k1 => secp256k1_sqrt,
            CurveType::Secp256r1 => secp256r1_sqrt,
            _ => panic!("Unsupported curve"),
        };

        let y = cols.pos_y.populate(record, &x_3_plus_b_plus_ax, sqrt_fn);

        let zero = BigUint::zero();
        let neg_y = cols.neg_y.populate(record, &zero, &y, FieldOperation::Sub);
        cols.neg_y_range_check
            .populate(record, &neg_y, &EC::BaseField::modulus());

        if cols.pos_y.lsb.to_canonical_u64() == instance.sign_bit as u64 {
            cols.y_limbs = EC::BaseField::to_limbs_field(&y);
        } else {
            cols.y_limbs = EC::BaseField::to_limbs_field(&neg_y);
        }
    }
}

impl<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters> ProtocolBuilder<E>
    for WeierstrassDecompressLayout<E, EC>
{
    type Params = ();

    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        _params: Self::Params,
    ) -> Result<Self, CircuitBuilderError> {
        let mut layout = match EC::CURVE_TYPE {
            CurveType::Secp256k1 | CurveType::Secp256r1 => WeierstrassDecompressLayout::new(cb),
            _ => panic!("Unsupported curve"),
        };
        let wits = &layout.layer_exprs.wits;

        let x_limbs = &wits.x_limbs;
        let max_num_limbs = EC::BaseField::to_limbs_expr(&EC::BaseField::modulus());

        wits.range_x.eval(cb, x_limbs, &max_num_limbs)?;
        wits.x_2.eval(cb, x_limbs, x_limbs, FieldOperation::Mul)?;
        wits.x_3
            .eval(cb, &wits.x_2.result, x_limbs, FieldOperation::Mul)?;

        let b_const = EC::BaseField::to_limbs_expr::<E>(&EC::b_int());
        let a_const = EC::BaseField::to_limbs_expr::<E>(&EC::a_int());
        let params = [a_const, b_const];
        let p_x: Polynomial<Expression<E>> = x_limbs.clone().into();
        let p_one: Polynomial<Expression<E>> =
            EC::BaseField::to_limbs_expr::<E>(&BigUint::one()).into();
        wits.ax_plus_b.eval(cb, &params, &[p_x, p_one])?;
        wits.x_3_plus_b_plus_ax.eval(
            cb,
            &wits.x_3.result,
            &wits.ax_plus_b.result,
            FieldOperation::Add,
        )?;

        wits.neg_y.eval(
            cb,
            &[Expression::<E>::ZERO].iter(),
            &wits.pos_y.multiplication.result,
            FieldOperation::Sub,
        )?;
        // Range check the `neg_y.result` to be canonical.
        let modulus_limbs = EC::BaseField::to_limbs_expr(&EC::BaseField::modulus());
        wits.neg_y_range_check
            .eval(cb, &wits.neg_y.result, &modulus_limbs)?;

        // Constrain that `y` is a square root. Note that `y.multiplication.result` is constrained
        // to be canonical here. Since `y_limbs` is constrained to be either
        // `y.multiplication.result` or `neg_y.result`, `y_limbs` will be canonical.
        wits.pos_y
            .eval(cb, &wits.x_3_plus_b_plus_ax.result, wits.pos_y.lsb)?;

        // When the sign rule is LeastSignificantBit, the sign_bit should match the parity
        // of the result. The parity of the square root result is given by the wits.y.lsb
        // value. Thus, if the sign_bit matches the wits.y.lsb value, then the result
        // should be the square root of the y value. Otherwise, the result should be the
        // negative square root of the y value.
        let cond: Expression<E> = 1
            - (wits.pos_y.lsb.expr() + wits.sign_bit.expr()
                - 2 * wits.pos_y.lsb.expr() * wits.sign_bit.expr());
        for (y, sqrt_y, neg_sqrt_y) in izip!(
            wits.y_limbs.0.iter(),
            wits.pos_y.multiplication.result.0.iter(),
            wits.neg_y.result.0.iter()
        ) {
            cb.condition_require_equal(
                || "when lsb == sign_bit, y_limbs = sqrt(y), otherwise y_limbs = -sqrt(y)",
                cond.expr(),
                y.expr(),
                sqrt_y.expr(),
                neg_sqrt_y.expr(),
            )?;
        }

        let mut output32 =
            Vec::with_capacity(<EC::BaseField as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(
            &wits.y_limbs.0.iter().rev().cloned().collect::<Vec<_>>(),
            &mut output32,
        );
        let output32 = output32.try_into().unwrap();

        let mut input32 = Vec::with_capacity(<EC::BaseField as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(
            &wits.x_limbs.0.iter().rev().cloned().collect::<Vec<_>>(),
            &mut input32,
        );
        let input32 = input32.try_into().unwrap();

        // set input32/output32 expr
        layout.input32_exprs = input32;
        layout.output32_exprs = output32;
        layout.old_output32_exprs =
            GenericArray::generate(|i| array::from_fn(|j| wits.old_output32[i][j].expr()));

        Ok(layout)
    }

    fn finalize(&mut self, cb: &mut CircuitBuilder<E>) -> (OutEvalGroups, Chip<E>) {
        self.n_fixed = cb.cs.num_fixed;
        self.n_committed = cb.cs.num_witin as usize;
        self.n_structural_witin = cb.cs.num_structural_witin as usize;
        self.n_challenges = 0;

        // register selector to legacy constrain system
        cb.cs.r_selector = Some(self.selector_type_layout.sel_mem_read.clone());
        cb.cs.w_selector = Some(self.selector_type_layout.sel_mem_write.clone());
        cb.cs.lk_selector = Some(self.selector_type_layout.sel_lookup.clone());
        cb.cs.zero_selector = Some(self.selector_type_layout.sel_zero.clone());

        let w_len = cb.cs.w_expressions.len();
        let r_len = cb.cs.r_expressions.len();
        let lk_len = cb.cs.lk_expressions.len();
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();
        (
            [
                // r_record
                (0..r_len).collect_vec(),
                // w_record
                (r_len..r_len + w_len).collect_vec(),
                // lk_record
                (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
                // zero_record
                (0..zero_len).collect_vec(),
            ],
            Chip::new_from_cb(cb, self.n_challenges),
        )
    }

    fn n_committed(&self) -> usize {
        todo!()
    }

    fn n_fixed(&self) -> usize {
        todo!()
    }

    fn n_challenges(&self) -> usize {
        todo!()
    }

    fn n_evaluations(&self) -> usize {
        todo!()
    }

    fn n_layers(&self) -> usize {
        todo!()
    }
}

#[derive(Clone, Default)]
pub struct WeierstrassDecompressTrace<P: NumLimbs + NumWords> {
    pub instances: Vec<EllipticCurveDecompressInstance<P>>,
    pub _phantom: PhantomData<P>,
}

impl<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters> ProtocolWitnessGenerator<E>
    for WeierstrassDecompressLayout<E, EC>
{
    type Trace = WeierstrassDecompressTrace<EC::BaseField>;

    fn fixed_witness_group(&self) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::new(0, 0, InstancePaddingStrategy::Default)
    }

    fn phase1_witness_group(
        &self,
        phase1: Self::Trace,
        wits: [&mut RowMajorMatrix<E::BaseField>; 2],
        lk_multiplicity: &mut LkMultiplicity,
    ) {
        let num_instances = wits[0].num_instances();
        let nthreads = max_usable_threads();
        let num_instance_per_batch = num_instances.div_ceil(nthreads).max(1);

        // The number of columns used for weierstrass decompress subcircuit.
        let num_main_wit_cols = size_of::<WeierstrassDecompressWitCols<u8, EC::BaseField>>();

        let [wits, structural_wits] = wits;
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
                        let cols: &mut WeierstrassDecompressWitCols<E::BaseField, EC::BaseField> =
                            row[self.layer_exprs.wits.sign_bit.id as usize..][..num_main_wit_cols] // TODO: Find a better way to write it.
                                .borrow_mut();
                        Self::populate(&mut lk_multiplicity, cols, phase1_instance);

                        for x in eqs.iter_mut() {
                            *x = E::BaseField::ONE;
                        }
                    });
            });
    }
}

/// this is for testing purpose
pub struct TestWeierstrassDecompressLayout<E: ExtensionField, EC: EllipticCurve> {
    layout: WeierstrassDecompressLayout<E, EC>,
    mem_rw: Vec<WriteMEM>,
    vm_state: StateInOut<E>,
    _field_ptr: WitIn,
}

#[allow(clippy::type_complexity)]
pub fn setup_gkr_circuit<E: ExtensionField, EC: EllipticCurve + WeierstrassParameters>() -> Result<
    (
        TestWeierstrassDecompressLayout<E, EC>,
        GKRCircuit<E>,
        u16,
        u16,
    ),
    ZKVMError,
> {
    let mut cs = ConstraintSystem::new(|| "weierstrass_decompress");
    let mut cb = CircuitBuilder::<E>::new(&mut cs);

    // constrain vmstate
    let vm_state = StateInOut::construct_circuit(&mut cb, false)?;

    let field_ptr = cb.create_witin(|| "field_ptr");

    let mut layout = WeierstrassDecompressLayout::build_layer_logic(&mut cb, ())?;

    let num_limbs = <EC::BaseField as NumLimbs>::Limbs::U32;
    let mut mem_rw = layout
        .input32_exprs
        .iter()
        .enumerate()
        .map(|(i, val)| {
            WriteMEM::construct_circuit(
                &mut cb,
                // mem address := field_ptr + i * 4
                field_ptr.expr() + (i as u32) * 4,
                val.clone(),
                val.clone(),
                vm_state.ts,
            )
        })
        .collect::<Result<Vec<WriteMEM>, _>>()?;

    mem_rw.extend(
        izip!(
            layout.old_output32_exprs.iter(),
            layout.output32_exprs.iter()
        )
        .enumerate()
        .map(|(i, (val_before, val_after))| {
            WriteMEM::construct_circuit(
                &mut cb,
                // mem address := field_ptr + i * 4 + num_limbs
                field_ptr.expr() + (i as u32) * 4 + num_limbs,
                val_before.clone(),
                val_after.clone(),
                vm_state.ts,
            )
        })
        .collect::<Result<Vec<WriteMEM>, _>>()?,
    );

    let (out_evals, mut chip) = layout.finalize(&mut cb);

    let layer = Layer::from_circuit_builder(
        &cb,
        "weierstrass_decompress".to_string(),
        layout.n_challenges,
        out_evals,
    );
    chip.add_layer(layer);

    Ok((
        TestWeierstrassDecompressLayout {
            layout,
            vm_state,
            _field_ptr: field_ptr,
            mem_rw,
        },
        chip.gkr_circuit(),
        cs.num_witin,
        cs.num_structural_witin,
    ))
}

#[tracing::instrument(
    skip_all,
    name = "run_weierstrass_decompress",
    level = "trace",
    fields(profiling_1)
)]
pub fn run_weierstrass_decompress<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
    EC: EllipticCurve + WeierstrassParameters,
>(
    (layout, gkr_circuit, num_witin, num_structual_witin): (
        TestWeierstrassDecompressLayout<E, EC>,
        GKRCircuit<E>,
        u16,
        u16,
    ),
    instances: Vec<EllipticCurveDecompressInstance<EC::BaseField>>,
    test_outputs: bool,
    verify: bool,
) -> Result<GKRProof<E>, BackendError> {
    let num_instances = instances.len();
    let log2_num_instance = ceil_log2(num_instances);
    let num_threads = optimal_sumcheck_threads(log2_num_instance);

    let span = entered_span!("phase1_witness", profiling_2 = true);
    let nthreads = max_usable_threads();
    let num_instance_per_batch = num_instances.div_ceil(nthreads).max(1);

    let mut lk_multiplicity = LkMultiplicity::default();
    let mut phase1_witness = RowMajorMatrix::<E::BaseField>::new(
        instances.len(),
        num_witin as usize,
        InstancePaddingStrategy::Default,
    );
    let mut structural_witness = RowMajorMatrix::<E::BaseField>::new(
        instances.len(),
        num_structual_witin as usize,
        InstancePaddingStrategy::Default,
    );
    let raw_witin_iter = phase1_witness.par_batch_iter_mut(num_instance_per_batch);
    raw_witin_iter
        .zip_eq(instances.par_chunks(num_instance_per_batch))
        .for_each(|(instances, steps)| {
            let mut lk_multiplicity = lk_multiplicity.clone();
            instances
                .chunks_mut(num_witin as usize)
                .zip_eq(steps)
                .for_each(|(instance, _step)| {
                    layout
                        .vm_state
                        .assign_instance(
                            instance,
                            &StepRecord::new_ecall_any(10, ByteAddr::from(0)),
                        )
                        .expect("assign vm_state error");
                    layout.mem_rw.iter().for_each(|mem_config| {
                        mem_config
                            .assign_op(
                                instance,
                                &mut lk_multiplicity,
                                10,
                                &MemOp {
                                    previous_cycle: 0,
                                    addr: ByteAddr::from(0).waddr(),
                                    value: Default::default(),
                                },
                            )
                            .expect("assign error");
                    });
                })
        });

    layout.layout.phase1_witness_group(
        WeierstrassDecompressTrace {
            instances: instances.clone(),
            _phantom: PhantomData,
        },
        [&mut phase1_witness, &mut structural_witness],
        &mut lk_multiplicity,
    );

    exit_span!(span);

    if test_outputs {
        let decompress_fn = match EC::CURVE_TYPE {
            CurveType::Secp256k1 => secp256k1_decompress::<EC>,
            CurveType::Secp256r1 => secp256r1_decompress::<EC>,
            _ => panic!("Unsupported curve"),
        };

        let expected_outputs = instances
            .iter()
            .map(
                |EllipticCurveDecompressInstance {
                     x,
                     sign_bit,
                     old_y_words: _,
                 }| {
                    let computed_point = decompress_fn(&x.to_bytes_be(), *sign_bit as u32);
                    EC::BaseField::to_limbs(&computed_point.y)
                },
            )
            .collect_vec();

        let y_output_index_start = layout.layout.layer_exprs.wits.y_limbs.0[0].id as usize;
        let got_outputs = phase1_witness
            .iter_rows()
            .take(num_instances)
            .map(|cols| {
                cols[y_output_index_start..][..<EC::BaseField as NumLimbs>::Limbs::USIZE]
                    .iter()
                    .map(|y| y.to_canonical_u64() as u8)
                    .collect_vec()
            })
            .collect_vec();
        assert_eq!(expected_outputs, got_outputs);
    }

    let mut prover_transcript = BasicTranscript::<E>::new(b"protocol");
    let challenges = [
        prover_transcript.read_challenge().elements,
        prover_transcript.read_challenge().elements,
    ];

    let span = entered_span!("gkr_witness", profiling_2 = true);
    let phase1_witness_group = phase1_witness
        .to_mles()
        .into_iter()
        .map(Arc::new)
        .collect_vec();
    let structural_witness = structural_witness
        .to_mles()
        .into_iter()
        .map(Arc::new)
        .collect_vec();
    let fixed = layout
        .layout
        .fixed_witness_group()
        .to_mles()
        .into_iter()
        .map(Arc::new)
        .collect_vec();
    #[allow(clippy::type_complexity)]
    let (gkr_witness, gkr_output) = gkr_witness::<E, PCS, CpuBackend<E, PCS>, CpuProver<_>>(
        &gkr_circuit,
        &phase1_witness_group,
        &structural_witness,
        &fixed,
        &[],
        &challenges,
    );
    exit_span!(span);

    let span = entered_span!("out_eval", profiling_2 = true);
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
    exit_span!(span);

    if cfg!(debug_assertions) {
        // mock prover
        let out_wits = gkr_output.0.0.clone();
        MockProver::check(&gkr_circuit, &gkr_witness, out_wits, challenges.to_vec())
            .expect("mock prover failed");
    }

    let span = entered_span!("create_proof", profiling_2 = true);
    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove::<CpuBackend<E, PCS>, CpuProver<_>>(
            num_threads,
            log2_num_instance,
            gkr_witness,
            &out_evals,
            &[],
            &challenges,
            &mut prover_transcript,
            num_instances,
        )
        .expect("Failed to prove phase");
    exit_span!(span);

    if verify {
        {
            let mut verifier_transcript = BasicTranscript::<E>::new(b"protocol");
            let challenges = [
                verifier_transcript.read_challenge().elements,
                verifier_transcript.read_challenge().elements,
            ];

            // This is to make prover/verifier match
            let mut point = Vec::with_capacity(log2_num_instance);
            point.extend(verifier_transcript.sample_vec(log2_num_instance).to_vec());

            gkr_circuit
                .verify(
                    log2_num_instance,
                    gkr_proof.clone(),
                    &out_evals,
                    &[],
                    &challenges,
                    &mut verifier_transcript,
                    num_instances,
                )
                .expect("GKR verify failed");

            // Omit the PCS opening phase.
        }
    }
    Ok(gkr_proof)
}

#[cfg(test)]
mod tests {
    use crate::precompiles::weierstrass::test_utils::random_decompress_instances;

    use super::*;
    use ff_ext::BabyBearExt4;
    use mpcs::BasefoldDefault;
    use sp1_curves::weierstrass::{
        SwCurve, WeierstrassParameters, secp256k1::Secp256k1, secp256r1::Secp256r1,
    };

    fn test_weierstrass_decompress_helper<WP: WeierstrassParameters>() {
        type E = BabyBearExt4;
        type Pcs = BasefoldDefault<E>;

        let instances = random_decompress_instances::<SwCurve<WP>>(8);

        let _ = run_weierstrass_decompress::<E, Pcs, SwCurve<WP>>(
            setup_gkr_circuit::<E, SwCurve<WP>>().expect("setup gkr circuit failed"),
            instances,
            true,
            true,
        );
    }

    #[test]
    fn test_weierstrass_decompress_secp256k1() {
        test_weierstrass_decompress_helper::<Secp256k1>();
    }

    #[test]
    fn test_weierstrass_decompress_secp256r1() {
        test_weierstrass_decompress_helper::<Secp256r1>();
    }

    fn test_weierstrass_decompress_nonpow2_helper<WP: WeierstrassParameters>() {
        type E = BabyBearExt4;
        type Pcs = BasefoldDefault<E>;

        let instances = random_decompress_instances::<SwCurve<WP>>(5);
        let _ = run_weierstrass_decompress::<E, Pcs, SwCurve<WP>>(
            setup_gkr_circuit::<E, SwCurve<WP>>().expect("setup gkr circuit failed"),
            instances,
            true,
            true,
        );
    }

    #[test]
    fn test_weierstrass_decompress_nonpow2_secp256k1() {
        test_weierstrass_decompress_nonpow2_helper::<Secp256k1>();
    }

    #[test]
    fn test_weierstrass_decompress_nonpow2_secp256r1() {
        test_weierstrass_decompress_nonpow2_helper::<Secp256r1>();
    }
}
