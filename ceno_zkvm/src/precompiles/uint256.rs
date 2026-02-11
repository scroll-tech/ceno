// The crate uint256 circuit is modified from succinctlabs/sp1 under MIT license

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

use crate::{
    chip_handler::MemoryExpr,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::{FieldOperation, IsZeroOperation, field_op::FieldOpCols, range::FieldLtCols},
    instructions::riscv::insn_base::{StateInOut, WriteMEM},
    precompiles::{SelectorTypeLayout, utils::merge_u8_slice_to_u16_limbs_pairs_and_extend},
    scheme::utils::gkr_witness,
    structs::PointAndEval,
    witness::LkMultiplicity,
};
use ceno_emul::{ByteAddr, MemOp, StepRecord};
use derive::AlignedBorrow;
use ff_ext::{ExtensionField, SmallField};
use generic_array::{GenericArray, sequence::GenericSequence};
use gkr_iop::{
    OutEvalGroups, ProtocolBuilder, ProtocolWitnessGenerator,
    chip::Chip,
    cpu::{CpuBackend, CpuProver},
    error::{BackendError, CircuitBuilderError},
    gkr::{GKRCircuit, GKRProof, GKRProverOutput, layer::Layer, mock::MockProver},
    selector::{SelectorContext, SelectorType},
};
use itertools::{Itertools, izip};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression, ToExpr, WitIn,
    util::{ceil_log2, max_usable_threads},
};
use num::{BigUint, One, Zero};
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};
use sp1_curves::{
    params::{FieldParameters, Limbs, NumLimbs, NumWords},
    polynomial::Polynomial,
    uint256::U256Field,
    utils::biguint_to_limbs,
};
use std::{array, borrow::BorrowMut, marker::PhantomData, sync::Arc};
use sumcheck::{
    macros::{entered_span, exit_span},
    util::optimal_sumcheck_threads,
};
use transcript::{BasicTranscript, Transcript};
use typenum::Unsigned;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

/// A set of columns for the Uint256Mul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Uint256MulWitCols<T> {
    pub x_limbs: Limbs<T, <U256Field as NumLimbs>::Limbs>,
    pub y_limbs: Limbs<T, <U256Field as NumLimbs>::Limbs>,
    pub modulus_limbs: Limbs<T, <U256Field as NumLimbs>::Limbs>,

    /// Columns for checking if modulus is zero. If it's zero, then use 2^256 as the effective
    /// modulus.
    pub modulus_is_zero: IsZeroOperation<T>,

    /// Column that is equal to is_real * (1 - modulus_is_zero.result).
    pub modulus_is_not_zero: T,

    // Output values. We compute (x * y) % modulus.
    pub output: FieldOpCols<T, U256Field>,

    pub output_range_check: FieldLtCols<T, U256Field>,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Uint256MulLayer<WitT> {
    pub wits: Uint256MulWitCols<WitT>,
}

#[derive(Clone, Debug)]
pub struct Uint256MulLayout<E: ExtensionField> {
    pub layer_exprs: Uint256MulLayer<WitIn>,
    pub selector_type_layout: SelectorTypeLayout<E>,
    /// Read x, y, and modulus from memory.
    pub input32_exprs: [GenericArray<MemoryExpr<E>, <U256Field as NumWords>::WordsFieldElement>; 3],
    pub output32_exprs: GenericArray<MemoryExpr<E>, <U256Field as NumWords>::WordsFieldElement>,
    pub n_fixed: usize,
    pub n_committed: usize,
    pub n_structural_witin: usize,
    pub n_challenges: usize,
}

impl<E: ExtensionField> Uint256MulLayout<E> {
    fn new(cb: &mut CircuitBuilder<E>) -> Self {
        let wits = Uint256MulWitCols {
            x_limbs: Limbs(GenericArray::generate(|_| cb.create_witin(|| "uint256 x"))),
            y_limbs: Limbs(GenericArray::generate(|_| cb.create_witin(|| "uint256 y"))),
            modulus_limbs: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| "uint256 modulus")
            })),
            modulus_is_zero: IsZeroOperation::create(cb),
            modulus_is_not_zero: cb.create_witin(|| "uint256_mul_modulus_is_not_zero"),
            output: FieldOpCols::create(cb, || "uint256_mul_output"),
            output_range_check: FieldLtCols::create(cb, || "uint256_mul_output_range_check"),
        };

        let eq = cb.create_placeholder_structural_witin(|| "uint256_mul_structural_witin");
        let sel = SelectorType::Prefix(eq.expr());
        let selector_type_layout = SelectorTypeLayout {
            sel_first: None,
            sel_last: None,
            sel_all: sel.clone(),
        };

        // Default expression, will be updated in build_layer_logic
        let input32_exprs: [GenericArray<MemoryExpr<E>, <U256Field as NumWords>::WordsFieldElement>;
            3] = array::from_fn(|_| {
            GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)))
        });
        // Default expression, will be updated in build_layer_logic
        let output32_exprs: GenericArray<
            MemoryExpr<E>,
            <U256Field as NumWords>::WordsFieldElement,
        > = GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));

        Self {
            layer_exprs: Uint256MulLayer { wits },
            selector_type_layout,
            input32_exprs,
            output32_exprs,
            n_fixed: 0,
            n_committed: 0,
            n_challenges: 0,
            n_structural_witin: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_row(
        blu_events: &mut LkMultiplicity,
        cols: &mut Uint256MulWitCols<E::BaseField>,
        instance: &Uint256MulInstance,
    ) {
        let x = &instance.x;
        cols.x_limbs = U256Field::to_limbs_field(x);
        let y = &instance.y;
        cols.y_limbs = U256Field::to_limbs_field(y);
        let modulus = &instance.modulus;
        cols.modulus_limbs = U256Field::to_limbs_field(modulus);

        let modulus_bytes = modulus.to_bytes_le();
        let modulus_byte_sum = modulus_bytes.iter().map(|b| *b as u32).sum::<u32>();
        cols.modulus_is_zero.populate(modulus_byte_sum);

        // Populate the output column.
        let effective_modulus = if modulus.is_zero() {
            BigUint::one() << 256
        } else {
            modulus.clone()
        };
        let result = cols.output.populate_with_modulus(
            blu_events,
            x,
            y,
            &effective_modulus,
            // &modulus,
            FieldOperation::Mul,
        );

        cols.modulus_is_not_zero = E::BaseField::ONE - cols.modulus_is_zero.result;
        if cols.modulus_is_not_zero == E::BaseField::ONE {
            cols.output_range_check
                .populate(blu_events, &result, &effective_modulus);
        }
    }
}

impl<E: ExtensionField> ProtocolBuilder<E> for Uint256MulLayout<E> {
    type Params = ();

    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        _params: Self::Params,
    ) -> Result<Self, CircuitBuilderError> {
        let mut layout = Self::new(cb);
        let wits = &layout.layer_exprs.wits;

        // We are computing (x * y) % modulus. The value of x is stored in the "prev_value" of
        // the x_memory, since we write to it later.
        let x_limbs = &wits.x_limbs;
        let y_limbs = &wits.y_limbs;
        let modulus_limbs = &wits.modulus_limbs;

        // If the modulus is zero, then we don't perform the modulus operation.
        // Evaluate the modulus_is_zero operation by summing each byte of the modulus. The sum will
        // not overflow because we are summing 32 bytes.
        let modulus_byte_sum = modulus_limbs
            .0
            .iter()
            .fold(Expression::ZERO, |acc, &limb| acc + limb.expr());
        wits.modulus_is_zero.eval(cb, modulus_byte_sum)?;

        // If the modulus is zero, we'll actually use 2^256 as the modulus, so nothing happens.
        // Otherwise, we use the modulus passed in.
        let modulus_is_zero = wits.modulus_is_zero.result;
        let mut coeff_2_256: Vec<Expression<E>> = Vec::new();
        coeff_2_256.resize(32, Expression::ZERO);
        coeff_2_256.push(Expression::ONE);
        let modulus_polynomial: Polynomial<Expression<E>> = (*modulus_limbs).into();
        let p_modulus: Polynomial<Expression<E>> = modulus_polynomial
            * (1 - modulus_is_zero.expr())
            + Polynomial::from_coefficients(&coeff_2_256) * modulus_is_zero.expr();

        // Evaluate the uint256 multiplication
        wits.output
            .eval_with_modulus(cb, x_limbs, y_limbs, &p_modulus, FieldOperation::Mul)?;

        // Verify the range of the output if the moduls is not zero.  Also, check the value of
        // modulus_is_not_zero.
        wits.output_range_check.condition_eval(
            cb,
            &wits.output.result,
            modulus_limbs,
            wits.modulus_is_not_zero.expr(),
        )?;
        cb.require_equal(
            || "uint256_mul: modulus_is_not_zero",
            wits.modulus_is_not_zero.expr(),
            Expression::ONE - modulus_is_zero.expr(),
        )?;

        // Constraint output32 from wits.output by converting 8-bit limbs to 2x16-bit felts
        let mut output32 = Vec::with_capacity(<U256Field as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.output.result.0, &mut output32);
        let output32 = output32.try_into().unwrap();

        // Constraint input32 from wits.x_limbs, wits.y_limbs, wits.modulus_limbs
        let mut x_input32 = Vec::with_capacity(<U256Field as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.x_limbs.0, &mut x_input32);
        let x_input32 = x_input32.try_into().unwrap();

        let mut y_input32 = Vec::with_capacity(<U256Field as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.y_limbs.0, &mut y_input32);
        let y_input32 = y_input32.try_into().unwrap();

        let mut modulus_input32 =
            Vec::with_capacity(<U256Field as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(
            &wits.modulus_limbs.0,
            &mut modulus_input32,
        );
        let modulus_input32 = modulus_input32.try_into().unwrap();

        // set input32/output32 expr
        layout.input32_exprs = [x_input32, y_input32, modulus_input32];
        layout.output32_exprs = output32;

        Ok(layout)
    }

    fn finalize(&mut self, cb: &mut CircuitBuilder<E>) -> (OutEvalGroups, Chip<E>) {
        self.n_fixed = cb.cs.num_fixed;
        self.n_committed = cb.cs.num_witin as usize;
        self.n_structural_witin = cb.cs.num_structural_witin as usize;
        self.n_challenges = 0;

        // register selector to legacy constrain system
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

pub struct Uint256MulTrace {
    pub instances: Vec<Uint256MulInstance>,
}

impl<E: ExtensionField> ProtocolWitnessGenerator<E> for Uint256MulLayout<E> {
    type Trace = Uint256MulTrace;

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
        let num_wit_cols = size_of::<Uint256MulWitCols<u8>>();
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
                        let cols: &mut Uint256MulWitCols<E::BaseField> = row
                            [self.layer_exprs.wits.x_limbs.0[0].id as usize..][..num_wit_cols] // TODO: Find a better way to write it.
                            .borrow_mut();
                        Self::populate_row(&mut lk_multiplicity, cols, phase1_instance);
                        for x in eqs.iter_mut() {
                            *x = E::BaseField::ONE;
                        }
                    });
            });
    }
}

pub trait Uint256InvSpec {
    type P: FieldParameters + NumWords;
    fn syscall() -> u32;
    fn name() -> String;
    fn modulus() -> BigUint;
}

/// A set of columns for the Uint256Inv operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Uint256InvWitCols<T> {
    // x = UInt256Field::ONE
    // y := input
    // y in little endian format
    pub y_limbs: Limbs<T, <U256Field as NumLimbs>::Limbs>,
    // output values. x / y = output
    pub output: FieldOpCols<T, U256Field>,
    pub output_range_check: FieldLtCols<T, U256Field>,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Uint256InvLayer<WitT> {
    pub wits: Uint256InvWitCols<WitT>,
}

#[derive(Clone, Debug)]
pub struct Uint256InvLayout<E: ExtensionField, Spec: Uint256InvSpec> {
    pub layer_exprs: Uint256InvLayer<WitIn>,
    pub selector_type_layout: SelectorTypeLayout<E>,
    // y from memory
    pub input32_exprs: GenericArray<MemoryExpr<E>, <Spec::P as NumWords>::WordsFieldElement>,
    pub modulus_limbs: Limbs<Expression<E>, <Spec::P as NumLimbs>::Limbs>,
    pub output32_exprs: GenericArray<MemoryExpr<E>, <Spec::P as NumWords>::WordsFieldElement>,
    pub n_fixed: usize,
    pub n_committed: usize,
    pub n_structural_witin: usize,
    pub n_challenges: usize,
    phantom: PhantomData<Spec::P>,
}

impl<E: ExtensionField, Spec: Uint256InvSpec> Uint256InvLayout<E, Spec> {
    fn new(cb: &mut CircuitBuilder<E>) -> Self {
        let wits = Uint256InvWitCols {
            y_limbs: Limbs(GenericArray::generate(|_| cb.create_witin(|| "uint256 y"))),
            output: FieldOpCols::create(cb, || "uint256_inv_output"),
            output_range_check: FieldLtCols::create(cb, || "uint256_inv_output_range_check"),
        };
        let modulus_limbs = Spec::P::to_limbs_expr(&Spec::modulus());

        let eq = cb.create_placeholder_structural_witin(|| "uint256_mul_structural_witin");
        let sel = SelectorType::Prefix(eq.expr());
        let selector_type_layout = SelectorTypeLayout {
            sel_first: None,
            sel_last: None,
            sel_all: sel.clone(),
        };

        // Default expression, will be updated in build_layer_logic
        let input32_exprs = GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));
        // Default expression, will be updated in build_layer_logic
        let output32_exprs = GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));

        Self {
            layer_exprs: Uint256InvLayer { wits },
            selector_type_layout,
            input32_exprs,
            modulus_limbs,
            output32_exprs,
            n_fixed: 0,
            n_committed: 0,
            n_challenges: 0,
            n_structural_witin: 0,
            phantom: Default::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_row(
        blu_events: &mut LkMultiplicity,
        cols: &mut Uint256InvWitCols<E::BaseField>,
        y: &BigUint,
    ) {
        cols.y_limbs = U256Field::to_limbs_field(y);
        let y_inv = cols.output.populate_with_modulus(
            blu_events,
            &BigUint::one(),
            y,
            &Spec::modulus(),
            FieldOperation::Div,
        );
        cols.output_range_check
            .populate(blu_events, &y_inv, &Spec::modulus());
    }
}

impl<E: ExtensionField, Spec: Uint256InvSpec> ProtocolBuilder<E> for Uint256InvLayout<E, Spec> {
    type Params = ();

    fn build_layer_logic(
        cb: &mut CircuitBuilder<E>,
        _params: Self::Params,
    ) -> Result<Self, CircuitBuilderError> {
        let mut layout = Self::new(cb);
        let wits = &layout.layer_exprs.wits;

        // compute y_inv = (1 / y) % modulus
        // NOTE: y_limbs and modulus_limbs in little endian format
        let y_limbs = &wits.y_limbs;
        let modulus_limbs = &layout.modulus_limbs;

        // If the modulus is zero, we'll actually use 2^256 as the modulus, so nothing happens.
        // Otherwise, we use the modulus passed in.
        let modulus_polynomial: Polynomial<Expression<E>> = modulus_limbs.clone().into();
        let p_modulus: Polynomial<Expression<E>> = modulus_polynomial;

        // constant one
        let one_limbs: Limbs<Expression<E>, _> = Spec::P::to_limbs_expr(&BigUint::one());

        // Evaluate the uint256 multiplication
        wits.output
            .eval_with_modulus(cb, &one_limbs, y_limbs, &p_modulus, FieldOperation::Div)?;

        // Verify the range of the output if the moduls is not zero.  Also, check the value of
        // modulus_is_not_zero.
        wits.output_range_check
            .eval(cb, &wits.output.result, modulus_limbs)?;

        // Constraint output32 from wits.output by converting 8-bit limbs to 2x16-bit felts
        let mut output32 = Vec::with_capacity(<Spec::P as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(
            // rev to convert to big-endian
            &wits.output.result.0.into_iter().rev().collect_vec(),
            &mut output32,
        );
        let output32 = output32.try_into().unwrap();

        // Constraint input32 from wits.y_limbs
        let mut y_input32 = Vec::with_capacity(<Spec::P as NumWords>::WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(
            // rev to convert to big-endian
            &wits.y_limbs.0.into_iter().rev().collect_vec(),
            &mut y_input32,
        );
        let y_input32 = y_input32.try_into().unwrap();

        // set input32/output32 expr
        layout.input32_exprs = y_input32;
        layout.output32_exprs = output32;

        Ok(layout)
    }

    fn finalize(&mut self, cb: &mut CircuitBuilder<E>) -> (OutEvalGroups, Chip<E>) {
        self.n_fixed = cb.cs.num_fixed;
        self.n_committed = cb.cs.num_witin as usize;
        self.n_structural_witin = cb.cs.num_structural_witin as usize;
        self.n_challenges = 0;

        // register selector to legacy constrain system
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

pub struct Uint256InvTrace {
    pub instances: Vec<BigUint>,
}

impl<E: ExtensionField, Spec: Uint256InvSpec> ProtocolWitnessGenerator<E>
    for Uint256InvLayout<E, Spec>
{
    type Trace = Uint256InvTrace;

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
        let num_wit_cols = size_of::<Uint256InvWitCols<u8>>();
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
                        let cols: &mut Uint256InvWitCols<E::BaseField> = row
                            [self.layer_exprs.wits.y_limbs.0[0].id as usize..][..num_wit_cols] // TODO: Find a better way to write it.
                            .borrow_mut();
                        Self::populate_row(&mut lk_multiplicity, cols, phase1_instance);
                        for x in eqs.iter_mut() {
                            *x = E::BaseField::ONE;
                        }
                    });
            });
    }
}

/// Uint256 Mul Event.
///
/// This event is emitted when a uint256 mul operation is performed.
#[derive(Default, Debug, Clone)]
pub struct Uint256MulInstance {
    /// x
    pub x: BigUint,
    /// y
    pub y: BigUint,
    /// modulus
    pub modulus: BigUint,
}

/// this is for testing purpose
pub struct TestUint256MulLayout<E: ExtensionField> {
    layout: Uint256MulLayout<E>,
    mem_rw: Vec<WriteMEM>,
    vm_state: StateInOut<E>,
    _number_ptr: WitIn,
}

#[allow(clippy::type_complexity)]
pub fn setup_uint256mul_gkr_circuit<E: ExtensionField>()
-> Result<(TestUint256MulLayout<E>, GKRCircuit<E>, u16, u16), ZKVMError> {
    let mut cs = ConstraintSystem::new(|| "uint256_mul");
    let mut cb = CircuitBuilder::<E>::new(&mut cs);
    // constrain vmstate
    let vm_state = StateInOut::construct_circuit(&mut cb, false)?;

    let number_ptr = cb.create_witin(|| "state_ptr_0");

    let mut layout = Uint256MulLayout::build_layer_logic(&mut cb, ())?;

    // Write the result to the same address of the first input point.
    let limb_len = layout.output32_exprs.len();
    let mut mem_rw = izip!(&layout.input32_exprs[0], &layout.output32_exprs)
        .enumerate()
        .map(|(i, (val_before, val_after))| {
            WriteMEM::construct_circuit(
                &mut cb,
                // mem address := state_ptr_0 + i
                number_ptr.expr() + E::BaseField::from_canonical_u32(i as u32).expr(),
                val_before.clone(),
                val_after.clone(),
                vm_state.ts,
            )
        })
        .collect::<Result<Vec<WriteMEM>, _>>()?;

    // Keep the second input point unchanged in memory.
    layout.input32_exprs[1..]
        .iter()
        .enumerate()
        .map(|(j, input32_exprs)| {
            let circuit = input32_exprs
                .iter()
                .enumerate()
                .map(|(i, val_before)| {
                    WriteMEM::construct_circuit(
                        &mut cb,
                        // mem address := state_ptr_1 + i
                        number_ptr.expr()
                            + E::BaseField::from_canonical_u32((limb_len * j + i) as u32).expr(),
                        val_before.clone(),
                        val_before.clone(),
                        vm_state.ts,
                    )
                })
                .collect::<Result<Vec<WriteMEM>, _>>();
            circuit.map(|c| mem_rw.extend(c))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (out_evals, mut chip) = layout.finalize(&mut cb);

    let layer = Layer::from_circuit_builder(
        &cb,
        "weierstrass_add".to_string(),
        layout.n_challenges,
        out_evals,
    );
    chip.add_layer(layer);

    Ok((
        TestUint256MulLayout {
            layout,
            vm_state,
            _number_ptr: number_ptr,
            mem_rw,
        },
        chip.gkr_circuit(),
        cs.num_witin,
        cs.num_structural_witin,
    ))
}

#[tracing::instrument(
    skip_all,
    name = "run_uint256_mul",
    level = "trace",
    fields(profiling_1)
)]
pub fn run_uint256_mul<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static>(
    (layout, gkr_circuit, num_witin, num_structural_witin): (
        TestUint256MulLayout<E>,
        GKRCircuit<E>,
        u16,
        u16,
    ),
    instances: Vec<Uint256MulInstance>,
    verify: bool,
    test_outputs: bool,
) -> Result<GKRProof<E>, BackendError> {
    let mut shard_ctx = ShardContext::default();
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
        num_structural_witin as usize,
        InstancePaddingStrategy::Default,
    );
    let raw_witin_iter = phase1_witness.par_batch_iter_mut(num_instance_per_batch);
    let shard_ctx_vec = shard_ctx.get_forked();
    raw_witin_iter
        .zip_eq(instances.par_chunks(num_instance_per_batch))
        .zip(shard_ctx_vec)
        .for_each(|((instances, steps), mut shard_ctx)| {
            let mut lk_multiplicity = lk_multiplicity.clone();
            instances
                .chunks_mut(num_witin as usize)
                .zip_eq(steps)
                .for_each(|(instance, _step)| {
                    layout
                        .vm_state
                        .assign_instance(
                            instance,
                            &shard_ctx,
                            &StepRecord::new_ecall_any(10, ByteAddr::from(0)),
                        )
                        .expect("assign vm_state error");
                    layout.mem_rw.iter().for_each(|mem_config| {
                        mem_config
                            .assign_op(
                                instance,
                                &mut shard_ctx,
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
        Uint256MulTrace {
            instances: instances.clone(),
        },
        [&mut phase1_witness, &mut structural_witness],
        &mut lk_multiplicity,
    );
    exit_span!(span);

    if test_outputs {
        // Test got output == expected output.
        let expected_outputs = instances
            .iter()
            .map(|Uint256MulInstance { x, y, modulus }| {
                let c = if modulus.is_zero() {
                    (x * y) % (BigUint::one() << 256)
                } else {
                    (x * y) % modulus
                };
                biguint_to_limbs::<{ <U256Field as NumLimbs>::Limbs::USIZE }>(&c).to_vec()
            })
            .collect_vec();

        let output_index_start = layout.layout.layer_exprs.wits.output.result.0[0].id as usize;
        let got_outputs = phase1_witness
            .iter_rows()
            .take(num_instances)
            .map(|cols| {
                cols[output_index_start..][..<U256Field as NumLimbs>::Limbs::USIZE]
                    .iter()
                    .map(|c| c.to_canonical_u64() as u8)
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
    let selector_ctxs = vec![SelectorContext::new(0, num_instances, log2_num_instance); 1];
    let GKRProverOutput { gkr_proof, .. } = gkr_circuit
        .prove::<CpuBackend<E, PCS>, CpuProver<_>>(
            num_threads,
            log2_num_instance,
            gkr_witness,
            &out_evals,
            &[],
            &challenges,
            &mut prover_transcript,
            &selector_ctxs,
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
                    out_evals,
                    &[],
                    &[],
                    &challenges,
                    &mut verifier_transcript,
                    &selector_ctxs,
                )
                .expect("GKR verify failed");

            // Omit the PCS opening phase.
        }
    }
    Ok(gkr_proof)
}

#[cfg(test)]
mod tests {
    use ff_ext::BabyBearExt4;
    use mpcs::BasefoldDefault;
    use num::bigint::RandBigInt;
    use rand::{SeedableRng, rngs::StdRng};
    use sp1_curves::{params::FieldParameters, utils::biguint_from_limbs};

    use super::*;

    #[test]
    fn test_uint256_mul() {
        type E = BabyBearExt4;
        type Pcs = BasefoldDefault<E>;

        let mut rng = StdRng::seed_from_u64(42);

        let instances = (0..8)
            .map(|i| {
                let mut x = rng.gen_biguint(<U256Field as NumWords>::WordsFieldElement::U64 * 32);
                let mut y = rng.gen_biguint(<U256Field as NumWords>::WordsFieldElement::U64 * 32);
                let modulus = if i == 0 {
                    BigUint::zero()
                } else {
                    let modulus =
                        rng.gen_biguint(<U256Field as NumWords>::WordsFieldElement::U64 * 32);
                    x = &x % &modulus;
                    y = &y % &modulus;
                    modulus
                };
                Uint256MulInstance { x, y, modulus }
            })
            .collect_vec();

        let _ = run_uint256_mul::<E, Pcs>(
            setup_uint256mul_gkr_circuit::<E>().expect("setup gkr circuit failed"),
            instances,
            true,
            true,
        )
        .inspect_err(|err| {
            eprintln!("{:?}", err);
        })
        .expect("uint256_mul failed");
    }

    #[test]
    fn test_uint256_modulus() {
        assert_eq!(biguint_from_limbs(U256Field::MODULUS), U256Field::modulus());
    }
}
