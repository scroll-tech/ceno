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

use std::array;

use derive::AlignedBorrow;
use ff_ext::ExtensionField;
use generic_array::{GenericArray, sequence::GenericSequence};
use gkr_iop::{
    OutEvalGroups, ProtocolBuilder, chip::Chip, error::CircuitBuilderError, selector::SelectorType,
};
use itertools::Itertools;
use multilinear_extensions::{Expression, StructuralWitInType, ToExpr, WitIn};
use num::{BigUint, One, Zero};
use p3::field::FieldAlgebra;
use sp1_curves::{
    params::{Limbs, NumWords},
    polynomial::Polynomial,
    uint256::U256Field,
};
use typenum::Unsigned;

use crate::{
    chip_handler::MemoryExpr,
    circuit_builder::CircuitBuilder,
    gadgets::{FieldOperation, IsZeroOperation, field_op::FieldOpCols, range::FieldLtCols},
    precompiles::{SelectorTypeLayout, utils::merge_u8_slice_to_u16_limbs_pairs_and_extend},
    witness::LkMultiplicity,
};

type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

/// A set of columns for the Uint256Mul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Uint256MulWitCols<T> {
    pub x_limbs: Limbs<T, WordsFieldElement>,
    pub y_limbs: Limbs<T, WordsFieldElement>,
    pub modulus_limbs: Limbs<T, WordsFieldElement>,

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
    pub input32_exprs: [GenericArray<MemoryExpr<E>, WordsFieldElement>; 3],
    pub output32_exprs: GenericArray<MemoryExpr<E>, WordsFieldElement>,
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

        let eq = cb.create_structural_witin(
            || "uint256_mul_structural_witin",
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

        // Default expression, will be updated in build_layer_logic
        let input32_exprs: [GenericArray<MemoryExpr<E>, WordsFieldElement>; 3] =
            array::from_fn(|_| {
                GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)))
            });
        // Default expression, will be updated in build_layer_logic
        let output32_exprs: GenericArray<MemoryExpr<E>, WordsFieldElement> =
            GenericArray::generate(|_| array::from_fn(|_| Expression::WitIn(0)));

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
    fn populate(
        blu_events: &mut LkMultiplicity,
        cols: &mut Uint256MulWitCols<E::BaseField>,
        x: &BigUint,
        y: &BigUint,
        modulus: &BigUint,
    ) {
        let modulus_bytes = modulus.to_bytes_le();
        let modulus_byte_sum = modulus_bytes.iter().map(|b| *b as u32).sum::<u32>();
        IsZeroOperation::populate(&mut cols.modulus_is_zero, modulus_byte_sum);

        // Populate the output column.
        let effective_modulus = if modulus.is_zero() {
            BigUint::one() << 256
        } else {
            modulus.clone()
        };
        let result = cols.output.populate_with_modulus(
            blu_events,
            &x,
            &y,
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

        // Assert that the correct result is being written to x_memory.
        for (limb, mem) in wits.output.result.0.iter().zip(x_limbs.0.iter()) {
            cb.require_equal(|| "output == x_limbs", limb.expr(), mem.expr())?;
        }

        // Constraint output32 from wits.output by converting 8-bit limbs to 2x16-bit felts
        let mut output32 = Vec::with_capacity(WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.output.result.0, &mut output32);
        let output32 = output32.try_into().unwrap();

        // Constraint input32 from wits.x_limbs, wits.y_limbs, wits.modulus_limbs
        let mut x_input32 = Vec::with_capacity(WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.x_limbs.0, &mut x_input32);
        let x_input32 = x_input32.try_into().unwrap();

        let mut y_input32 = Vec::with_capacity(WordsFieldElement::USIZE);
        merge_u8_slice_to_u16_limbs_pairs_and_extend::<E>(&wits.y_limbs.0, &mut y_input32);
        let y_input32 = y_input32.try_into().unwrap();

        let mut modulus_input32 = Vec::with_capacity(WordsFieldElement::USIZE);
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
