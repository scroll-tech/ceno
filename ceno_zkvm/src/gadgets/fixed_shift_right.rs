// The fixed_shift_right gadget is modified from succinctlabs/sp1 under MIT license

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

use ceno_emul::WORD_SIZE;
use derive::AlignedBorrow;
use ff_ext::SmallField;
use gkr_iop::error::CircuitBuilderError;
use multilinear_extensions::{Expression, ToExpr, WitIn};

use crate::{
    circuit_builder::CircuitBuilder,
    gadgets::{util::shr_carry, word::Word},
    witness::LkMultiplicity,
};

/// A set of columns needed to compute `>>` of a word with a fixed offset R.
///
/// Note that we decompose shifts into a byte shift and a bit shift.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FixedShiftRightOperation<T> {
    /// The output value.
    pub value: Word<T>,

    /// The shift output of `shrcarry` on each byte of a word.
    pub shift: Word<T>,

    /// The carry ouytput of `shrcarry` on each byte of a word.
    pub carry: Word<T>,
}

impl FixedShiftRightOperation<WitIn> {
    pub fn create<E: ff_ext::ExtensionField, NR, N>(cb: &mut CircuitBuilder<E>, name_fn: N) -> Self
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name: String = name_fn().into();
        Self {
            value: Word::create(cb, || format!("{}_value", name)),
            shift: Word::create(cb, || format!("{}_shift", name)),
            carry: Word::create(cb, || format!("{}_carry", name)),
        }
    }
}

impl<F: SmallField> FixedShiftRightOperation<F> {
    pub fn populate(&mut self, record: &mut LkMultiplicity, input: u32, rotation: usize) -> u32 {
        let input_bytes = input.to_le_bytes().map(F::from_canonical_u8);
        let expected = input >> rotation;

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = F::from_canonical_u32(Self::carry_multiplier(rotation));

        // Perform the byte shift.
        let mut word = [F::ZERO; WORD_SIZE];
        for i in 0..WORD_SIZE {
            if i + nb_bytes_to_shift < WORD_SIZE {
                word[i] = input_bytes[(i + nb_bytes_to_shift) % WORD_SIZE];
            }
        }
        let input_bytes_rotated = Word(word);

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = F::ZERO;
        let mut last_carry = F::ZERO;
        for i in (0..WORD_SIZE).rev() {
            let b = input_bytes_rotated[i].to_string().parse::<u8>().unwrap();
            let c = nb_bits_to_shift as u8;
            let (shift, carry) = shr_carry(b, c);

            record.lookup_shr_byte(shift as u64, carry as u64, nb_bits_to_shift as u64);

            self.shift[i] = F::from_canonical_u8(shift);
            self.carry[i] = F::from_canonical_u8(carry);

            if i == WORD_SIZE - 1 {
                first_shift = self.shift[i];
            } else {
                self.value[i] = self.shift[i] + last_carry * carry_multiplier;
            }

            last_carry = self.carry[i];
        }

        // For the first byte, we don't move over the carry as this is a shift, not a rotate.
        self.value[WORD_SIZE - 1] = first_shift;

        // Assert the answer is correct.
        assert_eq!(self.value.to_u32(), expected);

        expected
    }
}

impl<Expr: Clone> FixedShiftRightOperation<Expr> {
    pub fn eval<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        input: Word<impl ToExpr<E, Output = Expression<E>>>,
        rotation: usize,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ff_ext::ExtensionField,
        Expr: multilinear_extensions::ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = Self::carry_multiplier(rotation);

        // Perform the byte shift.
        let input_bytes_rotated = Word(std::array::from_fn(|i| {
            if i + nb_bytes_to_shift < WORD_SIZE {
                input[(i + nb_bytes_to_shift) % WORD_SIZE].expr()
            } else {
                Expression::<E>::ZERO
            }
        }));

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = Expression::<E>::ZERO;
        let mut last_carry = Expression::<E>::ZERO;
        for i in (0..WORD_SIZE).rev() {
            builder.lookup_shr_byte(
                input_bytes_rotated[i].expr(),
                nb_bits_to_shift,
                self.shift[i].expr(),
                self.carry[i].expr(),
            )?;

            if i == WORD_SIZE - 1 {
                first_shift = self.shift[i].expr();
            } else {
                builder.require_equal(
                    || "fixed shift right value calculation",
                    self.value[i].expr(),
                    self.shift[i].expr() + last_carry * carry_multiplier,
                )?;
            }

            last_carry = self.carry[i].expr();
        }

        // For the first byte, we don't move over the carry as this is a shift, not a rotate.
        builder.require_equal(
            || "fixed shift right first value calculation",
            self.value[WORD_SIZE - 1].expr(),
            first_shift,
        )
    }

    pub const fn nb_bytes_to_shift(rotation: usize) -> usize {
        rotation / 8
    }

    pub const fn nb_bits_to_shift(rotation: usize) -> usize {
        rotation % 8
    }

    pub const fn carry_multiplier(rotation: usize) -> u32 {
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        1 << (8 - nb_bits_to_shift)
    }
}
