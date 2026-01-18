// The add4 gadget is modified from succinctlabs/sp1 under MIT license

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
use ff_ext::{ExtensionField, SmallField};
use gkr_iop::error::CircuitBuilderError;
use multilinear_extensions::{Expression, ToExpr, WitIn};

use crate::{circuit_builder::CircuitBuilder, gadgets::word::Word, witness::LkMultiplicity};

/// A set of columns needed to compute the add of four words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add4Operation<T> {
    /// The result of `a + b + c + d`.
    pub value: Word<T>,

    /// Indicates if the carry for the `i`th digit is 0.
    pub is_carry_0: Word<T>,

    /// Indicates if the carry for the `i`th digit is 1.
    pub is_carry_1: Word<T>,

    /// Indicates if the carry for the `i`th digit is 2.
    pub is_carry_2: Word<T>,

    /// Indicates if the carry for the `i`th digit is 3. The carry when adding 4 words is at most
    /// 3.
    pub is_carry_3: Word<T>,

    /// The carry for the `i`th digit.
    pub carry: Word<T>,
}

impl Add4Operation<WitIn> {
    pub fn create<E: ExtensionField, NR, N>(cb: &mut CircuitBuilder<E>, name_fn: N) -> Self
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name: String = name_fn().into();
        Self {
            value: Word::create(cb, || format!("{}_value", name)),
            is_carry_0: Word::create(cb, || format!("{}_is_carry_0", name)),
            is_carry_1: Word::create(cb, || format!("{}_is_carry_1", name)),
            is_carry_2: Word::create(cb, || format!("{}_is_carry_2", name)),
            is_carry_3: Word::create(cb, || format!("{}_is_carry_3", name)),
            carry: Word::create(cb, || format!("{}_carry", name)),
        }
    }
}

impl<F: SmallField> Add4Operation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        &mut self,
        record: &mut LkMultiplicity,
        a_u32: u32,
        b_u32: u32,
        c_u32: u32,
        d_u32: u32,
    ) -> u32 {
        let expected = a_u32
            .wrapping_add(b_u32)
            .wrapping_add(c_u32)
            .wrapping_add(d_u32);
        self.value = Word::from(expected);
        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();
        let c = c_u32.to_le_bytes();
        let d = d_u32.to_le_bytes();

        let base = 256;
        let mut carry = [0u8, 0u8, 0u8, 0u8];
        for i in 0..WORD_SIZE {
            let mut res = (a[i] as u32) + (b[i] as u32) + (c[i] as u32) + (d[i] as u32);
            if i > 0 {
                res += carry[i - 1] as u32;
            }
            carry[i] = (res / base) as u8;
            self.is_carry_0[i] = F::from_bool(carry[i] == 0);
            self.is_carry_1[i] = F::from_bool(carry[i] == 1);
            self.is_carry_2[i] = F::from_bool(carry[i] == 2);
            self.is_carry_3[i] = F::from_bool(carry[i] == 3);
            self.carry[i] = F::from_canonical_u8(carry[i]);
            debug_assert!(carry[i] <= 3);
            debug_assert_eq!(self.value[i], F::from_canonical_u32(res % base));
        }

        // Range check.
        {
            record.assert_bytes(&a);
            record.assert_bytes(&b);
            record.assert_bytes(&c);
            record.assert_bytes(&d);
            record.assert_bytes(&expected.to_le_bytes());
        }
        expected
    }
}

impl<Expr: Clone> Add4Operation<Expr> {
    #[allow(clippy::too_many_arguments)]
    pub fn eval<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        a: Word<impl ToExpr<E, Output = Expression<E>> + Clone>,
        b: Word<impl ToExpr<E, Output = Expression<E>> + Clone>,
        c: Word<impl ToExpr<E, Output = Expression<E>> + Clone>,
        d: Word<impl ToExpr<E, Output = Expression<E>> + Clone>,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        // Range check each byte.
        {
            builder.assert_bytes(|| "add4 operation a.0", &a.0)?;
            builder.assert_bytes(|| "add4 operation b.0", &b.0)?;
            builder.assert_bytes(|| "add4 operation c.0", &c.0)?;
            builder.assert_bytes(|| "add4 operation d.0", &d.0)?;
            builder.assert_bytes(|| "add4 operation self.value.0", &self.value.0)?;
        }

        // Each value in is_carry_{0,1,2,3} is 0 or 1, and exactly one of them is 1 per digit.
        {
            for i in 0..WORD_SIZE {
                builder.assert_bit(|| "add4 is_carry_0", self.is_carry_0[i].expr())?;
                builder.assert_bit(|| "add4 is_carry_1", self.is_carry_1[i].expr())?;
                builder.assert_bit(|| "add4 is_carry_2", self.is_carry_2[i].expr())?;
                builder.assert_bit(|| "add4 is_carry_3", self.is_carry_3[i].expr())?;
                builder.require_equal(
                    || "add4 is_carry sum to 1",
                    self.is_carry_0[i].expr()
                        + self.is_carry_1[i].expr()
                        + self.is_carry_2[i].expr()
                        + self.is_carry_3[i].expr(),
                    1.into(),
                )?;
            }
        }

        // Calculates carry from is_carry_{0,1,2,3}.
        {
            for i in 0..WORD_SIZE {
                builder.require_equal(
                    || "add4 carry from is_carry",
                    self.carry[i].expr(),
                    self.is_carry_1[i].expr() * 1
                        + self.is_carry_2[i].expr() * 2
                        + self.is_carry_3[i].expr() * 3,
                )?;
            }
        }

        // Compare the sum and summands by looking at carry.
        {
            // For each limb, assert that difference between the carried result and the non-carried
            // result is the product of carry and base.
            for i in 0..WORD_SIZE {
                let mut overflow =
                    a[i].expr() + b[i].expr() + c[i].expr() + d[i].expr() - self.value[i].expr();
                if i > 0 {
                    overflow = overflow.expr() + self.carry[i - 1].expr();
                }
                builder.require_equal(
                    || "add4 carry overflow",
                    self.carry[i].expr() * 256,
                    overflow.clone(),
                )?;
            }
        }
        Ok(())
    }
}
