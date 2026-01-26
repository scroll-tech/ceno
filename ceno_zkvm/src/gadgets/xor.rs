// The xor gadget is modified from succinctlabs/sp1 under MIT license

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
use itertools::izip;
use multilinear_extensions::{Expression, ToExpr, WitIn};

use crate::{circuit_builder::CircuitBuilder, gadgets::word::Word, witness::LkMultiplicity};

/// A set of columns needed to compute the xor of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct XorOperation<T> {
    /// The result of `x ^ y`.
    pub value: Word<T>,
}

impl XorOperation<WitIn> {
    /// Creates an xor operation in the circuit.
    pub fn create<E: ExtensionField, NR, N>(cb: &mut CircuitBuilder<E>, name_fn: N) -> Self
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name: String = name_fn().into();
        Self {
            value: Word::create(cb, || format!("{}_value", name)),
        }
    }
}

impl<F: SmallField> XorOperation<F> {
    pub fn populate(&mut self, record: &mut LkMultiplicity, x: u32, y: u32) -> u32 {
        let expected = x ^ y;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        for i in 0..WORD_SIZE {
            let xor = x_bytes[i] ^ y_bytes[i];
            self.value[i] = F::from_canonical_u8(xor);

            record.lookup_xor_byte(x_bytes[i] as u64, y_bytes[i] as u64);
        }
        expected
    }
}

impl<Expr: Clone> XorOperation<Expr> {
    #[allow(unused_variables)]
    pub fn eval<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        a: Word<impl ToExpr<E, Output = Expression<E>>>,
        b: Word<impl ToExpr<E, Output = Expression<E>>>,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        izip!(a.0, b.0)
            .enumerate()
            .map(|(i, (a_byte, b_byte))| {
                builder.lookup_xor_byte(a_byte.expr(), b_byte.expr(), self.value[i].expr())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
}
