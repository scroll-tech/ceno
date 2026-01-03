// The word struct is modified from succinctlabs/sp1 under MIT license

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

use std::ops::{Index, IndexMut};

use std::array::IntoIter;

use arrayref::array_ref;
use ceno_emul::WORD_SIZE;
use derive::AlignedBorrow;
use ff_ext::{ExtensionField, SmallField};
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use serde::{Deserialize, Serialize};

use crate::circuit_builder::CircuitBuilder;

/// An array of four bytes to represent a 32-bit value.
///
/// We use the generic type `T` to represent the different representations of a byte, ranging from
/// a `u8` to a `Expression<E>` or `AB::Expr`.
#[derive(
    AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
#[repr(C)]
pub struct Word<T>(pub [T; WORD_SIZE]);

impl Word<WitIn> {
    /// Creates a word in the circuit.
    pub fn create<E: ExtensionField, NR, N>(cb: &mut CircuitBuilder<E>, name_fn: N) -> Self
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name: String = name_fn().into();
        Word(std::array::from_fn(|i| {
            cb.create_witin(|| format!("{}[{}]", name, i))
        }))
    }
}

impl<F: SmallField> Word<F> {
    /// Converts a word to a u32.
    pub fn to_u32(&self) -> u32 {
        u32::from_le_bytes(self.0.map(|x| x.to_string().parse::<u8>().unwrap()))
    }
}

impl<Expr: Clone> Word<Expr> {
    /// Applies `f` to each element of the word.
    pub fn map<F, S>(self, f: F) -> Word<S>
    where
        F: FnMut(Expr) -> S,
    {
        Word(self.0.map(f))
    }

    /// Extends a variable to a word.
    pub fn extend<E: ExtensionField>(var: Expr) -> Word<Expression<E>>
    where
        Expr: ToExpr<E, Output = Expression<E>>,
    {
        Word([
            Expression::<E>::ZERO + var.expr(),
            Expression::<E>::ZERO,
            Expression::<E>::ZERO,
            Expression::<E>::ZERO,
        ])
    }

    pub fn zero<E: ExtensionField>() -> Word<Expression<E>> {
        Word([
            Expression::<E>::ZERO,
            Expression::<E>::ZERO,
            Expression::<E>::ZERO,
            Expression::<E>::ZERO,
        ])
    }

    /// Reduces a word to a single variable.
    pub fn reduce<E>(&self) -> Expression<E>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        let base = [1, 1 << 8, 1 << 16, 1 << 24];
        self.0
            .iter()
            .enumerate()
            .map(|(i, x)| x.expr() * base[i])
            .sum()
    }
}

impl<T> Index<usize> for Word<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for Word<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F: SmallField> From<u32> for Word<F> {
    fn from(value: u32) -> Self {
        Word(value.to_le_bytes().map(F::from_canonical_u8))
    }
}

impl<T> IntoIterator for Word<T> {
    type Item = T;
    type IntoIter = IntoIter<T, WORD_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Clone> FromIterator<T> for Word<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let elements = iter.into_iter().take(WORD_SIZE).collect_vec();

        Word(array_ref![elements, 0, WORD_SIZE].clone())
    }
}
