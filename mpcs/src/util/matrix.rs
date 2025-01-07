use std::{
    marker::PhantomData,
    ops::Index,
    slice::{Chunks, ChunksMut},
    sync::Arc,
};

use ff::Field;
use multilinear_extensions::mle::{DenseMultilinearExtension, IntoMLE};
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};

use super::next_pow2_instance_padding;

#[derive(Clone)]
pub enum InstancePaddingStrategy {
    // Pads with default values of underlying type
    // Usually zero, but check carefully
    Default,
    // Pads by repeating last row
    RepeatLast,
    // Custom strategy consists of a closure
    // `pad(i, j) = padding value for cell at row i, column j`
    // pad should be able to cross thread boundaries
    Custom(Arc<dyn Fn(u64, u64) -> u64 + Send + Sync>),
}

/// TODO replace with plonky3 RowMajorMatrix https://github.com/Plonky3/Plonky3/blob/784b7dd1fa87c1202e63350cc8182d7c5327a7af/matrix/src/dense.rs#L26
#[derive(Clone)]
pub struct RowMajorMatrix<T: Sized + Sync + Clone + Send + Copy, V = Vec<T>> {
    // represent 2D in 1D linear memory and avoid double indirection by Vec<Vec<T>> to improve performance
    values: V,
    num_col: usize,
    padding_strategy: InstancePaddingStrategy,
    _phantom: PhantomData<T>,
}

impl<T: Sized + Sync + Clone + Send + Copy + Default + From<u64>> RowMajorMatrix<T> {
    pub fn new(num_rows: usize, num_col: usize, padding_strategy: InstancePaddingStrategy) -> Self {
        RowMajorMatrix {
            values: (0..num_rows * num_col)
                .into_par_iter()
                .map(|_| T::default())
                .collect(),
            num_col,
            padding_strategy,
            _phantom: PhantomData,
        }
    }

    pub fn num_cols(&self) -> usize {
        self.num_col
    }

    pub fn num_padding_instances(&self) -> usize {
        next_pow2_instance_padding(self.num_instances()) - self.num_instances()
    }

    pub fn num_instances(&self) -> usize {
        self.values.len() / self.num_col
    }

    pub fn iter_rows(&self) -> Chunks<T> {
        self.values.chunks(self.num_col)
    }

    pub fn iter_mut(&mut self) -> ChunksMut<T> {
        self.values.chunks_mut(self.num_col)
    }

    pub fn par_iter_mut(&mut self) -> rayon::slice::ChunksMut<T> {
        self.values.par_chunks_mut(self.num_col)
    }

    pub fn par_batch_iter_mut(&mut self, num_rows: usize) -> rayon::slice::ChunksMut<T> {
        self.values.par_chunks_mut(num_rows * self.num_col)
    }

    // Returns column number `column`, padded appropriately according to the stored strategy
    pub fn column_padded(&self, column: usize) -> Vec<T> {
        let num_instances = self.num_instances();
        let num_padding_instances = self.num_padding_instances();

        let padding_iter = (num_instances..num_instances + num_padding_instances).map(|i| {
            match &self.padding_strategy {
                InstancePaddingStrategy::Custom(fun) => T::from(fun(i as u64, column as u64)),
                InstancePaddingStrategy::RepeatLast if num_instances > 0 => {
                    self[num_instances - 1][column]
                }
                _ => T::default(),
            }
        });

        self.values
            .iter()
            .skip(column)
            .step_by(self.num_col)
            .copied()
            .chain(padding_iter)
            .collect::<Vec<_>>()
    }
}

impl<F: Field + From<u64>> RowMajorMatrix<F> {
    pub fn into_mles<E: ff_ext::ExtensionField<BaseField = F>>(
        self,
    ) -> Vec<DenseMultilinearExtension<E>> {
        (0..self.num_col)
            .into_par_iter()
            .map(|i| self.column_padded(i).into_mle())
            .collect()
    }
}

impl<F: Sync + Send + Copy> Index<usize> for RowMajorMatrix<F> {
    type Output = [F];

    fn index(&self, idx: usize) -> &Self::Output {
        &self.values[self.num_col * idx..][..self.num_col]
    }
}
