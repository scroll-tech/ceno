use multilinear_extensions::mle::{DenseMultilinearExtension, IntoMLE};
use p3::field::{Field, PrimeCharacteristicRing};
use p3::matrix::{Matrix, bitrev::BitReversableMatrix};
use rand::{Rng, distributions::Standard, prelude::Distribution};
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use std::{
    ops::{Deref, DerefMut, Index},
    slice::{Chunks, ChunksMut},
    sync::Arc,
};

/// get next power of 2 instance with minimal size 2
pub fn next_pow2_instance_padding(num_instance: usize) -> usize {
    num_instance.next_power_of_two().max(2)
}

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

#[derive(Clone)]
pub struct RowMajorMatrix<T: Sized + Sync + Clone + Send + Copy> {
    inner: p3::matrix::dense::RowMajorMatrix<T>,
    padding_strategy: InstancePaddingStrategy,
}

impl<T: Sized + Sync + Clone + Send + Copy + Default + PrimeCharacteristicRing> RowMajorMatrix<T> {
    pub fn rand<R: Rng>(rng: &mut R, rows: usize, cols: usize) -> Self
    where
        Standard: Distribution<T>,
    {
        Self {
            inner: p3::matrix::dense::RowMajorMatrix::rand(rng, rows, cols),
            padding_strategy: InstancePaddingStrategy::Default,
        }
    }
    pub fn empty() -> Self {
        Self {
            inner: p3::matrix::dense::RowMajorMatrix::new(vec![], 0),
            padding_strategy: InstancePaddingStrategy::Default,
        }
    }
    /// convert into the p3 RowMajorMatrix, with padded to next power of 2 height filling with T::default value
    pub fn into_default_padded_p3_rmm(self) -> p3::matrix::dense::RowMajorMatrix<T> {
        let padded_height = next_pow2_instance_padding(self.num_instances());
        let mut inner = self.inner;
        inner.pad_to_height(padded_height, T::default());
        inner
    }

    pub fn n_col(&self) -> usize {
        self.inner.width
    }

    pub fn num_vars(&self) -> usize {
        (next_pow2_instance_padding(self.num_instances())).ilog2() as usize
    }

    pub fn new(num_rows: usize, num_col: usize, padding_strategy: InstancePaddingStrategy) -> Self {
        let value = (0..num_rows * num_col)
            .into_par_iter()
            .map(|_| T::default())
            .collect();
        RowMajorMatrix {
            inner: p3::matrix::dense::RowMajorMatrix::new(value, num_col),
            padding_strategy,
        }
    }

    pub fn new_by_inner_matrix(
        m: p3::matrix::dense::RowMajorMatrix<T>,
        padding_strategy: InstancePaddingStrategy,
    ) -> Self {
        RowMajorMatrix {
            inner: m,
            padding_strategy,
        }
    }

    pub fn num_padding_instances(&self) -> usize {
        next_pow2_instance_padding(self.num_instances()) - self.num_instances()
    }

    pub fn num_instances(&self) -> usize {
        self.inner.height()
    }

    pub fn iter_rows(&self) -> Chunks<T> {
        self.inner.values.chunks(self.inner.width)
    }

    pub fn iter_mut(&mut self) -> ChunksMut<T> {
        self.inner.values.chunks_mut(self.inner.width)
    }

    pub fn par_batch_iter_mut(&mut self, num_rows: usize) -> rayon::slice::ChunksMut<T> {
        self.inner
            .values
            .par_chunks_mut(num_rows * self.inner.width)
    }

    // Returns column number `column`, padded appropriately according to the stored strategy
    pub fn column_padded(&self, column: usize) -> Vec<T> {
        let n_column = self.n_col();
        let num_instances = self.num_instances();
        let num_padding_instances = self.num_padding_instances();

        let padding_iter = (num_instances..num_instances + num_padding_instances).map(|i| {
            match &self.padding_strategy {
                InstancePaddingStrategy::Custom(fun) => T::from_u64(fun(i as u64, column as u64)),
                InstancePaddingStrategy::RepeatLast if num_instances > 0 => {
                    self[num_instances - 1][column]
                }
                _ => T::default(),
            }
        });

        self.inner
            .values
            .iter()
            .skip(column)
            .step_by(n_column)
            .copied()
            .chain(padding_iter)
            .collect::<Vec<_>>()
    }
}

impl<F: Field + PrimeCharacteristicRing> RowMajorMatrix<F> {
    pub fn to_mles<E: ff_ext::ExtensionField<BaseField = F>>(
        &self,
    ) -> Vec<DenseMultilinearExtension<E>> {
        let n_column = self.inner.width;
        (0..n_column)
            .into_par_iter()
            .map(|i| self.column_padded(i).into_mle())
            .collect()
    }
}

impl<T: Sized + Sync + Clone + Send + Copy + Default + PrimeCharacteristicRing> Deref
    for RowMajorMatrix<T>
{
    type Target = p3::matrix::dense::DenseMatrix<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Sized + Sync + Clone + Send + Copy + Default + PrimeCharacteristicRing> DerefMut
    for RowMajorMatrix<T>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<F: Sync + Send + Copy + PrimeCharacteristicRing> Index<usize> for RowMajorMatrix<F> {
    type Output = [F];

    fn index(&self, idx: usize) -> &Self::Output {
        let num_col = self.n_col();
        &self.inner.values[num_col * idx..][..num_col]
    }
}
