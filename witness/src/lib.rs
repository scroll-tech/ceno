use multilinear_extensions::{
    mle::{DenseMultilinearExtension, IntoMLE},
    util::max_usable_threads,
};
use p3::{
    field::{Field, PrimeCharacteristicRing},
    matrix::{Matrix, bitrev::BitReversableMatrix},
};
use rand::{Rng, distributions::Standard, prelude::Distribution};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
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
    // num_row is the real instance BEFORE padding
    num_rows: usize,
    is_padded: bool,
    padding_strategy: InstancePaddingStrategy,
}

impl<T: Sized + Sync + Clone + Send + Copy + Default + PrimeCharacteristicRing> RowMajorMatrix<T> {
    pub fn rand<R: Rng>(rng: &mut R, rows: usize, cols: usize) -> Self
    where
        Standard: Distribution<T>,
    {
        debug_assert!(rows > 0);
        let mut inner = p3::matrix::dense::RowMajorMatrix::rand(rng, rows, cols);
        let num_row_padded = next_pow2_instance_padding(rows);
        if num_row_padded > rows {
            inner.pad_to_height(num_row_padded, T::default());
        }
        Self {
            inner,
            num_rows: rows,
            is_padded: true,
            padding_strategy: InstancePaddingStrategy::Default,
        }
    }
    pub fn empty() -> Self {
        Self {
            inner: p3::matrix::dense::RowMajorMatrix::new(vec![], 0),
            num_rows: 0,
            is_padded: true,
            padding_strategy: InstancePaddingStrategy::Default,
        }
    }
    pub fn into_default_padded_p3_rmm(
        self,
        is_bit_reserse: bool,
    ) -> p3::matrix::dense::RowMajorMatrix<T> {
        let padded_height = next_pow2_instance_padding(self.num_instances());
        let mut inner = self.inner;
        if is_bit_reserse {
            inner = inner.bit_reverse_rows().to_row_major_matrix();
        }
        inner.pad_to_height(padded_height, T::default());
        inner
    }

    pub fn n_col(&self) -> usize {
        self.inner.width
    }

    pub fn new(
        num_rows: usize,
        num_cols: usize,
        padding_strategy: InstancePaddingStrategy,
    ) -> Self {
        let num_row_padded = next_pow2_instance_padding(num_rows);
        let value = (0..num_row_padded * num_cols)
            .into_par_iter()
            .map(|_| T::default())
            .collect();
        RowMajorMatrix {
            inner: p3::matrix::dense::RowMajorMatrix::new(value, num_cols),
            num_rows,
            is_padded: matches!(padding_strategy, InstancePaddingStrategy::Default),
            padding_strategy,
        }
    }

    pub fn new_by_inner_matrix(
        mut m: p3::matrix::dense::RowMajorMatrix<T>,
        padding_strategy: InstancePaddingStrategy,
    ) -> Self {
        let num_rows = m.height();
        let num_row_padded = next_pow2_instance_padding(num_rows);
        if num_row_padded > m.height() {
            m.pad_to_height(num_row_padded, T::default());
        }
        RowMajorMatrix {
            inner: m,
            num_rows,
            is_padded: matches!(padding_strategy, InstancePaddingStrategy::Default),
            padding_strategy,
        }
    }

    pub fn num_padding_instances(&self) -> usize {
        next_pow2_instance_padding(self.num_instances()) - self.num_instances()
    }

    pub fn num_instances(&self) -> usize {
        self.num_rows
    }

    pub fn iter_rows(&self) -> Chunks<T> {
        let max_range = self.num_instances() * self.n_col();
        self.inner.values[..max_range].chunks(self.inner.width)
    }

    pub fn iter_mut(&mut self) -> ChunksMut<T> {
        let max_range = self.num_instances() * self.n_col();
        self.inner.values[..max_range].chunks_mut(self.inner.width)
    }

    pub fn par_batch_iter_mut(&mut self, num_rows: usize) -> rayon::slice::ChunksMut<T> {
        let max_range = self.num_instances() * self.n_col();
        self.inner.values[..max_range].par_chunks_mut(num_rows * self.inner.width)
    }

    pub fn padding_by_strategy(&mut self) {
        debug_assert!(!self.is_padded);
        let num_instances = self.num_instances();
        let start_index = self.num_instances() * self.n_col();

        if num_instances == 0 {
            return;
        }

        match &self.padding_strategy {
            InstancePaddingStrategy::Default => (),
            InstancePaddingStrategy::RepeatLast => {
                let nthreads = max_usable_threads();
                let num_instance_per_batch = if self.num_padding_instances() > 256 {
                    self.num_padding_instances().div_ceil(nthreads)
                } else {
                    self.num_padding_instances()
                }
                .max(1);

                let last_instance = self[num_instances - 1].to_vec();
                self.inner.values[start_index..]
                    .par_chunks_mut(self.inner.width * num_instance_per_batch)
                    .for_each(|instance| {
                        instance
                            .iter_mut()
                            .zip(last_instance.iter().cycle())
                            .for_each(|(v1, v2)| {
                                *v1 = *v2;
                            })
                    });
            }
            InstancePaddingStrategy::Custom(fun) => {
                self.inner.values[start_index..]
                    .par_chunks_mut(self.inner.width)
                    .enumerate()
                    .for_each(|(i, instance)| {
                        instance.iter_mut().enumerate().for_each(|(j, v)| {
                            *v = T::from_u64(fun((start_index + i) as u64, j as u64));
                        })
                    });
            }
        };
        self.is_padded = true;
    }
}

impl<F: Field + PrimeCharacteristicRing> RowMajorMatrix<F> {
    pub fn to_mles<E: ff_ext::ExtensionField<BaseField = F>>(
        &self,
    ) -> Vec<DenseMultilinearExtension<E>> {
        debug_assert!(self.is_padded);
        let n_column = self.inner.width;
        (0..n_column)
            .into_par_iter()
            .map(|i| {
                self.inner
                    .values
                    .iter()
                    .skip(i)
                    .step_by(n_column)
                    .copied()
                    .collect::<Vec<_>>()
                    .into_mle()
            })
            .collect::<Vec<_>>()
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
