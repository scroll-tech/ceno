use multilinear_extensions::mle::{IntoMLE, MultilinearExtension};
use p3::{
    field::{Field, FieldAlgebra},
    matrix::Matrix,
};
use rand::{Rng, distributions::Standard, prelude::Distribution};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelExtend, ParallelIterator},
    slice::ParallelSliceMut,
};
use std::{
    ops::{Deref, DerefMut, Index},
    slice::{Chunks, ChunksMut},
    sync::Arc,
};

// for witness we reserve some space for value vector to extend to avoid allocated + full clone
pub const CAPACITY_RESERVED_FACTOR: usize = 2;

/// get next power of 2 instance with minimal size 2
pub fn next_pow2_instance_padding(num_instance: usize) -> usize {
    num_instance.next_power_of_two().max(2)
}

#[derive(Clone)]
pub enum InstancePaddingStrategy {
    // Pads with default values of underlying type
    // Usually zero, but check carefully
    Default,
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

impl<T: Sized + Sync + Clone + Send + Copy + Default + FieldAlgebra> RowMajorMatrix<T> {
    pub fn rand<R: Rng>(rng: &mut R, rows: usize, cols: usize) -> Self
    where
        Standard: Distribution<T>,
    {
        debug_assert!(rows > 0);
        let num_row_padded = next_pow2_instance_padding(rows);
        Self {
            inner: p3::matrix::dense::RowMajorMatrix::rand(rng, num_row_padded, cols),
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

    /// convert into the p3 RowMajorMatrix, with padded to next power of 2 height filling with T::default value
    /// padding its height to the next power of two (optionally multiplied by a `blowup_factor`)
    /// padding is filled with `T::default()`, and the transformation consumes `self`
    pub fn into_default_padded_p3_rmm(
        mut self,
        blowup_factor: Option<usize>,
    ) -> p3::matrix::dense::RowMajorMatrix<T> {
        let padded_height = next_pow2_instance_padding(self.num_instances());
        if let Some(blowup_factor) = blowup_factor {
            if blowup_factor != CAPACITY_RESERVED_FACTOR {
                tracing::warn!(
                    "blowup_factor {blowup_factor} != CAPACITY_RESERVED_FACTOR {CAPACITY_RESERVED_FACTOR}, \
                     consider updating the default CAPACITY_RESERVED_FACTOR accordingly"
                );
            }
        }
        self.pad_to_height(padded_height * blowup_factor.unwrap_or(1), T::default());
        self.inner
    }

    pub fn n_col(&self) -> usize {
        self.inner.width
    }

    pub fn num_vars(&self) -> usize {
        self.inner.height().ilog2() as usize
    }

    pub fn new(
        num_rows: usize,
        num_cols: usize,
        padding_strategy: InstancePaddingStrategy,
    ) -> Self {
        let num_row_padded = next_pow2_instance_padding(num_rows);

        let mut value = Vec::with_capacity(CAPACITY_RESERVED_FACTOR * num_row_padded * num_cols);
        value.par_extend(
            (0..num_row_padded * num_cols)
                .into_par_iter()
                .map(|_| T::default()),
        );
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

    pub fn new_by_values(
        values: Vec<T>,
        num_cols: usize,
        padding_strategy: InstancePaddingStrategy,
    ) -> Self {
        RowMajorMatrix::new_by_inner_matrix(
            p3::matrix::dense::RowMajorMatrix::new(values, num_cols),
            padding_strategy,
        )
    }

    pub fn num_padding_instances(&self) -> usize {
        next_pow2_instance_padding(self.num_instances()) - self.num_instances()
    }

    pub fn num_instances(&self) -> usize {
        self.num_rows
    }

    pub fn iter_rows(&self) -> Chunks<T> {
        self.inner.values[..self.num_instances() * self.n_col()].chunks(self.inner.width)
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
        let start_index = self.num_instances() * self.n_col();

        match &self.padding_strategy {
            InstancePaddingStrategy::Default => (),
            InstancePaddingStrategy::Custom(fun) => {
                self.inner.values[start_index..]
                    .par_chunks_mut(self.inner.width)
                    .enumerate()
                    .for_each(|(i, instance)| {
                        instance.iter_mut().enumerate().for_each(|(j, v)| {
                            *v = T::from_canonical_u64(fun((start_index + i) as u64, j as u64));
                        })
                    });
            }
        };
        self.is_padded = true;
    }

    pub fn into_inner(self) -> p3::matrix::dense::RowMajorMatrix<T> {
        self.inner
    }

    pub fn values(&self) -> &[T] {
        &self.inner.values
    }

    pub fn pad_to_height(&mut self, new_height: usize, fill: T) {
        let (cur_height, n_cols) = (self.height(), self.n_col());
        assert!(new_height >= cur_height);
        self.values.par_extend(
            (0..(new_height - cur_height) * n_cols)
                .into_par_iter()
                .map(|_| fill),
        );
    }
}

impl<F: Field> RowMajorMatrix<F> {
    pub fn to_mles<'a, E: ff_ext::ExtensionField<BaseField = F>>(
        &self,
    ) -> Vec<MultilinearExtension<'a, E>> {
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

    pub fn to_cols_base<E: ff_ext::ExtensionField<BaseField = F>>(&self) -> Vec<Vec<F>> {
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
            })
            .collect::<Vec<_>>()
    }

    pub fn to_cols_ext<E: ff_ext::ExtensionField<BaseField = F>>(&self) -> Vec<Vec<E>> {
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
                    .map(|v| E::from_ref_base(&v))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }
}

impl<T: Sized + Sync + Clone + Send + Copy + Default> Deref for RowMajorMatrix<T> {
    type Target = p3::matrix::dense::DenseMatrix<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Sized + Sync + Clone + Send + Copy + Default> DerefMut for RowMajorMatrix<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<F: Sync + Send + Copy + FieldAlgebra> Index<usize> for RowMajorMatrix<F> {
    type Output = [F];

    fn index(&self, idx: usize) -> &Self::Output {
        let num_col = self.n_col();
        &self.inner.values[num_col * idx..][..num_col]
    }
}

#[macro_export]
macro_rules! set_val {
    ($ins:ident, $field:expr, $val:expr) => {
        $ins[$field.id as usize] = $val.into_f();
    };
}

#[macro_export]
macro_rules! set_fixed_val {
    ($ins:ident, $field:expr, $val:expr) => {
        $ins[$field.0] = $val;
    };
}
