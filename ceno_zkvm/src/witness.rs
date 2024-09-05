use std::{
    mem::{self, MaybeUninit},
    slice::ChunksMut,
};

use multilinear_extensions::util::create_uninit_vec;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
    slice::ParallelSliceMut,
};

#[macro_export]
macro_rules! set_val {
    ($ins:ident, $field:expr, $val:expr) => {
        $ins[$field.id as usize] = MaybeUninit::new($val.into());
    };
}

pub struct RowMajorMatrix<T: Sized + Sync + Clone + Send> {
    // represent 2D in 1D linear memory and avoid double indirection by Vec<Vec<T>> to improve performance
    values: Vec<MaybeUninit<T>>,
    num_padding_rows: usize,
    num_col: usize,
}

impl<T: Sized + Sync + Clone + Send> RowMajorMatrix<T> {
    pub fn new(num_rows: usize, num_col: usize) -> Self {
        let num_total_rows = num_rows.next_power_of_two();
        let num_padding_rows = num_total_rows - num_rows;
        RowMajorMatrix {
            values: create_uninit_vec(num_total_rows * num_col),
            num_padding_rows,
            num_col,
        }
    }

    pub fn num_instances(&self) -> usize {
        self.values.len() / self.num_col - self.num_padding_rows
    }

    pub fn iter_mut(&mut self) -> ChunksMut<MaybeUninit<T>> {
        self.values.chunks_mut(self.num_col)
    }

    pub fn par_iter_mut(&mut self) -> rayon::slice::ChunksMut<MaybeUninit<T>> {
        self.values.par_chunks_mut(self.num_col)
    }

    pub fn de_interleaving(mut self) -> Vec<Vec<T>> {
        (0..self.num_col)
            .map(|i| {
                self.values
                    .par_iter_mut()
                    .skip(i)
                    .step_by(self.num_col)
                    .map(|v| unsafe { mem::replace(v, mem::MaybeUninit::uninit()).assume_init() })
                    .collect::<Vec<T>>()
            })
            .collect()
    }
}
