use ff::Field;
use std::{
    array,
    cell::RefCell,
    collections::HashMap,
    mem::{self},
    ops::Index,
    slice::{Chunks, ChunksMut},
    sync::Arc,
};

use multilinear_extensions::mle::{DenseMultilinearExtension, IntoMLE};
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use thread_local::ThreadLocal;

use crate::{
    instructions::InstancePaddingStrategy,
    structs::ROMType,
    tables::{AndTable, LtuTable, OpsTable, OrTable, PowTable, XorTable},
    utils::next_pow2_instance_padding,
};

#[macro_export]
macro_rules! set_val {
    ($ins:ident, $field:expr, $val:expr) => {
        $ins[$field.id as usize] = $val.into();
    };
}

#[macro_export]
macro_rules! set_fixed_val {
    ($ins:ident, $field:expr, $val:expr) => {
        $ins[$field.0] = $val;
    };
}

#[derive(Clone)]
pub struct RowMajorMatrix<T: Sized + Sync + Clone + Send + Copy> {
    // represent 2D in 1D linear memory and avoid double indirection by Vec<Vec<T>> to improve performance
    values: Vec<T>,
    num_col: usize,
    padding_strategy: InstancePaddingStrategy,
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
        }
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

    pub fn shard_by_rows(&self, shard_rows: usize) -> Vec<Self> {
        let padded_row_num = self.num_instances() + self.num_padding_instances();
        if padded_row_num <= shard_rows {
            return vec![self.clone()];
        }
        // padded_row_num and chunk_rows should both be pow of 2.
        assert_eq!(padded_row_num % shard_rows, 0);
        let shard_num = self.num_instances().div_ceil(shard_rows);
        let mut shards = Vec::new();
        for i in 0..shard_num {
            let start = i * shard_rows * self.num_col;
            let end = ((i + 1) * shard_rows * self.num_col).min(self.values.len());
            let values: Vec<_> = self.values[start..end].to_vec();

            shards.push(Self {
                num_col: self.num_col,
                values,
                padding_strategy: self.padding_strategy.clone(),
            });
        }
        assert_eq!(
            self.num_instances(),
            shards.iter().map(|c| { c.num_instances() }).sum::<usize>()
        );
        shards
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

/// A lock-free thread safe struct to count logup multiplicity for each ROM type
/// Lock-free by thread-local such that each thread will only have its local copy
/// struct is cloneable, for internallly it use Arc so the clone will be low cost
#[derive(Clone, Default, Debug)]
#[allow(clippy::type_complexity)]
pub struct LkMultiplicity {
    multiplicity: Arc<ThreadLocal<RefCell<[HashMap<u64, usize>; mem::variant_count::<ROMType>()]>>>,
}

impl LkMultiplicity {
    /// assert within range
    #[inline(always)]
    pub fn assert_ux<const C: usize>(&mut self, v: u64) {
        match C {
            16 => self.increment(ROMType::U16, v),
            14 => self.increment(ROMType::U14, v),
            8 => self.increment(ROMType::U8, v),
            5 => self.increment(ROMType::U5, v),
            _ => panic!("Unsupported bit range"),
        }
    }

    /// Track a lookup into a logic table (AndTable, etc).
    pub fn logic_u8<OP: OpsTable>(&mut self, a: u64, b: u64) {
        self.increment(OP::ROM_TYPE, OP::pack(a, b));
    }

    /// lookup a AND b
    pub fn lookup_and_byte(&mut self, a: u64, b: u64) {
        self.logic_u8::<AndTable>(a, b)
    }

    /// lookup a OR b
    pub fn lookup_or_byte(&mut self, a: u64, b: u64) {
        self.logic_u8::<OrTable>(a, b)
    }

    /// lookup a XOR b
    pub fn lookup_xor_byte(&mut self, a: u64, b: u64) {
        self.logic_u8::<XorTable>(a, b)
    }

    /// lookup a < b as unsigned byte
    pub fn lookup_ltu_byte(&mut self, a: u64, b: u64) {
        self.logic_u8::<LtuTable>(a, b)
    }

    pub fn lookup_pow2(&mut self, v: u64) {
        self.logic_u8::<PowTable>(2, v)
    }

    /// Fetch instruction at pc
    pub fn fetch(&mut self, pc: u32) {
        self.increment(ROMType::Instruction, pc as u64);
    }

    /// merge result from multiple thread local to single result
    pub fn into_finalize_result(self) -> [HashMap<u64, usize>; mem::variant_count::<ROMType>()] {
        Arc::try_unwrap(self.multiplicity)
            .unwrap()
            .into_iter()
            .fold(array::from_fn(|_| HashMap::new()), |mut x, y| {
                x.iter_mut().zip(y.borrow().iter()).for_each(|(m1, m2)| {
                    for (key, value) in m2 {
                        *m1.entry(*key).or_insert(0) += value;
                    }
                });
                x
            })
    }

    fn increment(&mut self, rom_type: ROMType, key: u64) {
        let multiplicity = self
            .multiplicity
            .get_or(|| RefCell::new(array::from_fn(|_| HashMap::new())));
        (*multiplicity.borrow_mut()[rom_type as usize]
            .entry(key)
            .or_default()) += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use crate::{structs::ROMType, witness::LkMultiplicity};

    #[test]
    fn test_lk_multiplicity_threads() {
        // TODO figure out a way to verify thread_local hit/miss in unittest env
        let lkm = LkMultiplicity::default();
        let thread_count = 20;
        // each thread calling assert_byte once
        for _ in 0..thread_count {
            let mut lkm = lkm.clone();
            thread::spawn(move || lkm.assert_ux::<8>(8u64))
                .join()
                .unwrap();
        }
        let res = lkm.into_finalize_result();
        // check multiplicity counts of assert_byte
        assert_eq!(res[ROMType::U8 as usize][&8], thread_count);
    }
}
