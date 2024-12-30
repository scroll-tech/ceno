use ff::Field;
use itertools::izip;
use multilinear_extensions::mle::{DenseMultilinearExtension, IntoMLE};
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    mem::{self},
    ops::{AddAssign, Index},
    slice::{Chunks, ChunksMut},
    sync::Arc,
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

pub type MultiplicityRaw<K> = [HashMap<K, usize>; mem::variant_count::<ROMType>()];

#[derive(Clone, Default, Debug)]
pub struct Multiplicity<K>(pub MultiplicityRaw<K>);

/// A lock-free thread safe struct to count logup multiplicity for each ROM type
/// Lock-free by thread-local such that each thread will only have its local copy
/// struct is cloneable, for internallly it use Arc so the clone will be low cost
#[derive(Clone, Default, Debug)]
#[allow(clippy::type_complexity)]
pub struct LkMultiplicityRaw<K: Copy + Clone + Debug + Eq + Hash + Send> {
    multiplicity: Arc<ThreadLocal<RefCell<Multiplicity<K>>>>,
}

impl<K> AddAssign<Self> for LkMultiplicityRaw<K>
where
    K: Copy + Clone + Debug + Default + Eq + Hash + Send,
{
    fn add_assign(&mut self, rhs: Self) {
        *self += Multiplicity(rhs.into_finalize_result());
    }
}

impl<K> AddAssign<Self> for Multiplicity<K>
where
    K: Eq + Hash,
{
    fn add_assign(&mut self, rhs: Self) {
        for (lhs, rhs) in izip!(&mut self.0, rhs.0) {
            for (key, value) in rhs {
                *lhs.entry(key).or_default() += value;
            }
        }
    }
}

impl<K> AddAssign<Multiplicity<K>> for LkMultiplicityRaw<K>
where
    K: Copy + Clone + Debug + Default + Eq + Hash + Send,
{
    fn add_assign(&mut self, rhs: Multiplicity<K>) {
        let multiplicity = self.multiplicity.get_or_default();
        for (lhs, rhs) in izip!(&mut multiplicity.borrow_mut().0, rhs.0) {
            for (key, value) in rhs {
                *lhs.entry(key).or_default() += value;
            }
        }
    }
}

impl<K> AddAssign<((ROMType, K), usize)> for LkMultiplicityRaw<K>
where
    K: Copy + Clone + Debug + Default + Eq + Hash + Send,
{
    fn add_assign(&mut self, ((rom_type, key), value): ((ROMType, K), usize)) {
        let multiplicity = self.multiplicity.get_or_default();
        (*multiplicity.borrow_mut().0[rom_type as usize]
            .entry(key)
            .or_default()) += value;
    }
}

impl<K> AddAssign<(ROMType, K)> for LkMultiplicityRaw<K>
where
    K: Copy + Clone + Debug + Default + Eq + Hash + Send,
{
    fn add_assign(&mut self, (rom_type, key): (ROMType, K)) {
        let multiplicity = self.multiplicity.get_or_default();
        (*multiplicity.borrow_mut().0[rom_type as usize]
            .entry(key)
            .or_default()) += 1;
    }
}

impl<K: Copy + Clone + Debug + Default + Eq + Hash + Send> LkMultiplicityRaw<K> {
    /// Merge result from multiple thread local to single result.
    pub fn into_finalize_result(self) -> MultiplicityRaw<K> {
        let mut results = Multiplicity::default();
        for y in Arc::try_unwrap(self.multiplicity).unwrap() {
            results += y.into_inner();
        }
        results.0
    }

    pub fn increment(&mut self, rom_type: ROMType, key: K) {
        *self += (rom_type, key);
    }

    pub fn set_count(&mut self, rom_type: ROMType, key: K, count: usize) {
        if count == 0 {
            return;
        }
        let multiplicity = self.multiplicity.get_or_default();
        let table = &mut multiplicity.borrow_mut().0[rom_type as usize];
        if count == 0 {
            table.remove(&key);
        } else {
            table.insert(key, count);
        }
    }

    /// Clone inner, expensive operation.
    pub fn deep_clone(&self) -> Self {
        let multiplicity = self.multiplicity.get_or_default();
        let deep_cloned = multiplicity.borrow().clone();
        let thread_local = ThreadLocal::new();
        thread_local.get_or(|| RefCell::new(deep_cloned));
        LkMultiplicityRaw {
            multiplicity: Arc::new(thread_local),
        }
    }
}

/// Default LkMultiplicity with u64 key.
pub type LkMultiplicity = LkMultiplicityRaw<u64>;

impl LkMultiplicity {
    /// assert within range
    #[inline(always)]
    pub fn assert_ux<const C: usize>(&mut self, v: u64) {
        use ROMType::*;
        self.increment(
            match C {
                16 => U16,
                14 => U14,
                8 => U8,
                5 => U5,
                _ => panic!("Unsupported bit range"),
            },
            v,
        );
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
