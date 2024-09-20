use ff::Field;
use std::{
    array,
    cell::RefCell,
    collections::HashMap,
    mem::{self, MaybeUninit},
    slice::{Chunks, ChunksMut},
    sync::Arc,
};

use multilinear_extensions::{
    mle::{DenseMultilinearExtension, IntoMLEs},
    util::create_uninit_vec,
};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use thread_local::ThreadLocal;

use crate::{
    structs::ROMType,
    tables::{AndTable, LtuTable, OpsTable, OrTable, XorTable},
};

#[macro_export]
macro_rules! set_val {
    ($ins:ident, $field:expr, $val:expr) => {
        $ins[$field.id as usize] = MaybeUninit::new($val.into());
    };
}

#[macro_export]
macro_rules! set_fixed_val {
    ($ins:ident, $field:expr, $val:expr) => {
        $ins[$field.0] = MaybeUninit::new($val);
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

    pub fn iter_rows(&self) -> Chunks<MaybeUninit<T>> {
        self.values.chunks(self.num_col)
    }

    pub fn iter_mut(&mut self) -> ChunksMut<MaybeUninit<T>> {
        self.values.chunks_mut(self.num_col)
    }

    pub fn par_iter_mut(&mut self) -> rayon::slice::ChunksMut<MaybeUninit<T>> {
        self.values.par_chunks_mut(self.num_col)
    }

    pub fn par_batch_iter_mut(
        &mut self,
        num_rows: usize,
    ) -> rayon::slice::ChunksMut<MaybeUninit<T>> {
        self.values.par_chunks_mut(num_rows * self.num_col)
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

impl<F: Field> RowMajorMatrix<F> {
    pub fn into_mles<E: ff_ext::ExtensionField<BaseField = F>>(
        self,
    ) -> Vec<DenseMultilinearExtension<E>> {
        self.de_interleaving().into_mles()
    }
}

/// A lock-free thread safe struct to count logup multiplicity for each ROM type
/// Lock-free by thread-local such that each thread will only have its local copy
/// struct is cloneable, for internallly it use Arc so the clone will be low cost
#[derive(Clone, Default)]
#[allow(clippy::type_complexity)]
pub struct LkMultiplicity {
    multiplicity: Arc<ThreadLocal<RefCell<[HashMap<u64, usize>; mem::variant_count::<ROMType>()]>>>,
}

#[allow(dead_code)]
impl LkMultiplicity {
    /// assert within range
    #[inline(always)]
    pub fn assert_ux<const C: usize>(&mut self, v: u64) {
        match C {
            16 => self.increment(ROMType::U16, v),
            8 => self.increment(ROMType::U8, v),
            5 => self.increment(ROMType::U5, v),
            1 => self.increment(ROMType::U1, v),
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
