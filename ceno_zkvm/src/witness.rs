use std::{
    array,
    cell::RefCell,
    collections::HashMap,
    mem::{self, MaybeUninit},
    slice::{Chunks, ChunksMut},
    sync::Arc,
};

use multilinear_extensions::util::create_uninit_vec;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use thread_local::ThreadLocal;

use crate::structs::ROMType;

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
            16 => self.assert_u16(v),
            8 => self.assert_byte(v),
            5 => self.assert_u5(v),
            _ => panic!("Unsupported bit range"),
        }
    }

    fn assert_u5(&mut self, v: u64) {
        let multiplicity = self
            .multiplicity
            .get_or(|| RefCell::new(array::from_fn(|_| HashMap::new())));
        (*multiplicity.borrow_mut()[ROMType::U5 as usize]
            .entry(v)
            .or_default()) += 1;
    }

    fn assert_u16(&mut self, v: u64) {
        let multiplicity = self
            .multiplicity
            .get_or(|| RefCell::new(array::from_fn(|_| HashMap::new())));
        (*multiplicity.borrow_mut()[ROMType::U16 as usize]
            .entry(v)
            .or_default()) += 1;
    }

    fn assert_byte(&mut self, v: u64) {
        let v = v * (1 << u8::BITS);
        let multiplicity = self
            .multiplicity
            .get_or(|| RefCell::new(array::from_fn(|_| HashMap::new())));
        (*multiplicity.borrow_mut()[ROMType::U16 as usize]
            .entry(v)
            .or_default()) += 1;
    }

    /// lookup a < b as unsigned byte
    pub fn lookup_ltu_limb8(&mut self, a: u64, b: u64) {
        let key = a.wrapping_mul(256) + b;
        let multiplicity = self
            .multiplicity
            .get_or(|| RefCell::new(array::from_fn(|_| HashMap::new())));
        (*multiplicity.borrow_mut()[ROMType::Ltu as usize]
            .entry(key)
            .or_default()) += 1;
    }

    pub fn fetch(&mut self, pc: u32) {
        let multiplicity = self
            .multiplicity
            .get_or(|| RefCell::new(array::from_fn(|_| HashMap::new())));
        (*multiplicity.borrow_mut()[ROMType::Instruction as usize]
            .entry(pc as u64)
            .or_default()) += 1;
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
            thread::spawn(move || lkm.assert_byte(8u64)).join().unwrap();
        }
        let res = lkm.into_finalize_result();
        // check multiplicity counts of assert_byte
        assert_eq!(res[ROMType::U16 as usize][&(8 << 8)], thread_count);
    }
}
