use itertools::izip;
use multilinear_extensions::mle::{DenseMultilinearExtension, IntoMLE};
use p3::{
    field::{Field, PrimeCharacteristicRing},
    maybe_rayon::prelude::*,
};
use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    mem::{self},
    ops::AddAssign,
    sync::Arc,
};
use thread_local::ThreadLocal;

use crate::{
    structs::ROMType,
    tables::{AndTable, LtuTable, OpsTable, OrTable, PowTable, XorTable},
};

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
