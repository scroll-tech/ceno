use itertools::izip;
use p3::field::PrimeField32;
use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    mem::{self},
    ops::{AddAssign, Deref, DerefMut},
    sync::Arc,
};
use thread_local::ThreadLocal;

use crate::tables::{
    LookupTable, OpsTable,
    ops::{AndTable, LtuTable, OrTable, PowTable, XorTable},
};

pub type MultiplicityRaw<K> = [HashMap<K, usize>; mem::variant_count::<LookupTable>()];

#[derive(Clone, Default, Debug)]
pub struct Multiplicity<K>(pub MultiplicityRaw<K>);

impl<K> Deref for Multiplicity<K> {
    type Target = MultiplicityRaw<K>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K> DerefMut for Multiplicity<K> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// for consuming the wrapper
impl<K> IntoIterator for Multiplicity<K>
where
    MultiplicityRaw<K>: IntoIterator,
{
    type Item = <MultiplicityRaw<K> as IntoIterator>::Item;
    type IntoIter = <MultiplicityRaw<K> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// for immutable references
impl<'a, K> IntoIterator for &'a Multiplicity<K>
where
    &'a MultiplicityRaw<K>: IntoIterator,
{
    type Item = <&'a MultiplicityRaw<K> as IntoIterator>::Item;
    type IntoIter = <&'a MultiplicityRaw<K> as IntoIterator>::IntoIter;

    #[allow(clippy::into_iter_on_ref)]
    fn into_iter(self) -> Self::IntoIter {
        (&self.0).into_iter()
    }
}

/// for mutable references
impl<'a, K> IntoIterator for &'a mut Multiplicity<K>
where
    &'a mut MultiplicityRaw<K>: IntoIterator,
{
    type Item = <&'a mut MultiplicityRaw<K> as IntoIterator>::Item;
    type IntoIter = <&'a mut MultiplicityRaw<K> as IntoIterator>::IntoIter;

    #[allow(clippy::into_iter_on_ref)]
    fn into_iter(self) -> Self::IntoIter {
        (&mut self.0).into_iter()
    }
}

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
        *self += Multiplicity(rhs.into_finalize_result().0);
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

impl<K> AddAssign<((LookupTable, K), usize)> for LkMultiplicityRaw<K>
where
    K: Copy + Clone + Debug + Default + Eq + Hash + Send,
{
    fn add_assign(&mut self, ((rom_type, key), value): ((LookupTable, K), usize)) {
        let multiplicity = self.multiplicity.get_or_default();
        (*multiplicity.borrow_mut().0[rom_type as usize]
            .entry(key)
            .or_default()) += value;
    }
}

impl<K> AddAssign<(LookupTable, K)> for LkMultiplicityRaw<K>
where
    K: Copy + Clone + Debug + Default + Eq + Hash + Send,
{
    fn add_assign(&mut self, (rom_type, key): (LookupTable, K)) {
        let multiplicity = self.multiplicity.get_or_default();
        (*multiplicity.borrow_mut().0[rom_type as usize]
            .entry(key)
            .or_default()) += 1;
    }
}

impl<K: Copy + Clone + Debug + Default + Eq + Hash + Send> LkMultiplicityRaw<K> {
    /// Merge result from multiple thread local to single result.
    pub fn into_finalize_result(self) -> Multiplicity<K> {
        let mut results = Multiplicity::default();
        for y in Arc::try_unwrap(self.multiplicity).unwrap() {
            results += y.into_inner();
        }
        results
    }

    pub fn increment(&mut self, rom_type: LookupTable, key: K) {
        *self += (rom_type, key);
    }

    pub fn set_count(&mut self, rom_type: LookupTable, key: K, count: usize) {
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
}

/// Default LkMultiplicity with u64 key.
pub type LkMultiplicity = LkMultiplicityRaw<u64>;

impl LkMultiplicity {
    #[inline(always)]
    pub fn assert_dynamic_range(&mut self, v: u64, bits: u64) {
        self.increment(LookupTable::Dynamic, (1 << bits) + v);
    }

    #[inline(always)]
    pub fn assert_const_range(&mut self, v: u64, max_bits: usize) {
        // skip max_bits = 1 range check as it was constrained as (v)*(1-v) without lookup
        if max_bits > 1 {
            self.assert_dynamic_range(v, max_bits as u64);
        }
    }

    /// TODO remove `assert_ux` and use `assert_const_range` instead
    /// assert within range
    #[inline(always)]
    pub fn assert_ux<const C: usize>(&mut self, v: u64) {
        self.increment(LookupTable::Dynamic, (1 << C) + v);
    }

    #[inline(always)]
    pub fn assert_double_u8(&mut self, a: u64, b: u64) {
        self.increment(LookupTable::DoubleU8, (a << 8) + b);
    }

    /// assert slices within range
    #[inline]
    pub fn assert_ux_slice_fields<const C: usize, F: PrimeField32>(&mut self, vs: &[F]) {
        for &v in vs {
            self.assert_ux::<C>(v.as_canonical_u64());
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
        self.increment(LookupTable::Instruction, pc as u64);
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use crate::{tables::LookupTable, utils::lk_multiplicity::LkMultiplicity};

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
        assert_eq!(
            res[LookupTable::Dynamic as usize][&((1 << 8) + 8)],
            thread_count
        );
    }
}
