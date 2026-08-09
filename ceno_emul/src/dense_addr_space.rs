use crate::addr::{Cycle, Word, WordAddr};

/// Dense storage for addresses between `[base, end)`, addressed at word granularity.
///
/// The region is pre-allocated up-front so lookups become simple index operations.
#[derive(Debug)]
pub(crate) struct DenseAddrSpace<T> {
    base: WordAddr,
    end: WordAddr,
    cells: Vec<T>,
}

impl<T: Copy + Default> DenseAddrSpace<T> {
    pub(crate) fn new(base: WordAddr, end: WordAddr) -> Self {
        assert!(
            end.0 >= base.0,
            "dense address space end must be >= base ({:?} !>= {:?})",
            end,
            base
        );
        let len_words = (end.0 - base.0) as usize;
        Self {
            base,
            end,
            cells: vec![T::default(); len_words],
        }
    }

    pub(crate) fn read(&self, addr: WordAddr) -> Option<T> {
        self.index(addr).map(|idx| self.cells[idx])
    }

    pub(crate) fn write(&mut self, addr: WordAddr, value: T) -> Option<()> {
        self.index(addr).map(|idx| {
            self.cells[idx] = value;
        })
    }

    pub(crate) fn replace_in_bounds(&mut self, addr: WordAddr, value: T) -> T {
        assert!(
            addr.0 >= self.base.0 && addr.0 < self.end.0,
            "addr {addr:?} outside tracked address space"
        );
        let idx = (addr.0 - self.base.0) as usize;
        let prev = self.cells[idx];
        self.cells[idx] = value;
        prev
    }

    pub(crate) fn get_ref(&self, addr: WordAddr) -> Option<&T> {
        self.index(addr).map(|idx| &self.cells[idx])
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn base(&self) -> WordAddr {
        self.base
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn end(&self) -> WordAddr {
        self.end
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn cells_mut_ptr(&mut self) -> *mut T {
        self.cells.as_mut_ptr()
    }

    fn index(&self, addr: WordAddr) -> Option<usize> {
        if addr.0 < self.base.0 || addr.0 >= self.end.0 {
            return None;
        }
        Some((addr.0 - self.base.0) as usize)
    }
}

const PACKED_VALUE_MASK: u64 = u32::MAX as u64;
const MEMORY_SUBCYCLE: Cycle = 3;

/// Dense VM memory with the latest memory-access instruction ordinal packed
/// into the high half of each cell.
#[derive(Debug)]
pub(crate) struct PackedMemory {
    store: DenseAddrSpace<u64>,
    #[cfg(any(test, debug_assertions))]
    touched: Vec<WordAddr>,
}

impl PackedMemory {
    pub(crate) fn new(base: WordAddr, end: WordAddr) -> Self {
        Self {
            store: DenseAddrSpace::new(base, end),
            #[cfg(any(test, debug_assertions))]
            touched: Vec::new(),
        }
    }

    #[inline(always)]
    pub(crate) fn read(&self, addr: WordAddr) -> Option<Word> {
        self.store.read(addr).map(|cell| cell as Word)
    }

    #[inline(always)]
    pub(crate) fn write_value(&mut self, addr: WordAddr, value: Word) -> Option<()> {
        let cell = self.store.read(addr)?;
        self.store
            .write(addr, (cell & !PACKED_VALUE_MASK) | u64::from(value))
    }

    /// Record a memory access and optionally replace its value.
    #[inline(always)]
    pub(crate) fn access(
        &mut self,
        addr: WordAddr,
        cycle: Cycle,
        value: Option<Word>,
    ) -> Option<(Word, Cycle)> {
        let stamp = Self::encode_stamp(cycle);
        let prev = self.store.read(addr)?;
        let prev_stamp = (prev >> 32) as u32;
        let next_value = value.unwrap_or(prev as Word);
        self.store
            .write(addr, (u64::from(stamp) << 32) | u64::from(next_value))?;
        if prev_stamp == 0 {
            #[cfg(any(test, debug_assertions))]
            self.touched.push(addr);
        }
        Some((prev as Word, Self::decode_stamp(prev_stamp)))
    }

    #[inline(always)]
    pub(crate) fn latest_cycle(&self, addr: WordAddr) -> Option<Cycle> {
        self.store
            .read(addr)
            .map(|cell| Self::decode_stamp((cell >> 32) as u32))
    }

    #[inline(always)]
    pub(crate) fn encode_stamp(cycle: Cycle) -> u32 {
        assert_eq!(
            cycle & 3,
            MEMORY_SUBCYCLE,
            "packed memory access must use memory subcycle {MEMORY_SUBCYCLE}"
        );
        u32::try_from(cycle >> 2).expect("packed memory access stamp exceeds u32::MAX")
    }

    #[inline(always)]
    pub(crate) const fn decode_stamp(stamp: u32) -> Cycle {
        if stamp == 0 {
            0
        } else {
            (stamp as Cycle) << 2 | MEMORY_SUBCYCLE
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.store
            .cells
            .iter()
            .filter(|cell| (**cell >> 32) != 0)
            .count()
    }

    pub(crate) fn cells_mut_ptr(&mut self) -> *mut u64 {
        self.store.cells_mut_ptr()
    }

    pub(crate) fn base(&self) -> WordAddr {
        self.store.base()
    }

    pub(crate) fn end(&self) -> WordAddr {
        self.store.end()
    }

    #[cfg(any(test, debug_assertions))]
    pub(crate) fn addresses(&self) -> impl Iterator<Item = &WordAddr> {
        self.touched.iter()
    }

    #[cfg(all(
        any(test, debug_assertions),
        feature = "aot-x86_64",
        target_arch = "x86_64",
        target_os = "linux"
    ))]
    pub(crate) fn record_native_first_touch(&mut self, addr: WordAddr) {
        self.touched.push(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::PackedMemory;
    use crate::{Cycle, WordAddr};

    #[test]
    fn packed_memory_preserves_values_and_exact_cycles() {
        let base = WordAddr(10);
        let mut memory = PackedMemory::new(base, WordAddr(12));
        memory.write_value(base, 0xdead_beef).unwrap();

        assert_eq!(memory.access(base, 7, None), Some((0xdead_beef, 0)));
        assert_eq!(memory.access(base, 11, Some(42)), Some((0xdead_beef, 7)));
        assert_eq!(memory.read(base), Some(42));
        assert_eq!(memory.latest_cycle(base), Some(11));
        assert_eq!(memory.len(), 1);
    }

    #[test]
    fn packed_memory_stamp_supports_full_u32_ordinal() {
        let cycle = ((u32::MAX as Cycle) << 2) | 3;
        let stamp = PackedMemory::encode_stamp(cycle);
        assert_eq!(stamp, u32::MAX);
        assert_eq!(PackedMemory::decode_stamp(stamp), cycle);
    }

    #[test]
    #[should_panic(expected = "packed memory access must use memory subcycle 3")]
    fn packed_memory_rejects_non_memory_subcycle() {
        let _ = PackedMemory::encode_stamp(6);
    }

    #[test]
    #[should_panic(expected = "packed memory access stamp exceeds u32::MAX")]
    fn packed_memory_rejects_stamp_overflow() {
        let _ = PackedMemory::encode_stamp(((u32::MAX as Cycle + 1) << 2) | 3);
    }
}
