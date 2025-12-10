use crate::{WORD_SIZE, addr::WordAddr};

/// Dense storage for addresses between `[base, end)`, addressed at word granularity.
///
/// The region is pre-allocated up-front so lookups become simple index operations.
#[derive(Debug)]
pub(crate) struct DenseAddrSpace<T> {
    base: u32,
    end: u32,
    cells: Vec<T>,
}

impl<T: Copy + Default> DenseAddrSpace<T> {
    pub(crate) fn new(base: u32, end: u32) -> Self {
        assert!(
            end >= base,
            "dense address space end must be greater than or equal to base"
        );
        assert!(
            base.is_multiple_of(WORD_SIZE as u32),
            "dense address space base must be word aligned"
        );
        assert!(
            (end - base).is_multiple_of(WORD_SIZE as u32),
            "dense address space must align to WORD_SIZE"
        );
        let len_words = ((end - base) / WORD_SIZE as u32) as usize;
        Self {
            base,
            end,
            cells: vec![T::default(); len_words],
        }
    }

    pub(crate) fn read(&self, addr: WordAddr) -> T {
        self.index(addr)
            .map(|idx| self.cells[idx])
            .unwrap_or_default()
    }

    pub(crate) fn write(&mut self, addr: WordAddr, value: T) -> Option<()> {
        self.index(addr).map(|idx| {
            self.cells[idx] = value;
        })
    }

    pub(crate) fn replace(&mut self, addr: WordAddr, value: T) -> Option<T> {
        self.index(addr).map(|idx| {
            let prev = self.cells[idx];
            self.cells[idx] = value;
            prev
        })
    }

    pub(crate) fn get_ref(&self, addr: WordAddr) -> Option<&T> {
        self.index(addr).map(|idx| &self.cells[idx])
    }

    fn index(&self, addr: WordAddr) -> Option<usize> {
        let byte_addr = addr.baddr().0;
        if byte_addr < self.base || byte_addr >= self.end {
            return None;
        }
        Some(((byte_addr - self.base) / WORD_SIZE as u32) as usize)
    }
}
