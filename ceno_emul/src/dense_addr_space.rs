use crate::addr::WordAddr;

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
        if addr.0 < self.base.0 || addr.0 >= self.end.0 {
            return None;
        }
        Some((addr.0 - self.base.0) as usize)
    }
}
