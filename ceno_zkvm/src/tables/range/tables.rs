use crate::ROMType;

trait TableGen {
    fn count() -> usize;
    fn values() -> Vec<u64> {
        (0..Self::count() as u64).collect()
    }
}

struct U8TableGen;

impl TableGen for U8TableGen {
    fn count() -> usize {
        1 << 8
    }
}

impl ROMType {
    pub fn count(self) -> usize {
        match self {
            ROMType::U8 => 1 << 8,
            _ => unreachable!("Unsupported ROMType {:?}", self),
        }
    }

    pub fn gen(self) -> Vec<u64> {
        (0..self.count() as u64).collect()
    }
}
