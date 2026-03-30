use openvm_stark_backend::p3_field::PrimeCharacteristicRing;

pub trait CanonicalFieldExt: PrimeCharacteristicRing {
    #[allow(clippy::inline_always)]
    fn from_canonical_u64(value: u64) -> Self {
        let mut v = value;
        let mut result = Self::ZERO;
        let mut base = Self::ONE;
        while v > 0 {
            if v & 1 == 1 {
                result += base.clone();
            }
            base += base.clone();
            v >>= 1;
        }
        result
    }

    #[inline(always)]
    fn from_canonical_u32(value: u32) -> Self {
        Self::from_canonical_u64(u64::from(value))
    }

    #[inline(always)]
    fn from_canonical_u16(value: u16) -> Self {
        Self::from_canonical_u64(u64::from(value))
    }

    #[inline(always)]
    fn from_canonical_u8(value: u8) -> Self {
        Self::from_canonical_u64(u64::from(value))
    }

    #[inline(always)]
    fn from_canonical_usize(value: usize) -> Self {
        Self::from_canonical_u64(value as u64)
    }

    #[inline(always)]
    fn from_isize(value: isize) -> Self {
        if value >= 0 {
            Self::from_canonical_usize(value as usize)
        } else {
            -Self::from_canonical_usize(value.unsigned_abs() as usize)
        }
    }
}

impl<T> CanonicalFieldExt for T where T: PrimeCharacteristicRing {}
