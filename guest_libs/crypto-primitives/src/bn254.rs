use crate::utils::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint};
use ceno_syscall::{syscall_bn254_add, syscall_bn254_double};

/// The number of limbs in [Bn254AffinePoint].
pub const N: usize = 16;

/// A point on the Bn254 curve.
#[derive(Copy, Clone)]
#[repr(align(4))]
pub struct Bn254Point(pub WeierstrassPoint<N>);

impl WeierstrassAffinePoint<N> for Bn254Point {
    fn infinity() -> Self {
        Self(WeierstrassPoint::Infinity)
    }

    fn is_infinity(&self) -> bool {
        matches!(self.0, WeierstrassPoint::Infinity)
    }
}

impl AffinePoint<N> for Bn254Point {
    const GENERATOR: Self = Self(WeierstrassPoint::Affine([
        1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
    ]));

    fn new(limbs: [u32; N]) -> Self {
        Self(WeierstrassPoint::Affine(limbs))
    }

    fn identity() -> Self {
        Self::infinity()
    }

    fn inner(&self) -> &WeierstrassPoint<N> {
        &self.0
    }

    fn inner_mut(&mut self) -> &mut WeierstrassPoint<N> {
        &mut self.0
    }

    fn is_identity(&self) -> bool {
        self.is_infinity()
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();
        syscall_bn254_add(a, b);
    }

    fn complete_add_assign(&mut self, other: &Self) {
        self.weierstrass_add_assign(other);
    }

    fn double(&mut self) {
        let a = self.limbs_mut();
        syscall_bn254_double(a);
    }
}
