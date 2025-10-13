//! Copied from <https://github.com/succinctlabs/sp1/blob/ebb517c1a3f3e3b95ee34bf211fb46a73cf108fe/crates/zkvm/lib/src/secp256k1.rs>

use crate::{

    utils::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint},
};
use ceno_syscall::{syscall_secp256k1_add, syscall_secp256k1_double};

/// The number of limbs in [Secp256k1Point].
pub const N: usize = 16;

/// An affine point on the Secp256k1 curve.
#[derive(Copy, Clone, Debug)]
#[repr(align(4))]
pub struct Secp256k1Point(pub WeierstrassPoint<N>);

impl WeierstrassAffinePoint<N> for Secp256k1Point {
    fn infinity() -> Self {
        Self(WeierstrassPoint::Infinity)
    }

    fn is_infinity(&self) -> bool {
        matches!(self.0, WeierstrassPoint::Infinity)
    }
}

impl AffinePoint<N> for Secp256k1Point {
    /// The values are taken from https://en.bitcoin.it/wiki/Secp256k1.
    const GENERATOR: Self = Self(WeierstrassPoint::Affine([
        385357720, 1509065051, 768485593, 43777243, 3464956679, 1436574357, 4191992748, 2042521214,
        4212184248, 2621952143, 2793755673, 4246189128, 235997352, 1571093500, 648266853,
        1211816567,
    ]));

    fn new(limbs: [u32; N]) -> Self {
        Self(WeierstrassPoint::Affine(limbs))
    }

    fn identity() -> Self {
        Self::infinity()
    }

    fn limbs_ref(&self) -> &[u32; N] {
        match &self.0 {
            WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn limbs_mut(&mut self) -> &mut [u32; N] {
        match &mut self.0 {
            WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn is_identity(&self) -> bool {
        self.is_infinity()
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();
        syscall_secp256k1_add(a, b);
    }

    fn complete_add_assign(&mut self, other: &Self) {
        self.weierstrass_add_assign(other);
    }

    fn double(&mut self) {
        match &mut self.0 {
            WeierstrassPoint::Infinity => (),
            WeierstrassPoint::Affine(limbs) => syscall_secp256k1_double(limbs),
        }
    }
}
