//! Copied from <https://github.com/succinctlabs/sp1/blob/ebb517c1a3f3e3b95ee34bf211fb46a73cf108fe/crates/zkvm/lib/src/ecdsa.rs>
//!
//! An implementation of the types needed for [`CurveArithmetic`].
//!
//! [`CurveArithmetic`] is a trait that is used in [RustCryptos ECDSA](https://github.com/RustCrypto/signatures).
//!
//! [`CurveArithmetic`] contains all the types needed to implement the ECDSA algorithm over some
//! curve.
//!
//! This implementation is specifically for use inside of SP1, and internally uses SP1's Weierstrass
//! precompiles. Weierstrass precompiles.
//!
//! In summary, SP1 overrides curve arithmetic entirely, and patches upstream field operations
//! to be more efficient in the VM, such as `sqrt` or `inverse`.

use super::utils::AffinePoint as AffinePointTrait;

use elliptic_curve::{
    CurveArithmetic, FieldBytes, ff, generic_array::typenum::consts::U32, subtle::CtOption,
};
use std::{fmt::Debug, ops::Neg};

/// The affine point type for SP1.
pub mod affine;
pub use affine::AffinePoint;

/// The projective point type for SP1.
pub mod projective;
pub use projective::ProjectivePoint;

/// NOTE: The only supported ECDSA curves are secp256k1 and secp256r1, which both
/// have 8 limbs in their field elements.
const POINT_LIMBS: usize = 8 * 2;

/// The number of bytes in a field element as an [`usize`].
const FIELD_BYTES_SIZE_USIZE: usize = 32;

/// The number of bytes in a field element as an [`elliptic_curve::generic_array::U32`].
#[allow(non_camel_case_types)]
type FIELD_BYTES_SIZE = U32;

/// A [`CurveArithmetic`] extension for SP1 acceleration.
///
/// Patched crates implement this trait to take advantage of SP1-specific acceleration in the zkVM
/// context.
///
/// Note: This trait only supports 32 byte base field curves.
pub trait ECDSACurve
where
    Self: CurveArithmetic<
            FieldBytesSize = FIELD_BYTES_SIZE,
            AffinePoint = AffinePoint<Self>,
            ProjectivePoint = ProjectivePoint<Self>,
        >,
{
    type FieldElement: Field<Self> + Neg<Output = Self::FieldElement>;

    /// The underlying [`AffinePointTrait`] implementation.
    type SP1AffinePoint: ECDSAPoint;

    /// The `a` coefficient in the curve equation.
    const EQUATION_A: Self::FieldElement;

    /// The `b` coefficient in the curve equation.
    const EQUATION_B: Self::FieldElement;
}

/// Alias trait for the [`ff::PrimeField`] with 32 byte field elements.
///
/// Note: All bytes should be considered to be in big-endian format.
pub trait Field<C: ECDSACurve>: ff::PrimeField {
    /// Create an instance of self from a FieldBytes.
    fn from_bytes(bytes: &FieldBytes<C>) -> CtOption<Self>;

    /// Convert self to a FieldBytes.
    ///
    /// Note: Implementers should ensure these methods normalize first.
    fn to_bytes(self) -> FieldBytes<C>;

    /// Ensure the field element is normalized.
    fn normalize(self) -> Self;
}

pub type FieldElement<C> = <C as ECDSACurve>::FieldElement;

/// Alias trait for the [`AffinePointTrait`] with 32 byte field elements.
pub trait ECDSAPoint: AffinePointTrait<POINT_LIMBS> + Clone + Copy + Debug + Send + Sync {
    #[inline]
    fn from(x: &[u8], y: &[u8]) -> Self {
        <Self as AffinePointTrait<POINT_LIMBS>>::from(x, y)
    }
}

impl<P> ECDSAPoint for P where P: AffinePointTrait<POINT_LIMBS> + Clone + Copy + Debug + Send + Sync {}

pub mod ecdh {
    pub use elliptic_curve::ecdh::{EphemeralSecret, SharedSecret, diffie_hellman};

    use super::{AffinePoint, ECDSACurve, Field};

    impl<C: ECDSACurve> From<&AffinePoint<C>> for SharedSecret<C> {
        fn from(affine: &AffinePoint<C>) -> SharedSecret<C> {
            let (x, _) = affine.field_elements();

            x.to_bytes().into()
        }
    }
}
