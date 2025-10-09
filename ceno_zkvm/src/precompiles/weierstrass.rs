use generic_array::GenericArray;
use num::BigUint;
use sp1_curves::params::NumWords;

pub mod test_utils;
pub mod weierstrass_add;
pub mod weierstrass_decompress;
pub mod weierstrass_double;

#[derive(Clone, Default, Debug)]
pub struct EllipticCurveAddInstance<P: NumWords> {
    /// The first point as a list of words.
    pub p: GenericArray<u32, P::WordsCurvePoint>,
    /// The second point as a list of words.
    pub q: GenericArray<u32, P::WordsCurvePoint>,
}

#[derive(Clone, Default, Debug)]
pub struct EllipticCurveDoubleInstance<P: NumWords> {
    /// The point as a list of words.
    pub p: GenericArray<u32, P::WordsCurvePoint>,
}

/// Elliptic Curve Point Decompress Event.
///
/// This event is emitted when an elliptic curve point decompression operation is performed.
#[derive(Debug, Clone)]
pub struct EllipticCurveDecompressInstance<P: NumWords> {
    /// The sign bit of the point.
    pub sign_bit: bool,
    /// The x coordinate as a list of bytes.
    pub x: BigUint,
    /// The old value of y.
    pub old_y_words: GenericArray<u32, P::WordsFieldElement>,
}
