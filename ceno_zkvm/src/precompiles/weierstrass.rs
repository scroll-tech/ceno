use generic_array::GenericArray;
use sp1_curves::params::NumWords;

pub mod test_utils;
pub mod weierstrass_add;
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
