use generic_array::GenericArray;
use sp1_curves::params::NumWords;

mod weierstrass_add;

#[derive(Clone, Default, Debug)]
pub struct EllipticCurveAddInstance<P: NumWords> {
    /// The first point as a list of words.
    pub p: GenericArray<u32, P::WordsCurvePoint>,
    /// The second point as a list of words.
    pub q: GenericArray<u32, P::WordsCurvePoint>,
}
