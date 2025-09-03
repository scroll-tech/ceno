use ceno_emul::{ByteAddr, Cycle};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use sp1_curves::params::NumWords;

mod weierstrass_add;

/// Elliptic Curve Add Event.
///
/// This event is emitted when an elliptic curve addition operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EllipticCurveAddWitInstance<P: NumWords> {
    /// The first point as a list of words.
    pub p: GenericArray<u32, P::WordsCurvePoint>,
    /// The second point as a list of words.
    pub q: GenericArray<u32, P::WordsCurvePoint>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EllipticCurveAddStateInstance<P: NumWords> {
    pub addrs: [ByteAddr; 2],
    pub cur_ts: Cycle,
    pub read_ts: [GenericArray<Cycle, P::WordsCurvePoint>; 2],
}

#[derive(Clone, Default)]
pub struct EllipticCurveAddInstance<P: NumWords> {
    pub state: EllipticCurveAddStateInstance<P>,
    pub witin: EllipticCurveAddWitInstance<P>,
}
