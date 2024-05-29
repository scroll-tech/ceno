use super::uint::UInt;

// TODO: determine constant access controls

impl<const M: usize, const C: usize> UInt<M, C> {
    pub(crate) const HMM: usize = M + C;

    pub fn hello() {
        dbg!("hello");
        dbg!(Self::HMM);
    }
}
