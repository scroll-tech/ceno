#[cfg(not(feature = "babybear"))]
pub(crate) const DIGEST_WIDTH: usize = 4;

#[cfg(not(feature = "babybear"))]
pub(crate) const PERMUTATION_WIDTH: usize = 8;

#[cfg(feature = "babybear")]
pub(crate) const DIGEST_WIDTH: usize = 8;

#[cfg(feature = "babybear")]
pub(crate) const PERMUTATION_WIDTH: usize = 16;
