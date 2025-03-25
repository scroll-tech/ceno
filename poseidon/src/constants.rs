#[cfg(not(feature = "babybear"))]
pub(crate) const DIGEST_WIDTH: usize = 4;

#[cfg(feature = "babybear")]
pub(crate) const DIGEST_WIDTH: usize = 8;
