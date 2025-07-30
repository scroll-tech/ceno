#[cfg(not(feature = "babybear"))]
pub const DIGEST_WIDTH: usize = 4;

#[cfg(feature = "babybear")]
pub const DIGEST_WIDTH: usize = 8;
