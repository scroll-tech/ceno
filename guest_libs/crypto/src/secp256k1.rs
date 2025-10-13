use crate::CenoCryptoError;

/// secp256k1 ECDSA signature recovery.
#[inline]
pub fn secp256k1_ecrecover(
    _sig: &[u8; 64],
    _recid: u8,
    _msg: &[u8; 32],
) -> Result<[u8; 32], CenoCryptoError> {
    unimplemented!()
}
