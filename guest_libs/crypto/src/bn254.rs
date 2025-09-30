use crate::CenoCryptoError;

/// BN254 elliptic curve addition.
pub fn bn254_g1_add(_p1: &[u8], _p2: &[u8]) -> Result<[u8; 64], CenoCryptoError> {
    unimplemented!()
}

/// BN254 elliptic curve scalar multiplication.
pub fn bn254_g1_mul(_point: &[u8], _scalar: &[u8]) -> Result<[u8; 64], CenoCryptoError> {
    unimplemented!()
}

/// BN254 pairing check.
pub fn bn254_pairing_check(_pairs: &[(&[u8], &[u8])]) -> Result<bool, CenoCryptoError> {
    unimplemented!()
}
