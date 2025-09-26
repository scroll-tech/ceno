/// BN254 elliptic curve addition.
pub fn bn254_g1_add(p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileError> {
    unimplemented!()
}

/// BN254 elliptic curve scalar multiplication.
pub fn bn254_g1_mul(point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileError> {
    unimplemented!()
}

/// BN254 pairing check.
pub fn bn254_pairing_check(pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileError> {
    unimplemented!()
}
