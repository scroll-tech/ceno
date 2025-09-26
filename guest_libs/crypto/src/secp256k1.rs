/// secp256k1 ECDSA signature recovery.
#[inline]
fn secp256k1_ecrecover(
    sig: &[u8; 64],
    recid: u8,
    msg: &[u8; 32],
) -> Result<[u8; 32], PrecompileError> {
    unimplemented!()
}
