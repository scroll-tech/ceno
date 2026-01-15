use p256::{
    EncodedPoint,
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
};

/// secp256r1 (P-256) signature verification.
#[inline]
pub fn secp256r1_verify_signature(msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> Option<()> {
    #[cfg(feature = "profiling")]
    ceno_syscall::syscall_phantom_log_pc_cycle("secp256r1_verify_signature start");
    // Can fail only if the input is not exact length.
    let signature = Signature::from_slice(sig).ok()?;
    // Decode the public key bytes (x,y coordinates) using EncodedPoint
    let encoded_point = EncodedPoint::from_untagged_bytes(pk.into());
    // Create VerifyingKey from the encoded point
    let public_key = VerifyingKey::from_encoded_point(&encoded_point).ok()?;

    #[cfg(feature = "profiling")]
    {
        let res = public_key.verify_prehash(msg, &signature).ok();
        ceno_syscall::syscall_phantom_log_pc_cycle("secp256r1_verify_signature end");
        res
    }
    #[cfg(not(feature = "profiling"))]
    {
        public_key.verify_prehash(msg, &signature).ok()
    }
}
