use crate::CenoCryptoError;
use ceno_keccak::{Hasher, Keccak};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

/// secp256k1 ECDSA signature recovery.
#[inline]
pub fn secp256k1_ecrecover(
    sig: &[u8; 64],
    mut recid: u8,
    msg: &[u8; 32],
) -> Result<[u8; 32], CenoCryptoError> {
    // Copied from <https://github.com/alloy-rs/alloy/blob/8e9be40eb0e7c27618db1316989f77f1cfe3accb/crates/consensus/src/crypto.rs#L311-L334>
    // parse signature
    let mut sig = Signature::from_slice(sig.as_slice())?;

    // normalize signature and flip recovery id if needed.
    if let Some(sig_normalized) = sig.normalize_s() {
        sig = sig_normalized;
        recid ^= 1;
    }
    let recid = RecoveryId::from_byte(recid).expect("recovery ID is valid");

    // recover key
    let recovered_key = VerifyingKey::recover_from_prehash(&msg[..], &sig, recid)?;
    // hash it
    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(
        &recovered_key
            .to_encoded_point(/* compress = */ false)
            .as_bytes()[1..],
    );
    hasher.finalize(&mut hash);

    // truncate to 20 bytes
    hash[..12].fill(0);
    Ok(hash)
}
