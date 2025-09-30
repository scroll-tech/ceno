use crate::CenoCryptoError;
use ceno_keccak::{Hasher, Keccak};
use ceno_rt::syscalls::{syscall_secp256k1_add, syscall_secp256k1_double};
use k256::{
    AffinePoint, EncodedPoint, Scalar, Secp256k1, U256,
    ecdsa::{Error, RecoveryId, Signature, hazmat::bits2field},
    elliptic_curve::{
        Curve, Field, FieldBytesEncoding, PrimeField,
        bigint::CheckedAdd,
        ops::{Invert, Reduce},
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};

type UntaggedUncompressedPoint = [u8; 64];

#[repr(align(4))]
struct Aligned64([u8; 64]);

/// secp256k1 ECDSA signature recovery.
#[inline]
pub fn secp256k1_ecrecover(
    sig: &[u8; 64],
    recid: u8,
    msg: &[u8; 32],
) -> Result<[u8; 32], CenoCryptoError> {
    // Copied from <https://github.com/alloy-rs/alloy/blob/8e9be40eb0e7c27618db1316989f77f1cfe3accb/crates/consensus/src/crypto.rs#L311-L334>
    let mut signature = Signature::from_slice(sig)?;
    let mut recid = recid;

    // normalize signature and flip recovery id if needed.
    if let Some(sig_normalized) = signature.normalize_s() {
        signature = sig_normalized;
        recid ^= 1;
    }
    let recid = RecoveryId::from_byte(recid).expect("recovery ID is valid");

    // recover key
    let recovered_key = recover_from_prehash_unchecked(&msg[..], &signature, recid)?;

    let mut hasher = Keccak::v256();
    hasher.update(&recovered_key);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    // truncate to 20 bytes
    hash[..12].fill(0);
    Ok(hash)
}

/// Copied from <https://github.com/RustCrypto/signatures/blob/89232d6a962a199fd8211a117db74408353e4383/ecdsa/src/recovery.rs#L278-L316>
/// Modified to use ceno syscalls
fn recover_from_prehash_unchecked(
    prehash: &[u8],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> k256::ecdsa::signature::Result<UntaggedUncompressedPoint> {
    let (r, s) = signature.split_scalars();
    let z = <Scalar as Reduce<U256>>::reduce_bytes(&bits2field::<Secp256k1>(prehash)?);

    let mut r_bytes = r.to_repr();
    if recovery_id.is_x_reduced() {
        let decoded: U256 = FieldBytesEncoding::<Secp256k1>::decode_field_bytes(&r_bytes);
        match decoded.checked_add(&Secp256k1::ORDER).into_option() {
            Some(restored) => {
                r_bytes = <U256 as FieldBytesEncoding<Secp256k1>>::encode_field_bytes(&restored)
            }
            // No reduction should happen here if r was reduced
            None => return Err(Error::new()),
        };
    }

    // Modified part: use ceno syscall to decompress point
    // Original:
    // let R = AffinePoint::decompress(&r_bytes, u8::from(recovery_id.is_y_odd()).into());
    let r_point = {
        let mut buf = Aligned64([0u8; 64]);
        buf.0[..32].copy_from_slice(&r_bytes);

        // SAFETY:
        // [x] The input array should be 64 bytes long, with the first 32 bytes containing the X coordinate in
        //   big-endian format.
        // [x] The caller must ensure that `point` is valid pointer to data that is aligned along a four byte
        // boundary.
        ceno_rt::syscalls::syscall_secp256k1_decompress(&mut buf.0, recovery_id.is_y_odd());
        let point = EncodedPoint::from_untagged_bytes((&buf.0).into());
        AffinePoint::from_encoded_point(&point)
    };

    let Some(r_point) = r_point.into_option() else {
        return Err(Error::new());
    };

    // TODO: scalar syscalls
    let r_inv = *r.invert();
    let u1 = -(r_inv * z);
    let u2 = r_inv * *s;

    // Original:
    // ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &u1, &r_point, &u2)
    // Equivalent to: G * u1 + R * u2
    let pk_words = match (u1 == Scalar::ZERO, u2 == Scalar::ZERO) {
        (true, true) => return Err(Error::new()),
        (true, false) => secp256k1_mul(&r_point, u2),
        (false, true) => secp256k1_mul(&AffinePoint::GENERATOR, u1),
        (false, false) => {
            let mut p1 = secp256k1_mul(&AffinePoint::GENERATOR, u1);
            let p2 = secp256k1_mul(&r_point, u2);
            syscall_secp256k1_add(&mut p1, &p2);
            p1
        }
    };

    // FIXME: do we really need to verify the signature again here?
    // Original:
    // let vk = VerifyingKey::from_affine(pk.to_affine())?;
    // // Ensure signature verifies with the recovered key
    // vk.verify_prehash(prehash, signature)?;

    Ok(words_to_untagged_bytes(pk_words))
}

fn secp256k1_mul(point: &AffinePoint, scalar: Scalar) -> [u32; 16] {
    let mut base = point_to_words(point.to_encoded_point(false));
    let mut acc: [u32; 16] = [0; 16];
    let mut acc_init = false;

    let mut k = scalar;
    while !k.is_zero_vartime() {
        if bool::from(k.is_odd()) {
            if !acc_init {
                acc = base;
                acc_init = true;
            } else {
                // SAFETY: syscall requires point not to be infinity
                let tmp = base;
                syscall_secp256k1_add(&mut acc, &tmp)
            }
        }
        syscall_secp256k1_double(&mut base);
        k = k.shr_vartime(1);
    }

    acc
}

/// `bytes` is expected to contain the uncompressed representation of
/// a curve point, as described in https://docs.rs/secp/latest/secp/struct.Point.html
///
/// The return value is an array of words compatible with the sp1 syscall for `add` and `double`
/// Notably, these words should encode the X and Y coordinates of the point
/// in "little endian" and not "big endian" as is the case of secp
fn point_to_words(point: EncodedPoint) -> [u32; 16] {
    debug_assert!(!point.is_compressed());
    // ignore the tag byte (specific to the secp repr.)
    let mut bytes: [u8; 64] = point.as_bytes()[1..].try_into().unwrap();

    // Reverse the order of bytes for each coordinate
    bytes[0..32].reverse();
    bytes[32..].reverse();
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * (i + 1)].try_into().unwrap()))
}

fn words_to_untagged_bytes(words: [u32; 16]) -> UntaggedUncompressedPoint {
    let mut bytes = [0u8; 64];
    for i in 0..16 {
        bytes[4 * i..4 * (i + 1)].copy_from_slice(&words[i].to_le_bytes());
    }
    // Reverse the order of bytes for each coordinate
    bytes[..32].reverse();
    bytes[32..].reverse();
    bytes
}
