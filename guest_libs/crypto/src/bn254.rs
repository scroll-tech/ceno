//! Copied from <https://github.com/bluealloy/revm/blob/10ff66da1576a3532db657d7b953abcd59ec44a3/crates/precompile/src/bn254/substrate.rs>
//! under MIT license.
use crate::CenoCryptoError;
use bn::{AffineG1, AffineG2, Fq, Fq2, G1, G2, Group, Gt};
use std::vec::Vec;

/// FQ_LEN specifies the number of bytes needed to represent an
/// Fq element. This is an element in the base field of BN254.
///
/// Note: The base field is used to define G1 and G2 elements.
const FQ_LEN: usize = 32;

/// SCALAR_LEN specifies the number of bytes needed to represent an Fr element.
/// This is an element in the scalar field of BN254.
const SCALAR_LEN: usize = 32;

/// FQ2_LEN specifies the number of bytes needed to represent an
/// Fq^2 element.
///
/// Note: This is the quadratic extension of Fq, and by definition
/// means we need 2 Fq elements.
const FQ2_LEN: usize = 2 * FQ_LEN;

/// G1_LEN specifies the number of bytes needed to represent a G1 element.
///
/// Note: A G1 element contains 2 Fq elements.
const G1_LEN: usize = 2 * FQ_LEN;
/// G2_LEN specifies the number of bytes needed to represent a G2 element.
///
/// Note: A G2 element contains 2 Fq^2 elements.
const G2_LEN: usize = 2 * FQ2_LEN;

/// Input length for the add operation.
/// `ADD` takes two uncompressed G1 points (64 bytes each).
pub const ADD_INPUT_LEN: usize = 2 * G1_LEN;

/// Input length for the multiplication operation.
/// `MUL` takes an uncompressed G1 point (64 bytes) and scalar (32 bytes).
pub const MUL_INPUT_LEN: usize = G1_LEN + SCALAR_LEN;

/// Pair element length.
/// `PAIR` elements are composed of an uncompressed G1 point (64 bytes) and an uncompressed G2 point
/// (128 bytes).
pub const PAIR_ELEMENT_LEN: usize = G1_LEN + G2_LEN;

/// Reads a single `Fq` field element from the input slice.
///
/// Takes a byte slice and attempts to interpret the first 32 bytes as an
/// elliptic curve field element. Returns an error if the bytes do not form
/// a valid field element.
///
/// # Panics
///
/// Panics if the input is not at least 32 bytes long.
#[inline]
fn read_fq(input: &[u8]) -> Result<Fq, CenoCryptoError> {
    Fq::from_slice(&input[..FQ_LEN]).map_err(|_| CenoCryptoError::Bn254FieldPointNotAMember)
}
/// Reads a Fq2 (quadratic extension field element) from the input slice.
///
/// Parses two consecutive Fq field elements as the real and imaginary parts
/// of an Fq2 element.
/// The second component is parsed before the first, ie if a we represent an
/// element in Fq2 as (x,y) -- `y` is parsed before `x`
///
/// # Panics
///
/// Panics if the input is not at least 64 bytes long.
#[inline]
fn read_fq2(input: &[u8]) -> Result<Fq2, CenoCryptoError> {
    let y = read_fq(&input[..FQ_LEN])?;
    let x = read_fq(&input[FQ_LEN..2 * FQ_LEN])?;
    Ok(Fq2::new(x, y))
}

/// Creates a new `G1` point from the given `x` and `y` coordinates.
///
/// Constructs a point on the G1 curve from its affine coordinates.
///
/// Note: The point at infinity which is represented as (0,0) is
/// handled specifically because `AffineG1` is not capable of
/// representing such a point.
/// In particular, when we convert from `AffineG1` to `G1`, the point
/// will be (0,0,1) instead of (0,1,0)
#[inline]
fn new_g1_point(px: Fq, py: Fq) -> Result<G1, CenoCryptoError> {
    if px == Fq::zero() && py == Fq::zero() {
        Ok(G1::zero())
    } else {
        AffineG1::new(px, py)
            .map(Into::into)
            .map_err(|_| CenoCryptoError::Bn254AffineGFailedToCreate)
    }
}

/// Creates a new `G2` point from the given Fq2 coordinates.
///
/// G2 points in BN254 are defined over a quadratic extension field Fq2.
/// This function takes two Fq2 elements representing the x and y coordinates
/// and creates a G2 point.
///
/// Note: The point at infinity which is represented as (0,0) is
/// handled specifically because `AffineG2` is not capable of
/// representing such a point.
/// In particular, when we convert from `AffineG2` to `G2`, the point
/// will be (0,0,1) instead of (0,1,0)
#[inline]
fn new_g2_point(x: Fq2, y: Fq2) -> Result<G2, CenoCryptoError> {
    let point = if x.is_zero() && y.is_zero() {
        G2::zero()
    } else {
        G2::from(AffineG2::new(x, y).map_err(|_| CenoCryptoError::Bn254AffineGFailedToCreate)?)
    };

    Ok(point)
}

/// Reads a G1 point from the input slice.
///
/// Parses a G1 point from a byte slice by reading two consecutive field elements
/// representing the x and y coordinates.
///
/// # Panics
///
/// Panics if the input is not at least 64 bytes long.
#[inline]
pub fn read_g1_point(input: &[u8]) -> Result<G1, CenoCryptoError> {
    let px = read_fq(&input[0..FQ_LEN])?;
    let py = read_fq(&input[FQ_LEN..2 * FQ_LEN])?;
    new_g1_point(px, py)
}

/// Encodes a G1 point into a byte array.
///
/// Converts a G1 point in Jacobian coordinates to affine coordinates and
/// serializes the x and y coordinates as big-endian byte arrays.
///
/// Note: If the point is the point at infinity, this function returns
/// all zeroes.
#[inline]
pub fn encode_g1_point(point: G1) -> [u8; G1_LEN] {
    let mut output = [0u8; G1_LEN];

    if let Some(point_affine) = AffineG1::from_jacobian(point) {
        point_affine
            .x()
            .to_big_endian(&mut output[..FQ_LEN])
            .unwrap();
        point_affine
            .y()
            .to_big_endian(&mut output[FQ_LEN..])
            .unwrap();
    }

    output
}

/// Reads a G2 point from the input slice.
///
/// Parses a G2 point from a byte slice by reading four consecutive Fq field elements
/// representing the two Fq2 coordinates (x and y) of the G2 point.
///
/// # Panics
///
/// Panics if the input is not at least 128 bytes long.
#[inline]
pub fn read_g2_point(input: &[u8]) -> Result<G2, CenoCryptoError> {
    let ba = read_fq2(&input[0..FQ2_LEN])?;
    let bb = read_fq2(&input[FQ2_LEN..2 * FQ2_LEN])?;
    new_g2_point(ba, bb)
}

/// Reads a scalar from the input slice
///
/// Note: The scalar does not need to be canonical.
///
/// # Panics
///
/// If `input.len()` is not equal to [`SCALAR_LEN`].
#[inline]
pub fn read_scalar(input: &[u8]) -> bn::Fr {
    assert_eq!(
        input.len(),
        SCALAR_LEN,
        "unexpected scalar length. got {}, expected {SCALAR_LEN}",
        input.len()
    );
    // `Fr::from_slice` can only fail when the length is not `SCALAR_LEN`.
    bn::Fr::from_slice(input).unwrap()
}

/// Performs point addition on two G1 points.
#[inline]
pub fn g1_point_add(p1_bytes: &[u8], p2_bytes: &[u8]) -> Result<[u8; 64], CenoCryptoError> {
    let p1 = read_g1_point(p1_bytes)?;
    let p2 = read_g1_point(p2_bytes)?;
    let result = p1 + p2;
    Ok(encode_g1_point(result))
}

/// Performs a G1 scalar multiplication.
#[inline]
pub fn g1_point_mul(point_bytes: &[u8], fr_bytes: &[u8]) -> Result<[u8; 64], CenoCryptoError> {
    let p = read_g1_point(point_bytes)?;
    let fr = read_scalar(fr_bytes);
    let result = p * fr;
    Ok(encode_g1_point(result))
}

/// pairing_check performs a pairing check on a list of G1 and G2 point pairs and
/// returns true if the result is equal to the identity element.
///
/// Note: If the input is empty, this function returns true.
/// This is different to EIP2537 which disallows the empty input.
#[inline]
pub fn pairing_check(pairs: &[(&[u8], &[u8])]) -> Result<bool, CenoCryptoError> {
    let mut parsed_pairs = Vec::with_capacity(pairs.len());

    for (g1_bytes, g2_bytes) in pairs {
        let g1 = read_g1_point(g1_bytes)?;
        let g2 = read_g2_point(g2_bytes)?;

        // Skip pairs where either point is at infinity
        if !g1.is_zero() && !g2.is_zero() {
            parsed_pairs.push((g1, g2));
        }
    }

    if parsed_pairs.is_empty() {
        return Ok(true);
    }

    Ok(bn::pairing_batch(&parsed_pairs) == Gt::one())
}
