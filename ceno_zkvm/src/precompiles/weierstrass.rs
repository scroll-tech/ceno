use generic_array::GenericArray;
use num::BigUint;
use sp1_curves::params::NumWords;

pub mod compact_field_relation;
pub mod test_utils;
pub mod weierstrass_add;
pub mod weierstrass_decompress;
pub mod weierstrass_double;

#[derive(Clone, Default, Debug)]
pub struct EllipticCurveAddInstance<P: NumWords> {
    /// The first point as a list of words.
    pub p: GenericArray<u32, P::WordsCurvePoint>,
    /// The second point as a list of words.
    pub q: GenericArray<u32, P::WordsCurvePoint>,
}

#[derive(Clone, Default, Debug)]
pub struct EllipticCurveDoubleInstance<P: NumWords> {
    /// The point as a list of words.
    pub p: GenericArray<u32, P::WordsCurvePoint>,
}

#[derive(Clone, Debug)]
pub(crate) struct Secp256k1AffineResult {
    pub slope: BigUint,
    pub x3: BigUint,
    pub y3: BigUint,
}

pub(crate) fn batch_multiplicative_inverse(values: &[BigUint], modulus: &BigUint) -> Vec<BigUint> {
    if values.is_empty() {
        return Vec::new();
    }
    let mut prefixes = Vec::with_capacity(values.len());
    let mut product = BigUint::from(1u32);
    for value in values {
        prefixes.push(product.clone());
        if value != &BigUint::from(0u32) {
            product = (product * value) % modulus;
        }
    }
    let mut inverse = product.modpow(&(modulus - 2u32), modulus);
    let mut outputs = vec![BigUint::from(0u32); values.len()];
    for i in (0..values.len()).rev() {
        if values[i] != BigUint::from(0u32) {
            outputs[i] = (&inverse * &prefixes[i]) % modulus;
            inverse = (&inverse * &values[i]) % modulus;
        }
    }
    outputs
}

#[cfg(feature = "gpu")]
pub(crate) fn write_fixed_biguint(dst: &mut [u8], offset: usize, width: usize, value: &BigUint) {
    let bytes = value.to_bytes_le();
    assert!(
        bytes.len() <= width,
        "secp256k1 compact source value exceeds fixed width"
    );
    dst[offset..offset + width].fill(0);
    dst[offset..offset + bytes.len()].copy_from_slice(&bytes);
}

/// Elliptic Curve Point Decompress Event.
///
/// This event is emitted when an elliptic curve point decompression operation is performed.
#[derive(Debug, Clone)]
pub struct EllipticCurveDecompressInstance<P: NumWords> {
    /// The sign bit of the point.
    pub sign_bit: bool,
    /// The x coordinate as a list of bytes.
    pub x: BigUint,
    /// The old value of y.
    pub old_y_words: GenericArray<u32, P::WordsFieldElement>,
}

#[cfg(test)]
mod tests {
    use super::batch_multiplicative_inverse;
    use num::BigUint;

    #[test]
    fn batch_inverse_matches_individual_inversion_and_preserves_zero() {
        let modulus = BigUint::from(17u32);
        let values = [3u32, 0, 5, 16, 0, 1].map(BigUint::from);
        let inverses = batch_multiplicative_inverse(&values, &modulus);

        for (value, inverse) in values.iter().zip(inverses) {
            assert_eq!(inverse, value.modpow(&(&modulus - 2u32), &modulus));
        }
    }
}
