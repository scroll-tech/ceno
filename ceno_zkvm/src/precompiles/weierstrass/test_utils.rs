use generic_array::GenericArray;
use num::{BigUint, bigint::RandBigInt};
use rand::{Rng, SeedableRng};
use sp1_curves::{
    EllipticCurve,
    params::NumWords,
    weierstrass::{SwCurve, WeierstrassParameters},
};

use crate::precompiles::weierstrass::EllipticCurveDecompressInstance;

pub fn random_point_pairs<WP: WeierstrassParameters>(
    num_instances: usize,
) -> Vec<[GenericArray<u32, <WP::BaseField as NumWords>::WordsCurvePoint>; 2]> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let base = SwCurve::<WP>::generator();
    (0..num_instances)
        .map(|_| {
            let x = rng.gen_biguint(24);

            let mut y = rng.gen_biguint(24);
            while y == x {
                y = rng.gen_biguint(24);
            }

            let x_base = base.clone().sw_scalar_mul(&x);
            let y_base = base.clone().sw_scalar_mul(&y);
            [
                x_base.to_words_le().try_into().unwrap(),
                y_base.to_words_le().try_into().unwrap(),
            ]
        })
        .collect()
}

pub fn random_points<WP: WeierstrassParameters>(
    num_instances: usize,
) -> Vec<GenericArray<u32, <WP::BaseField as NumWords>::WordsCurvePoint>> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let base = SwCurve::<WP>::generator();
    (0..num_instances)
        .map(|_| {
            let x = rng.gen_biguint(24);
            let x_base = base.clone().sw_scalar_mul(&x);
            x_base.to_words_le().try_into().unwrap()
        })
        .collect()
}

pub fn random_decompress_instances<WP: EllipticCurve + WeierstrassParameters>(
    num_instances: usize,
) -> Vec<EllipticCurveDecompressInstance> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let base = SwCurve::<WP>::generator();
    (0..num_instances)
        .map(|_| {
            let x = rng.gen_biguint(24);
            let sign_bit = rng.gen_bool(0.5);
            let x_base = base.clone().sw_scalar_mul(&x);
            let x_vec = x_base.to_words_le();
            let x_bytes = words_to_bytes_le_vec(&x_vec);
            EllipticCurveDecompressInstance {
                sign_bit,
                x: BigUint::from_bytes_le(&x_bytes),
            }
        })
        .collect()
}

/// Converts a slice of words to a byte vector in little endian.
fn words_to_bytes_le_vec(words: &[u32]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().into_iter())
        .collect::<Vec<_>>()
}
