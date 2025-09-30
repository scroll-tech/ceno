use generic_array::GenericArray;
use num::bigint::RandBigInt;
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
            EllipticCurveDecompressInstance {
                sign_bit,
                x: x_base.x,
            }
        })
        .collect()
}
