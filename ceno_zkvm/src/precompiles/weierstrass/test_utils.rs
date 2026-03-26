use generic_array::GenericArray;
use num_bigint::BigUint;
use rand::{Rng, RngCore, SeedableRng};
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
            let x = gen_biguint(&mut rng, 24);

            let mut y = gen_biguint(&mut rng, 24);
            while y == x {
                y = gen_biguint(&mut rng, 24);
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
            let x = gen_biguint(&mut rng, 24);
            let x_base = base.clone().sw_scalar_mul(&x);
            x_base.to_words_le().try_into().unwrap()
        })
        .collect()
}

#[allow(dead_code)]
pub fn random_decompress_instances<WP: EllipticCurve + WeierstrassParameters>(
    num_instances: usize,
) -> Vec<EllipticCurveDecompressInstance<WP::BaseField>> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let base = SwCurve::<WP>::generator();
    (0..num_instances)
        .map(|_| {
            let x = gen_biguint(&mut rng, 24);
            let sign_bit = rng.gen_bool(0.5);
            let x_base = base.clone().sw_scalar_mul(&x);
            EllipticCurveDecompressInstance {
                sign_bit,
                x: x_base.x,
                old_y_words: GenericArray::default(),
            }
        })
        .collect()
}

fn gen_biguint<R: RngCore>(rng: &mut R, bits: u64) -> BigUint {
    if bits == 0 {
        return BigUint::from(0u8);
    }
    let num_bytes = bits.div_ceil(8) as usize;
    let mut buf = vec![0u8; num_bytes];
    rng.fill_bytes(&mut buf);
    let excess_bits = (num_bytes as u64 * 8) - bits;
    if excess_bits > 0 {
        let mask = 0xffu8 >> excess_bits;
        if let Some(last) = buf.last_mut() {
            *last &= mask;
        }
    }
    BigUint::from_bytes_be(&buf)
}
