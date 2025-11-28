// Test double of a curve point via syscall
extern crate ceno_rt;

use k256::{
    Scalar,
    elliptic_curve::{PrimeField, rand_core::RngCore},
};

fn main() {
    let mut bytes = [255u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] &= 0x1F; // ensure in scalar field range
    let s = Scalar::from_repr(bytes.into()).unwrap();
    let s_inv = s.invert().unwrap();
    assert_eq!(s * s_inv, Scalar::ONE);
}
