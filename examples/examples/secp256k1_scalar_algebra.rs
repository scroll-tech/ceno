extern crate ceno_rt;

use k256::{Scalar, elliptic_curve::Field};

fn main() {
    // test scalar invert
    let s = Scalar::random(rand::thread_rng());
    let s_inv = s.invert().unwrap();
    assert_eq!(s * s_inv, Scalar::ONE);
}
