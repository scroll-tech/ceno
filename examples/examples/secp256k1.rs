
extern crate ceno_rt;

use k256::{ProjectivePoint, Scalar};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::ops::MulByGenerator;

fn main() {
    let scalar = Scalar::from(5u64);
    let a = ProjectivePoint::mul_by_generator(&scalar);
    let _ = a.double(); // -> syscall_secp256k1_double
    
    let scalar = Scalar::from(6u64);
    let b = ProjectivePoint::mul_by_generator(&scalar);
    let _ = a + b; // -> syscall_secp256k1_add
}
