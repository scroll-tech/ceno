// Test double of a curve point via syscall
extern crate ceno_rt;

#[allow(unused_imports)]
use k256::{ProjectivePoint, elliptic_curve::Group};

fn main() {
    #[allow(deprecated)]
    let g = ProjectivePoint::generator();
    let _ = g.double();
}
