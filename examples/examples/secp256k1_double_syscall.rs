// Test double of a curve point via syscall
extern crate ceno_rt;
use k256::ProjectivePoint;

fn main() {
    let a = ProjectivePoint::generator();
    let _ = a.double();
}
