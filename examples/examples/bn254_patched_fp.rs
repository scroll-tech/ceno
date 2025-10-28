extern crate ceno_rt;

use bn::{Fq, Fq2};
use rand::{SeedableRng, rngs::StdRng};

fn to_unpatched_fq(val: Fq) -> substrate_bn::Fq {
    substrate_bn::Fq::from_u256(substrate_bn::arith::U256(val.into_u256().0)).unwrap()
}

fn to_unpatched_fq2(val: Fq2) -> substrate_bn::Fq2 {
    substrate_bn::Fq2::new(
        to_unpatched_fq(val.real()),
        to_unpatched_fq(val.imaginary()),
    )
}

fn main() {
    let mut a = Fq::one();
    let mut b = Fq::one();
    let seed = [0u8; 32];
    let mut rng = StdRng::from_seed(seed);
    const RUNS: usize = 10;

    for _ in 0..RUNS {
        let sum = a + b;
        let expected_sum = to_unpatched_fq(a) + to_unpatched_fq(b);
        assert_eq!(to_unpatched_fq(sum), expected_sum);

        a = Fq::random(&mut rng);
        b = Fq::random(&mut rng);
    }

    let mut a = Fq2::one();
    let mut b = Fq2::one();

    for _ in 0..RUNS {
        let sum = a + b;
        let expected_sum = to_unpatched_fq2(a) + to_unpatched_fq2(b);
        assert_eq!(to_unpatched_fq2(sum), expected_sum);

        a = Fq2::new(Fq::random(&mut rng), Fq::random(&mut rng));
        b = Fq2::new(Fq::random(&mut rng), Fq::random(&mut rng));
    }
}
