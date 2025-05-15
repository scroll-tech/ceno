use ff_ext::{ExtensionField, FromUniformBytes};
use p3::{field::extension::BinomialExtensionField, goldilocks::Goldilocks};
use rand::thread_rng;

type F = Goldilocks;
type E = BinomialExtensionField<F, 2>;

use crate::{
    mle::{ArcMultilinearExtension, MultilinearExtension},
    util::bit_decompose,
    virtual_poly::build_eq_x_r,
};

#[test]
fn test_eq_xr() {
    let mut rng = thread_rng();
    for nv in 4..10 {
        let r: Vec<_> = (0..nv).map(|_| E::random(&mut rng)).collect();
        let eq_x_r = build_eq_x_r(r.as_ref());
        let eq_x_r2 = build_eq_x_r_for_test(r.as_ref());
        assert_eq!(eq_x_r, eq_x_r2);
    }
}

/// Naive method to build eq(x, r).
/// Only used for testing purpose.
// Evaluate
//      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
// over r, which is
//      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
fn build_eq_x_r_for_test<E: ExtensionField>(r: &[E]) -> ArcMultilinearExtension<E> {
    // we build eq(x,r) from its evaluations
    // we want to evaluate eq(x,r) over x \in {0, 1}^num_vars
    // for example, with num_vars = 4, x is a binary vector of 4, then
    //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
    //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
    //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
    //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
    //  ....
    //  1 1 1 1 -> r0       * r1        * r2        * r3
    // we will need 2^num_var evaluations

    // First, we build array for {1 - r_i}
    let one_minus_r: Vec<E> = r.iter().map(|ri| E::ONE - *ri).collect();

    let num_var = r.len();
    let mut eval = vec![];

    for i in 0..1 << num_var {
        let mut current_eval = E::ONE;
        let bit_sequence = bit_decompose(i, num_var);

        for (&bit, (ri, one_minus_ri)) in bit_sequence.iter().zip(r.iter().zip(one_minus_r.iter()))
        {
            current_eval *= if bit { *ri } else { *one_minus_ri };
        }
        eval.push(current_eval);
    }

    let mle = MultilinearExtension::from_evaluations_ext_vec(num_var, eval);

    mle.into()
}
