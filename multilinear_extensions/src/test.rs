use ark_std::test_rng;
use ff::Field;
use goldilocks::{Goldilocks as F, SmallField};

use crate::{
    mle::{ArcDenseMultilinearExtension, DenseMultilinearExtension},
    util::bit_decompose,
    virtual_poly::{build_eq_x_r, VirtualPolynomial},
};

#[test]
fn test_virtual_polynomial_additions() {
    let mut rng = test_rng();
    for nv in 2..5 {
        for num_products in 2..5 {
            let base: Vec<F> = (0..nv).map(|_| F::random(&mut rng)).collect();

            let (a, _a_sum) = VirtualPolynomial::<F>::random(nv, (2, 3), num_products, &mut rng);
            let (b, _b_sum) = VirtualPolynomial::<F>::random(nv, (2, 3), num_products, &mut rng);
            let mut c = a.clone();
            c.merge(&b);

            assert_eq!(
                a.evaluate(base.as_ref()) + b.evaluate(base.as_ref()),
                c.evaluate(base.as_ref())
            );
        }
    }
}

#[test]
fn test_virtual_polynomial_mul_by_mle() {
    let mut rng = test_rng();
    for nv in 2..5 {
        for num_products in 2..5 {
            let base: Vec<F> = (0..nv).map(|_| F::random(&mut rng)).collect();

            let (a, _a_sum) = VirtualPolynomial::<F>::random(nv, (2, 3), num_products, &mut rng);
            let (b, _b_sum) = DenseMultilinearExtension::<F>::random_mle_list(nv, 1, &mut rng);
            let b_mle = b[0].clone();
            let coeff = F::random(&mut rng);
            let b_vp = VirtualPolynomial::new_from_mle(b_mle.clone(), coeff);

            let mut c = a.clone();

            c.mul_by_mle(b_mle, coeff);

            assert_eq!(
                a.evaluate(base.as_ref()) * b_vp.evaluate(base.as_ref()),
                c.evaluate(base.as_ref())
            );
        }
    }
}

#[test]
fn test_eq_xr() {
    let mut rng = test_rng();
    for nv in 4..10 {
        let r: Vec<F> = (0..nv).map(|_| F::random(&mut rng)).collect();
        let eq_x_r = build_eq_x_r(r.as_ref());
        let eq_x_r2 = build_eq_x_r_for_test(r.as_ref());
        assert_eq!(eq_x_r, eq_x_r2);
    }
}

#[test]
fn test_fix_high_variables() {
    let poly = DenseMultilinearExtension::from_evaluations_vec(
        3,
        vec![
            F::from(13),
            F::from(97),
            F::from(11),
            F::from(101),
            F::from(7),
            F::from(103),
            F::from(5),
            F::from(107),
        ],
    );

    let partial_point = vec![F::from(3), F::from(5)];

    let expected1 = DenseMultilinearExtension::from_evaluations_vec(
        2,
        vec![-F::from(17), F::from(127), -F::from(19), F::from(131)],
    );
    let result1 = poly.fix_high_variables(&partial_point[1..]);
    assert_eq!(result1, expected1);

    let expected2 =
        DenseMultilinearExtension::from_evaluations_vec(1, vec![-F::from(23), F::from(139)]);
    let result2 = poly.fix_high_variables(&partial_point);
    assert_eq!(result2, expected2);
}

/// Naive method to build eq(x, r).
/// Only used for testing purpose.
// Evaluate
//      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
// over r, which is
//      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
fn build_eq_x_r_for_test<F: SmallField>(r: &[F]) -> ArcDenseMultilinearExtension<F> {
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
    let one_minus_r: Vec<F> = r.iter().map(|ri| F::ONE - ri).collect();

    let num_var = r.len();
    let mut eval = vec![];

    for i in 0..1 << num_var {
        let mut current_eval = F::ONE;
        let bit_sequence = bit_decompose(i, num_var);

        for (&bit, (ri, one_minus_ri)) in bit_sequence.iter().zip(r.iter().zip(one_minus_r.iter()))
        {
            current_eval *= if bit { *ri } else { *one_minus_ri };
        }
        eval.push(current_eval);
    }

    let mle = DenseMultilinearExtension::from_evaluations_vec(num_var, eval);

    mle.into()
}
