use ark_std::test_rng;
use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::{Goldilocks, GoldilocksExt2};

type E = GoldilocksExt2;

use crate::{
    mle::{ArcDenseMultilinearExtension, DenseMultilinearExtension, MultilinearExtension},
    util::bit_decompose,
    virtual_poly::{VirtualPolynomial, build_eq_x_r},
};

#[test]
fn test_virtual_polynomial_additions() {
    let mut rng = test_rng();
    for nv in 2..5 {
        for num_products in 2..5 {
            let base: Vec<E> = (0..nv).map(|_| E::random(&mut rng)).collect();

            let (a, _a_sum) = VirtualPolynomial::<E>::random(nv, (2, 3), num_products, &mut rng);
            let (b, _b_sum) = VirtualPolynomial::<E>::random(nv, (2, 3), num_products, &mut rng);
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
            let base: Vec<E> = (0..nv).map(|_| E::random(&mut rng)).collect();

            let (a, _a_sum) = VirtualPolynomial::<E>::random(nv, (2, 3), num_products, &mut rng);
            let (b, _b_sum) = DenseMultilinearExtension::<E>::random_mle_list(nv, 1, &mut rng);
            let b_mle = b[0].clone();
            let coeff = Goldilocks::random(&mut rng);
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
        let r: Vec<_> = (0..nv).map(|_| E::random(&mut rng)).collect();
        let eq_x_r = build_eq_x_r(r.as_ref());
        let eq_x_r2 = build_eq_x_r_for_test(r.as_ref());
        assert_eq!(eq_x_r, eq_x_r2);
    }
}

#[test]
fn test_fix_high_variables() {
    let poly: DenseMultilinearExtension<E> =
        DenseMultilinearExtension::from_evaluations_vec(3, vec![
            Goldilocks::from(13),
            Goldilocks::from(97),
            Goldilocks::from(11),
            Goldilocks::from(101),
            Goldilocks::from(7),
            Goldilocks::from(103),
            Goldilocks::from(5),
            Goldilocks::from(107),
        ]);

    let partial_point = vec![E::from(3), E::from(5)];

    let expected1 = DenseMultilinearExtension::from_evaluations_ext_vec(2, vec![
        -E::from(17),
        E::from(127),
        -E::from(19),
        E::from(131),
    ]);
    let result1 = poly.fix_high_variables(&partial_point[1..]);
    assert_eq!(result1, expected1);

    let expected2 =
        DenseMultilinearExtension::from_evaluations_ext_vec(1, vec![-E::from(23), E::from(139)]);
    let result2 = poly.fix_high_variables(&partial_point);
    assert_eq!(result2, expected2);
}

/// Naive method to build eq(x, r).
/// Only used for testing purpose.
// Evaluate
//      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
// over r, which is
//      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
fn build_eq_x_r_for_test<E: ExtensionField>(r: &[E]) -> ArcDenseMultilinearExtension<E> {
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
    let one_minus_r: Vec<E> = r.iter().map(|ri| E::ONE - ri).collect();

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

    let mle = DenseMultilinearExtension::from_evaluations_ext_vec(num_var, eval);

    mle.into()
}
