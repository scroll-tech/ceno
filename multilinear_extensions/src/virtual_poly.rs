use std::{cmp::max, collections::HashMap, marker::PhantomData, mem::MaybeUninit, sync::Arc};

use crate::{
    Expression, WitnessId,
    macros::{entered_span, exit_span},
    mle::{ArcMultilinearExtension, MultilinearExtension},
    monomial::Term,
    util::{bit_decompose, create_uninit_vec, max_usable_threads},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use p3::field::Field;
use rand::Rng;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub type MonomialTermsType<'a, E> =
    Vec<Term<Either<<E as ExtensionField>::BaseField, E>, Expression<E>>>;

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct MonomialTerms<E: ExtensionField> {
    pub terms: Vec<Term<Either<E::BaseField, E>, usize>>,
}

#[rustfmt::skip]
/// A virtual polynomial is a sum of products of multilinear polynomials;
/// where the multilinear polynomials are stored via their multilinear
/// extensions:  `(coefficient, MultilinearExtension)`
///
/// * Number of products n = `polynomial.products.len()`,
/// * Number of multiplicands of ith product m_i =
///   `polynomial.products[i].1.len()`,
/// * Coefficient of ith product c_i = `polynomial.products[i].0`
///
/// The resulting polynomial is
///
/// $$ \sum_{i=0}^{n} c_i \cdot \prod_{j=0}^{m_i} P_{ij} $$
///
/// Example:
///  f = c0 * f0 * f1 * f2 + c1 * f3 * f4
/// where f0 ... f4 are multilinear polynomials
///
/// - flattened_ml_extensions stores the multilinear extension representation of
///   f0, f1, f2, f3 and f4
/// - products is
///   \ [
///   (c0, \[0, 1, 2\]),
///   (c1, \[3, 4\])
///   \ ]
/// - raw_pointers_lookup_table maps fi to i
///
#[derive(Default, Clone)]
pub struct VirtualPolynomial<'a, E: ExtensionField> {
    /// Aux information about the multilinear polynomial
    pub aux_info: VPAuxInfo<E>,
    //  monomial_form_formula
    pub products: Vec<MonomialTerms<E>>,
    /// Stores multilinear extensions in which product multiplicand can refer
    /// to.
    pub flattened_ml_extensions: Vec<ArcMultilinearExtension<'a, E>>,
    /// Pointers to the above poly extensions
    raw_pointers_lookup_table: HashMap<usize, usize>,


}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Auxiliary information about the multilinear polynomial
pub struct VPAuxInfo<E> {
    /// max number of multiplicands in each product
    pub max_degree: usize,
    /// max number of variables of the polynomial
    pub max_num_variables: usize,
    /// Associated field
    #[doc(hidden)]
    pub phantom: PhantomData<E>,
}

impl<'a, E: ExtensionField> VirtualPolynomial<'a, E> {
    /// Creates an empty virtual polynomial with `max_num_variables`.
    pub fn new(max_num_variables: usize) -> Self {
        VirtualPolynomial {
            aux_info: VPAuxInfo {
                max_degree: 0,
                max_num_variables,
                phantom: PhantomData,
            },
            products: Vec::new(),
            flattened_ml_extensions: Vec::new(),
            raw_pointers_lookup_table: HashMap::new(),
        }
    }

    /// Creates an new virtual polynomial from a MLE and scalar.
    pub fn new_from_mle(mle: ArcMultilinearExtension<'a, E>, scalar: E) -> Self {
        Self::new_from_product(vec![mle], scalar)
    }

    /// Creates an new virtual polynomial from product and scalar.
    pub fn new_from_product(mle: Vec<ArcMultilinearExtension<'a, E>>, scalar: E) -> Self {
        assert!(!mle.is_empty());
        assert!(
            mle.iter().map(|mle| mle.num_vars()).all_equal(),
            "all product must got same num_vars"
        );
        let mut poly = VirtualPolynomial::new(mle[0].num_vars());
        let indexes = mle
            .into_iter()
            .map(|mle| Expression::WitIn(poly.register_mle(mle) as WitnessId))
            .collect_vec();
        poly.add_monomial_terms(vec![Term {
            scalar: Either::Right(scalar),
            product: indexes,
        }]);
        poly
    }

    /// registers a multilinear extension (MLE) in flat storage and tracks its pointer to ensure uniqueness.
    ///
    /// assigns a unique index to the given `mle` and asserts that it hasn't been registered before
    /// by checking its raw pointer.
    ///
    /// panics if the same MLE (by pointer) is registered more than once.
    pub fn register_mle(&mut self, mle: ArcMultilinearExtension<'a, E>) -> usize {
        let mle_ptr: usize = Arc::as_ptr(&mle) as *const () as usize;
        let curr_index = self.flattened_ml_extensions.len();
        self.flattened_ml_extensions.push(mle);
        let prev = self.raw_pointers_lookup_table.insert(mle_ptr, curr_index);
        assert!(prev.is_none(), "duplicate mle_ptr: {}", mle_ptr);
        curr_index
    }

    pub(crate) fn add_monomial_terms(&mut self, monomial_terms: MonomialTermsType<'a, E>) {
        let terms = monomial_terms
            .into_iter()
            .map(|Term { scalar, product }| {
                assert!(
                    !product.is_empty(),
                    "some term product is empty scalar {scalar}, product {product:?}",
                );
                // sanity check: all mle in product must have same num_vars()
                assert!(
                    product
                        .iter()
                        .map(|expr| {
                            match expr {
                                Expression::WitIn(witin_id) => {
                                    self.flattened_ml_extensions[*witin_id as usize].num_vars()
                                }
                                e => unimplemented!("unimplemented {:?}", e),
                            }
                        })
                        .all_equal()
                );

                self.aux_info.max_degree = max(self.aux_info.max_degree, product.len());
                let mut indexed_product = Vec::with_capacity(product.len());

                for expr in product {
                    match expr {
                        Expression::WitIn(witin_id) => {
                            indexed_product.push(witin_id as usize);
                        }
                        _ => unimplemented!(),
                    }
                }
                Term {
                    scalar,
                    product: indexed_product,
                }
            })
            .collect_vec();

        self.products.push(MonomialTerms { terms });
    }

    /// Evaluate the virtual polynomial at point `point`.
    /// Returns an error if point.len() does not match `num_variables`.
    pub fn evaluate(&self, point: &[E]) -> E {
        let start = entered_span!("evaluation");

        assert_eq!(
            self.aux_info.max_num_variables,
            point.len(),
            "wrong number of variables {} vs {}",
            self.aux_info.max_num_variables,
            point.len()
        );

        let evals: Vec<E> = self
            .flattened_ml_extensions
            .iter()
            .map(|x| x.evaluate(&point[0..x.num_vars()]))
            .collect();

        let res = self
            .products
            .iter()
            .map(| MonomialTerms { terms }| {
                terms
                    .iter()
                    .map(|Term { scalar, product }| {
                        either::for_both!(scalar, c => product.iter().map(|&i| evals[i]).product::<E>() * *c)
                    })
                    .sum()
            })
            .sum();

        exit_span!(start);
        res
    }

    /// Sample a random virtual polynomial, return the polynomial and its sum.
    pub fn random<R: Rng>(
        nv: &[usize],
        num_multiplicands_range: (usize, usize),
        num_products: usize,
        rng: &mut R,
    ) -> (Self, E) {
        let start = entered_span!("sample random virtual polynomial");

        let mut sum = E::ZERO;
        let mut poly = VirtualPolynomial::new(*nv.iter().max().unwrap());
        for nv in nv {
            for _ in 0..num_products {
                let num_multiplicands =
                    rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
                let (product, product_sum) =
                    MultilinearExtension::random_mle_list(*nv, num_multiplicands, rng);
                let product = product.into_iter().map(Arc::new).collect_vec();
                let product: Vec<Expression<E>> = product
                    .into_iter()
                    .map(|mle| mle as _)
                    .map(|mle: Arc<MultilinearExtension<'_, _>>| {
                        Expression::WitIn(poly.register_mle(mle) as WitnessId)
                    })
                    .collect_vec();
                let scalar = E::random(&mut *rng);
                poly.add_monomial_terms(vec![Term {
                    scalar: Either::Right(scalar),
                    product,
                }]);
                sum += product_sum * scalar;
            }
        }

        exit_span!(start);
        (poly, sum)
    }

    /// creates a read-only view of the current virtual polynomial by converting all
    /// underlying multilinear extensions into borrowed views. This avoids cloning
    /// the full data while preserving structure.
    ///
    /// returns a new `VirtualPolynomial` containing views into the original data.
    pub fn as_view(&'a self) -> Self {
        let flattened_ml_extensions_view = self
            .flattened_ml_extensions
            .iter()
            .map(|mle| mle.as_view().into())
            .collect_vec();
        let mut new_poly = VirtualPolynomial {
            aux_info: self.aux_info.clone(),
            products: self.products.clone(),
            flattened_ml_extensions: vec![],
            raw_pointers_lookup_table: Default::default(),
        };
        flattened_ml_extensions_view.into_iter().for_each(|mle| {
            let _ = new_poly.register_mle(mle);
        });
        new_poly
    }

    /// Print out the evaluation map for testing. Panic if the num_vars() > 5.
    pub fn print_evals(&self) {
        if self.aux_info.max_num_variables > 5 {
            panic!("this function is used for testing only. cannot print more than 5 num_vars()")
        }
        for i in 0..1 << self.aux_info.max_num_variables {
            let point = bit_decompose(i, self.aux_info.max_num_variables);
            let point_fr: Vec<E> = point.iter().map(|&x| E::from_bool(x)).collect();
            println!("{} {:?}", i, self.evaluate(point_fr.as_ref()))
        }
        println!()
    }
}

/// Evaluate eq polynomial.
pub fn eq_eval<F: Field>(x: &[F], y: &[F]) -> F {
    assert_eq!(x.len(), y.len(), "x and y have different length");

    let start = entered_span!("eq_eval");
    let mut res = F::ONE;
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        let xi_yi = xi * yi;
        res *= xi_yi + xi_yi - xi - yi + F::ONE;
    }
    exit_span!(start);
    res
}

/// This function build the eq(x, r) polynomial for any given r.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r_sequential<E: ExtensionField>(r: &[E]) -> ArcMultilinearExtension<E> {
    let evals = build_eq_x_r_vec_sequential(r);
    let mle = MultilinearExtension::from_evaluations_ext_vec(r.len(), evals);

    mle.into()
}
/// This function build the eq(x, r) polynomial for any given r, and output the
/// evaluation of eq(x, r) in its vector form.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))

#[tracing::instrument(
    skip_all,
    name = "multilinear_extensions::build_eq_x_r_vec_sequential_with_scalar"
)]
pub fn build_eq_x_r_vec_sequential_with_scalar<E: ExtensionField>(r: &[E], scalar: E) -> Vec<E> {
    // avoid unnecessary allocation
    if r.is_empty() {
        return vec![scalar];
    }
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

    let mut evals = create_uninit_vec(1 << r.len());
    build_eq_x_r_helper_sequential(r, &mut evals, scalar);

    unsafe { std::mem::transmute(evals) }
}

#[inline]
#[tracing::instrument(skip_all, name = "multilinear_extensions::build_eq_x_r_vec_sequential")]
pub fn build_eq_x_r_vec_sequential<E: ExtensionField>(r: &[E]) -> Vec<E> {
    build_eq_x_r_vec_sequential_with_scalar(r, E::ONE)
}

/// A helper function to build eq(x, r)*init via dynamic programing tricks.
/// This function takes 2^num_var iterations, and per iteration with 1 multiplication.
fn build_eq_x_r_helper_sequential<E: ExtensionField>(r: &[E], buf: &mut [MaybeUninit<E>], init: E) {
    buf[0] = MaybeUninit::new(init);

    for (i, r) in r.iter().rev().enumerate() {
        let next_size = 1 << (i + 1);
        // suppose at the previous step we processed buf [0..size]
        // for the current step we are populating new buf[0..2*size]
        // for j travese 0..size
        // buf[2*j + 1] = r * buf[j]
        // buf[2*j] = (1 - r) * buf[j]
        (0..next_size).step_by(2).rev().for_each(|index| {
            let prev_val = unsafe { buf[index >> 1].assume_init() };
            let tmp = *r * prev_val;
            buf[index + 1] = MaybeUninit::new(tmp);
            buf[index] = MaybeUninit::new(prev_val - tmp);
        });
    }
}

/// This function build the eq(x, r) polynomial for any given r.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r<E: ExtensionField>(r: &[E]) -> ArcMultilinearExtension<E> {
    let evals = build_eq_x_r_vec(r);
    let mle = MultilinearExtension::from_evaluations_ext_vec(r.len(), evals);

    mle.into()
}
/// This function build the eq(x, r) polynomial for any given r, and output the
/// evaluation of eq(x, r) in its vector form.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))

#[tracing::instrument(skip_all, name = "multilinear_extensions::build_eq_x_r_vec")]
pub fn build_eq_x_r_vec<E: ExtensionField>(r: &[E]) -> Vec<E> {
    // avoid unnecessary allocation
    if r.is_empty() {
        return vec![E::ONE];
    }
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
    let nthreads = max_usable_threads();
    let nbits = nthreads.trailing_zeros() as usize;
    assert_eq!(1 << nbits, nthreads);

    if r.len() < nbits {
        build_eq_x_r_vec_sequential(r)
    } else {
        let eq_ts = build_eq_x_r_vec_sequential(&r[(r.len() - nbits)..]);
        let mut ret = create_uninit_vec(1 << r.len());

        // eq(x, r) = eq(x_lo, r_lo) * eq(x_hi, r_hi)
        // where rlen = r.len(), x_lo = x[0..rlen-nbits], x_hi = x[rlen-nbits..]
        //  r_lo = r[0..rlen-nbits] and r_hi = r[rlen-nbits..]
        // each thread is associated with x_hi, and it will computes the subset
        // { eq(x_lo, r_lo) * eq(x_hi, r_hi) } whose cardinality equals to 2^{rlen-nbits}
        ret.par_chunks_mut(1 << (r.len() - nbits))
            .zip((0..nthreads).into_par_iter())
            .for_each(|(chunks, tid)| {
                let eq_t = eq_ts[tid];

                build_eq_x_r_helper_sequential(&r[..(r.len() - nbits)], chunks, eq_t);
            });
        unsafe { std::mem::transmute::<Vec<MaybeUninit<E>>, Vec<E>>(ret) }
    }
}

#[tracing::instrument(
    skip_all,
    name = "multilinear_extensions::build_eq_x_r_vec_with_scalar"
)]
pub fn build_eq_x_r_vec_with_scalar<E: ExtensionField>(r: &[E], scalar: E) -> Vec<E> {
    // avoid unnecessary allocation
    if r.is_empty() {
        return vec![scalar];
    }
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
    let nthreads = max_usable_threads();
    let nbits = nthreads.trailing_zeros() as usize;
    assert_eq!(1 << nbits, nthreads);

    let mut evals = create_uninit_vec(1 << r.len());
    if r.len() < nbits {
        build_eq_x_r_helper_sequential(r, &mut evals, scalar);
    } else {
        let eq_ts = build_eq_x_r_vec_sequential_with_scalar(&r[(r.len() - nbits)..], scalar);

        // eq(x, r) = eq(x_lo, r_lo) * eq(x_hi, r_hi)
        // where rlen = r.len(), x_lo = x[0..rlen-nbits], x_hi = x[rlen-nbits..]
        //  r_lo = r[0..rlen-nbits] and r_hi = r[rlen-nbits..]
        // each thread is associated with x_hi, and it will computes the subset
        // { eq(x_lo, r_lo) * eq(x_hi, r_hi) } whose cardinality equals to 2^{rlen-nbits}
        evals
            .par_chunks_mut(1 << (r.len() - nbits))
            .zip((0..nthreads).into_par_iter())
            .for_each(|(chunks, tid)| {
                let eq_t = eq_ts[tid];

                build_eq_x_r_helper_sequential(&r[..(r.len() - nbits)], chunks, eq_t);
            });
    }
    unsafe { std::mem::transmute::<Vec<MaybeUninit<E>>, Vec<E>>(evals) }
}

#[cfg(test)]
mod tests {
    use crate::virtual_poly::{build_eq_x_r_vec, build_eq_x_r_vec_sequential};
    use ff_ext::{FromUniformBytes, GoldilocksExt2};
    use rand::thread_rng;

    #[test]
    fn test_build_eq() {
        env_logger::init();
        let mut rng = thread_rng();

        for num_vars in 10..24 {
            let r = (0..num_vars)
                .map(|_| GoldilocksExt2::random(&mut rng))
                .collect::<Vec<GoldilocksExt2>>();
            let eq_r_seq = build_eq_x_r_vec_sequential(&r);
            let eq_r_par = build_eq_x_r_vec(&r);
            assert_eq!(eq_r_par, eq_r_seq);
        }
    }
}
