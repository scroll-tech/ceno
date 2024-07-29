use std::{cmp::max, collections::HashMap, marker::PhantomData, mem, sync::Arc};

use crate::{
    mle::{ArcDenseMultilinearExtension, DenseMultilinearExtension},
    util::bit_decompose,
};
use ark_std::{end_timer, rand::Rng, start_timer};
use ff::{Field, PrimeField};
use ff_ext::ExtensionField;
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator},
    prelude::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use serde::{Deserialize, Serialize};

#[rustfmt::skip]
/// A virtual polynomial is a sum of products of multilinear polynomials;
/// where the multilinear polynomials are stored via their multilinear
/// extensions:  `(coefficient, DenseMultilinearExtension)`
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
///     \[
///         (c0, \[0, 1, 2\]),
///         (c1, \[3, 4\])
///     \]
/// - raw_pointers_lookup_table maps fi to i
///
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VirtualPolynomial<E: ExtensionField> {
    /// Aux information about the multilinear polynomial
    pub aux_info: VPAuxInfo<E>,
    /// list of reference to products (as usize) of multilinear extension
    pub products: Vec<(E::BaseField, Vec<usize>)>,
    /// Stores multilinear extensions in which product multiplicand can refer
    /// to.
    pub flattened_ml_extensions: Vec<ArcDenseMultilinearExtension<E>>,
    /// Pointers to the above poly extensions
    raw_pointers_lookup_table: HashMap<usize, usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Auxiliary information about the multilinear polynomial
pub struct VPAuxInfo<E> {
    /// max number of multiplicands in each product
    pub max_degree: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// Associated field
    #[doc(hidden)]
    pub phantom: PhantomData<E>,
}

impl<E: ExtensionField> AsRef<[u8]> for VPAuxInfo<E> {
    fn as_ref(&self) -> &[u8] {
        todo!()
    }
}

impl<E: ExtensionField> VirtualPolynomial<E> {
    /// Creates an empty virtual polynomial with `num_variables`.
    pub fn new(num_variables: usize) -> Self {
        VirtualPolynomial {
            aux_info: VPAuxInfo {
                max_degree: 0,
                num_variables,
                phantom: PhantomData::default(),
            },
            products: Vec::new(),
            flattened_ml_extensions: Vec::new(),
            raw_pointers_lookup_table: HashMap::new(),
        }
    }

    /// Creates an new virtual polynomial from a MLE and its coefficient.
    pub fn new_from_mle(mle: ArcDenseMultilinearExtension<E>, coefficient: E::BaseField) -> Self {
        let mle_ptr: usize = Arc::as_ptr(&mle) as usize;
        let mut hm = HashMap::new();
        hm.insert(mle_ptr, 0);

        VirtualPolynomial {
            aux_info: VPAuxInfo {
                // The max degree is the max degree of any individual variable
                max_degree: 1,
                num_variables: mle.num_vars,
                phantom: PhantomData::default(),
            },
            // here `0` points to the first polynomial of `flattened_ml_extensions`
            products: vec![(coefficient, vec![0])],
            flattened_ml_extensions: vec![mle],
            raw_pointers_lookup_table: hm,
        }
    }

    /// Add a product of list of multilinear extensions to self
    /// Returns an error if the list is empty, or the MLE has a different
    /// `num_vars` from self.
    ///
    /// The MLEs will be multiplied together, and then multiplied by the scalar
    /// `coefficient`.
    pub fn add_mle_list(
        &mut self,
        mle_list: Vec<ArcDenseMultilinearExtension<E>>,
        coefficient: E::BaseField,
    ) {
        let mle_list: Vec<ArcDenseMultilinearExtension<E>> = mle_list.into_iter().collect();
        let mut indexed_product = Vec::with_capacity(mle_list.len());

        assert!(!mle_list.is_empty(), "input mle_list is empty");

        self.aux_info.max_degree = max(self.aux_info.max_degree, mle_list.len());

        for mle in mle_list {
            assert_eq!(
                mle.num_vars, self.aux_info.num_variables,
                "product has a multiplicand with wrong number of variables {} vs {}",
                mle.num_vars, self.aux_info.num_variables
            );

            let mle_ptr: usize = Arc::as_ptr(&mle) as usize;
            if let Some(index) = self.raw_pointers_lookup_table.get(&mle_ptr) {
                indexed_product.push(*index)
            } else {
                let curr_index = self.flattened_ml_extensions.len();
                self.flattened_ml_extensions.push(mle);
                self.raw_pointers_lookup_table.insert(mle_ptr, curr_index);
                indexed_product.push(curr_index);
            }
        }
        self.products.push((coefficient, indexed_product));
    }

    /// in-place merge with another virtual polynomial
    pub fn merge(&mut self, other: &VirtualPolynomial<E>) {
        let start = start_timer!(|| "virtual poly add");
        for (coeffient, products) in other.products.iter() {
            let cur: Vec<ArcDenseMultilinearExtension<E>> = products
                .iter()
                .map(|&x| other.flattened_ml_extensions[x].clone())
                .collect();

            self.add_mle_list(cur, *coeffient);
        }
        end_timer!(start);
    }

    /// Multiple the current VirtualPolynomial by an MLE:
    /// - add the MLE to the MLE list;
    /// - multiple each product by MLE and its coefficient.
    /// Returns an error if the MLE has a different `num_vars` from self.
    #[tracing::instrument(skip_all, name = "mul_by_mle")]
    pub fn mul_by_mle(&mut self, mle: ArcDenseMultilinearExtension<E>, coefficient: E::BaseField) {
        let start = start_timer!(|| "mul by mle");

        assert_eq!(
            mle.num_vars, self.aux_info.num_variables,
            "product has a multiplicand with wrong number of variables {} vs {}",
            mle.num_vars, self.aux_info.num_variables
        );

        let mle_ptr = Arc::as_ptr(&mle) as usize;

        // check if this mle already exists in the virtual polynomial
        let mle_index = match self.raw_pointers_lookup_table.get(&mle_ptr) {
            Some(&p) => p,
            None => {
                self.raw_pointers_lookup_table
                    .insert(mle_ptr, self.flattened_ml_extensions.len());
                self.flattened_ml_extensions.push(mle);
                self.flattened_ml_extensions.len() - 1
            }
        };

        for (prod_coef, indices) in self.products.iter_mut() {
            // - add the MLE to the MLE list;
            // - multiple each product by MLE and its coefficient.
            indices.push(mle_index);
            *prod_coef *= coefficient;
        }

        // increase the max degree by one as the MLE has degree 1.
        self.aux_info.max_degree += 1;
        end_timer!(start);
    }

    /// Evaluate the virtual polynomial at point `point`.
    /// Returns an error is point.len() does not match `num_variables`.
    pub fn evaluate(&self, point: &[E]) -> E {
        let start = start_timer!(|| "evaluation");

        assert_eq!(
            self.aux_info.num_variables,
            point.len(),
            "wrong number of variables {} vs {}",
            self.aux_info.num_variables,
            point.len()
        );

        let evals: Vec<E> = self
            .flattened_ml_extensions
            .iter()
            .map(|x| x.evaluate(point))
            .collect();

        let res = self
            .products
            .iter()
            .map(|(c, p)| p.iter().map(|&i| evals[i]).product::<E>() * *c)
            .sum();

        end_timer!(start);
        res
    }

    /// Sample a random virtual polynomial, return the polynomial and its sum.
    pub fn random(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
        mut rng: &mut impl Rng,
    ) -> (Self, E) {
        let start = start_timer!(|| "sample random virtual polynomial");

        let mut sum = E::ZERO;
        let mut poly = VirtualPolynomial::new(nv);
        for _ in 0..num_products {
            let num_multiplicands =
                rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
            let (product, product_sum) =
                DenseMultilinearExtension::random_mle_list(nv, num_multiplicands, rng);
            let coefficient = E::BaseField::random(&mut rng);
            poly.add_mle_list(product, coefficient);
            sum += product_sum * coefficient;
        }

        end_timer!(start);
        (poly, sum)
    }

    /// Sample a random virtual polynomial that evaluates to zero everywhere
    /// over the boolean hypercube.
    pub fn rand_zero(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
        mut rng: impl Rng + Copy,
    ) -> Self {
        let mut poly = VirtualPolynomial::new(nv);
        for _ in 0..num_products {
            let num_multiplicands =
                rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
            let product =
                DenseMultilinearExtension::random_zero_mle_list(nv, num_multiplicands, rng);
            let coefficient = E::BaseField::random(&mut rng);
            poly.add_mle_list(product, coefficient);
        }

        poly
    }

    // Input poly f(x) and a random vector r, output
    //      \hat f(x) = \sum_{x_i \in eval_x} f(x_i) eq(x, r)
    // where
    //      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
    //
    // This function is used in ZeroCheck.
    pub fn build_f_hat(&self, r: &[E]) -> Self {
        let start = start_timer!(|| "zero check build hat f");

        assert_eq!(
            self.aux_info.num_variables,
            r.len(),
            "r.len() is different from number of variables: {} vs {}",
            r.len(),
            self.aux_info.num_variables
        );

        let eq_x_r = build_eq_x_r(r);
        let mut res = self.clone();
        res.mul_by_mle(eq_x_r, E::BaseField::ONE);

        end_timer!(start);
        res
    }

    /// Print out the evaluation map for testing. Panic if the num_vars > 5.
    pub fn print_evals(&self) {
        if self.aux_info.num_variables > 5 {
            panic!("this function is used for testing only. cannot print more than 5 num_vars")
        }
        for i in 0..1 << self.aux_info.num_variables {
            let point = bit_decompose(i, self.aux_info.num_variables);
            let point_fr: Vec<E> = point.iter().map(|&x| E::from(x as u64)).collect();
            println!("{} {:?}", i, self.evaluate(point_fr.as_ref()))
        }
        println!()
    }

    // TODO: This seems expensive. Is there a better way to covert poly into its ext fields?
    pub fn to_ext_field(&self) -> VirtualPolynomial<E> {
        let timer = start_timer!(|| "convert VP to ext field");
        let products = self.products.iter().map(|(f, v)| (*f, v.clone())).collect();

        let mut flattened_ml_extensions = vec![];
        let mut hm = HashMap::new();
        for mle in self.flattened_ml_extensions.iter() {
            let mle_ptr = Arc::as_ptr(mle) as usize;
            let index = self.raw_pointers_lookup_table.get(&mle_ptr).unwrap();

            let mle_ext_field = mle.as_ref().to_ext_field();
            let mle_ext_field = Arc::new(mle_ext_field);
            let mle_ext_field_ptr = Arc::as_ptr(&mle_ext_field) as usize;
            flattened_ml_extensions.push(mle_ext_field);
            hm.insert(mle_ext_field_ptr, *index);
        }
        end_timer!(timer);
        VirtualPolynomial {
            aux_info: self.aux_info.clone(),
            products,
            flattened_ml_extensions,
            raw_pointers_lookup_table: hm,
        }
    }
}

/// Evaluate eq polynomial.
pub fn eq_eval<F: PrimeField>(x: &[F], y: &[F]) -> F {
    assert_eq!(x.len(), y.len(), "x and y have different length");

    let start = start_timer!(|| "eq_eval");
    let mut res = F::ONE;
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        let xi_yi = xi * yi;
        res *= xi_yi + xi_yi - xi - yi + F::ONE;
    }
    end_timer!(start);
    res
}

/// This function build the eq(x, r) polynomial for any given r.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r_sequential<E: ExtensionField>(r: &[E]) -> ArcDenseMultilinearExtension<E> {
    let evals = build_eq_x_r_vec_sequential(r);
    let mle = DenseMultilinearExtension::from_evaluations_ext_vec(r.len(), evals);

    mle.into()
}
/// This function build the eq(x, r) polynomial for any given r, and output the
/// evaluation of eq(x, r) in its vector form.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))

#[tracing::instrument(skip_all, name = "multilinear_extensions::build_eq_x_r_vec_sequential")]
pub fn build_eq_x_r_vec_sequential<E: ExtensionField>(r: &[E]) -> Vec<E> {
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

    let mut evals = vec![E::ZERO; 1 << r.len()];
    build_eq_x_r_helper_sequential(r, &mut evals);

    evals
}

/// A helper function to build eq(x, r) via dynamic programing tricks.
/// This function takes 2^num_var iterations, and per iteration with 1 multiplication.
fn build_eq_x_r_helper_sequential<E: ExtensionField>(r: &[E], buf: &mut Vec<E>) {
    buf[0] = E::ONE;
    if r.is_empty() {
        buf.resize(1, E::ZERO);
        return;
    }
    for (i, r) in r.iter().rev().enumerate() {
        let next_size = 1 << (i + 1);
        // suppose at the previous step we processed buf [0..size]
        // for the current step we are populating new buf[0..2*size]
        // for j travese 0..size
        // buf[2*j + 1] = r * buf[j]
        // buf[2*j] = (1 - r) * buf[j]
        (0..next_size).step_by(2).rev().for_each(|index| {
            let prev_val = buf[index >> 1];
            let tmp = *r * prev_val;
            buf[index + 1] = tmp;
            buf[index] = prev_val - tmp;
        });
    }
}

/// This function build the eq(x, r) polynomial for any given r.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r<E: ExtensionField>(r: &[E]) -> ArcDenseMultilinearExtension<E> {
    let evals = build_eq_x_r_vec(r);
    let mle = DenseMultilinearExtension::from_evaluations_ext_vec(r.len(), evals);

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

    let mut evals: [Vec<E>; 2] = (0..2) // allocate 2 vector as rolling buffer
        .into_par_iter()
        .map(|_| vec![E::ZERO; 1 << r.len()])
        .collect::<Vec<Vec<E>>>()
        .try_into()
        .unwrap();
    build_eq_x_r_helper(r, &mut evals);

    mem::take(&mut evals[0])
}

/// A helper function to build eq(x, r) via dynamic programing tricks.
/// This function takes 2^num_var iterations, and per iteration with 1 multiplication.
fn build_eq_x_r_helper<E: ExtensionField>(r: &[E], buf: &mut [Vec<E>; 2]) {
    buf[0][0] = E::ONE;
    if r.is_empty() {
        buf[0].resize(1, E::ZERO);
        return;
    }
    for (i, r) in r.iter().rev().enumerate() {
        let [current, next] = buf;
        let (cur_size, next_size) = (1 << i, 1 << (i + 1));
        // suppose at the previous step we processed buf [0..size]
        // for the current step we are populating new buf[0..2*size]
        // for j travese 0..size
        // buf[2*j + 1] = r * buf[j]
        // buf[2*j] = (1 - r) * buf[j]
        current[0..cur_size]
            .par_iter()
            .zip_eq(next[0..next_size].par_chunks_mut(2))
            .with_min_len(64)
            .for_each(|(prev_val, next_vals)| {
                assert!(next_vals.len() == 2);
                let tmp = *r * prev_val;
                next_vals[1] = tmp;
                next_vals[0] = *prev_val - tmp;
            });
        buf.swap(0, 1); // swap rolling buffer
    }
}
