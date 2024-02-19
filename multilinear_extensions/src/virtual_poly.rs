use std::cmp::max;
use std::hash::Hash;
use std::ops::Add;
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use ark_std::rand::Rng;
use ark_std::{end_timer, start_timer};
use ff::PrimeField;
use goldilocks::SmallField;
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use serde::{Deserialize, Serialize};

use crate::mle::DenseMultilinearExtension;
use crate::util::bit_decompose;

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
pub struct VirtualPolynomial<F> {
    /// Aux information about the multilinear polynomial
    pub aux_info: VPAuxInfo<F>,
    /// list of reference to products (as usize) of multilinear extension
    pub products: Vec<(F, Vec<usize>)>,
    /// Stores multilinear extensions in which product multiplicand can refer
    /// to.
    pub flattened_ml_extensions: Vec<Arc<DenseMultilinearExtension<F>>>,
    /// Pointers to the above poly extensions
    raw_pointers_lookup_table: HashMap<*const DenseMultilinearExtension<F>, usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Auxiliary information about the multilinear polynomial
pub struct VPAuxInfo<F> {
    /// max number of multiplicands in each product
    pub max_degree: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// Associated field
    #[doc(hidden)]
    pub phantom: PhantomData<F>,
}

impl<F: PrimeField> AsRef<[u8]> for VPAuxInfo<F> {
    fn as_ref(&self) -> &[u8] {
        todo!()
    }
}

impl<F> VPAuxInfo<F> {
    pub fn to_ext_field<Ext: SmallField<BaseField = F>>(&self) -> VPAuxInfo<Ext> {
        VPAuxInfo::<Ext> {
            max_degree: self.max_degree,
            num_variables: self.num_variables,
            phantom: PhantomData::default(),
        }
    }
}

impl<F: SmallField> Add for &VirtualPolynomial<F> {
    type Output = VirtualPolynomial<F>;
    fn add(self, other: &VirtualPolynomial<F>) -> Self::Output {
        let start = start_timer!(|| "virtual poly add");
        let mut res = self.clone();
        for products in other.products.iter() {
            let cur: Vec<Arc<DenseMultilinearExtension<F>>> = products
                .1
                .iter()
                .map(|&x| other.flattened_ml_extensions[x].clone())
                .collect();

            res.add_mle_list(cur, products.0);
        }
        end_timer!(start);
        res
    }
}

// TODO: convert this into a trait
impl<F: SmallField> VirtualPolynomial<F> {
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
    pub fn new_from_mle(mle: &Arc<DenseMultilinearExtension<F>>, coefficient: F) -> Self {
        let mle_ptr: *const DenseMultilinearExtension<F> = Arc::as_ptr(mle);
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
            flattened_ml_extensions: vec![mle.clone()],
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
        mle_list: impl IntoIterator<Item = Arc<DenseMultilinearExtension<F>>>,
        coefficient: F,
    ) {
        let mle_list: Vec<Arc<DenseMultilinearExtension<F>>> = mle_list.into_iter().collect();
        let mut indexed_product = Vec::with_capacity(mle_list.len());

        assert!(!mle_list.is_empty(), "input mle_list is empty");

        self.aux_info.max_degree = max(self.aux_info.max_degree, mle_list.len());

        for mle in mle_list {
            assert_eq!(
                mle.num_vars, self.aux_info.num_variables,
                "product has a multiplicand with wrong number of variables {} vs {}",
                mle.num_vars, self.aux_info.num_variables
            );

            let mle_ptr: *const DenseMultilinearExtension<F> = Arc::as_ptr(&mle);
            if let Some(index) = self.raw_pointers_lookup_table.get(&mle_ptr) {
                indexed_product.push(*index)
            } else {
                let curr_index = self.flattened_ml_extensions.len();
                self.flattened_ml_extensions.push(mle.clone());
                self.raw_pointers_lookup_table.insert(mle_ptr, curr_index);
                indexed_product.push(curr_index);
            }
        }
        self.products.push((coefficient, indexed_product));
    }

    /// Multiple the current VirtualPolynomial by an MLE:
    /// - add the MLE to the MLE list;
    /// - multiple each product by MLE and its coefficient.
    /// Returns an error if the MLE has a different `num_vars` from self.
    pub fn mul_by_mle(&mut self, mle: Arc<DenseMultilinearExtension<F>>, coefficient: F) {
        let start = start_timer!(|| "mul by mle");

        assert_eq!(
            mle.num_vars, self.aux_info.num_variables,
            "product has a multiplicand with wrong number of variables {} vs {}",
            mle.num_vars, self.aux_info.num_variables
        );

        let mle_ptr: *const DenseMultilinearExtension<F> = Arc::as_ptr(&mle);

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
    pub fn evaluate(&self, point: &[F]) -> F {
        let start = start_timer!(|| "evaluation");

        assert_eq!(
            self.aux_info.num_variables,
            point.len(),
            "wrong number of variables {} vs {}",
            self.aux_info.num_variables,
            point.len()
        );

        let evals: Vec<F> = self
            .flattened_ml_extensions
            .iter()
            .map(|x| x.evaluate(point))
            .collect();

        let res = self
            .products
            .iter()
            .map(|(c, p)| *c * p.iter().map(|&i| evals[i]).product::<F>())
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
    ) -> (Self, F) {
        let start = start_timer!(|| "sample random virtual polynomial");

        let mut sum = F::ZERO;
        let mut poly = VirtualPolynomial::new(nv);
        for _ in 0..num_products {
            let num_multiplicands =
                rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
            let (product, product_sum) =
                DenseMultilinearExtension::random_mle_list(nv, num_multiplicands, rng);
            let coefficient = F::random(&mut rng);
            poly.add_mle_list(product.into_iter(), coefficient);
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
            let coefficient = F::random(&mut rng);
            poly.add_mle_list(product.into_iter(), coefficient);
        }

        poly
    }

    // Input poly f(x) and a random vector r, output
    //      \hat f(x) = \sum_{x_i \in eval_x} f(x_i) eq(x, r)
    // where
    //      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
    //
    // This function is used in ZeroCheck.
    pub fn build_f_hat(&self, r: &[F]) -> Self {
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
        res.mul_by_mle(eq_x_r, F::ONE);

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
            let point_fr: Vec<F> = point.iter().map(|&x| F::from(x as u64)).collect();
            println!("{} {:?}", i, self.evaluate(point_fr.as_ref()))
        }
        println!()
    }

    // TODO: This seems expensive. Is there a better way to covert poly into its ext fields?
    pub fn to_ext_field<Ext: SmallField<BaseField = F> + Hash>(&self) -> VirtualPolynomial<Ext> {
        let timer = start_timer!(|| "convert VP to ext field");
        let aux_info = self.aux_info.to_ext_field();
        let products = self
            .products
            .iter()
            .map(|(f, v)| (Ext::from_base(f), v.clone()))
            .collect();

        let mut flattened_ml_extensions = vec![];
        let mut hm = HashMap::new();
        for mle in self.flattened_ml_extensions.iter() {
            let mle_ptr: *const DenseMultilinearExtension<F> = Arc::as_ptr(mle);
            let index = self.raw_pointers_lookup_table.get(&mle_ptr).unwrap();

            let mle_ext_field = mle.as_ref().to_ext_field();
            let mle_ext_field = Arc::new(mle_ext_field);
            let mle_ext_field_ptr: *const DenseMultilinearExtension<Ext> =
                Arc::as_ptr(&mle_ext_field);
            flattened_ml_extensions.push(mle_ext_field);
            hm.insert(mle_ext_field_ptr, *index);
        }
        end_timer!(timer);
        VirtualPolynomial {
            aux_info,
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
pub fn build_eq_x_r<F: SmallField>(r: &[F]) -> Arc<DenseMultilinearExtension<F>> {
    let evals = build_eq_x_r_vec(r);
    let mle = DenseMultilinearExtension::from_evaluations_vec(r.len(), evals);

    Arc::new(mle)
}
/// This function build the eq(x, r) polynomial for any given r, and output the
/// evaluation of eq(x, r) in its vector form.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r_vec<F: PrimeField>(r: &[F]) -> Vec<F> {
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

    let mut eval = Vec::new();
    build_eq_x_r_helper(r, &mut eval);

    eval
}

/// A helper function to build eq(x, r) recursively.
/// This function takes `r.len()` steps, and for each step it requires a maximum
/// `r.len()-1` multiplications.
fn build_eq_x_r_helper<F: PrimeField>(r: &[F], buf: &mut Vec<F>) {
    // assert!(!r.is_empty(), "r length is 0");
    if r.is_empty() {
        buf.resize(1, F::ZERO);
        buf[0] = F::ONE;
        return;
    }

    if r.len() == 1 {
        // initializing the buffer with [1-r_0, r_0]
        buf.push(F::ONE - r[0]);
        buf.push(r[0]);
    } else {
        build_eq_x_r_helper(&r[1..], buf);

        // suppose at the previous step we received [b_1, ..., b_k]
        // for the current step we will need
        // if x_0 = 0:   (1-r0) * [b_1, ..., b_k]
        // if x_0 = 1:   r0 * [b_1, ..., b_k]
        // let mut res = vec![];
        // for &b_i in buf.iter() {
        //     let tmp = r[0] * b_i;
        //     res.push(b_i - tmp);
        //     res.push(tmp);
        // }
        // *buf = res;

        let mut res = vec![F::ZERO; buf.len() << 1];
        res.par_iter_mut().enumerate().for_each(|(i, val)| {
            let bi = buf[i >> 1];
            let tmp = r[0] * bi;
            if i & 1 == 0 {
                *val = bi - tmp;
            } else {
                *val = tmp;
            }
        });
        *buf = res;
    }
}
