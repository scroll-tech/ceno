use std::{cmp::max, collections::HashMap, marker::PhantomData, sync::Arc};

use crate::{
    mle::{DenseMultilinearExtension, MultilinearExtension},
    util::bit_decompose,
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

pub type ArcMultilinearExtension<'a, E> =
    Arc<dyn MultilinearExtension<E, Output = DenseMultilinearExtension<E>> + 'a>;
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
#[derive(Default, Clone)]
pub struct VirtualPolynomialV2<'a, E: ExtensionField> {
    /// Aux information about the multilinear polynomial
    pub aux_info: VPAuxInfo<E>,
    /// list of reference to products (as usize) of multilinear extension
    pub products: Vec<(E, Vec<usize>)>,
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

impl<'a, E: ExtensionField> VirtualPolynomialV2<'a, E> {
    /// Creates an empty virtual polynomial with `max_num_variables`.
    pub fn new(max_num_variables: usize) -> Self {
        VirtualPolynomialV2 {
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

    /// Creates an new virtual polynomial from a MLE and its coefficient.
    pub fn new_from_mle(mle: ArcMultilinearExtension<'a, E>, coefficient: E) -> Self {
        let mle_ptr: usize = Arc::as_ptr(&mle) as *const () as usize;
        let mut hm = HashMap::new();
        hm.insert(mle_ptr, 0);

        VirtualPolynomialV2 {
            aux_info: VPAuxInfo {
                // The max degree is the max degree of any individual variable
                max_degree: 1,
                max_num_variables: mle.num_vars(),
                phantom: PhantomData,
            },
            // here `0` points to the first polynomial of `flattened_ml_extensions`
            products: vec![(coefficient, vec![0])],
            flattened_ml_extensions: vec![mle],
            raw_pointers_lookup_table: hm,
        }
    }

    /// Add a product of list of multilinear extensions to self
    /// Returns an error if the list is empty.
    ///
    /// mle in mle_list must be in same num_vars() in same product,
    /// while different product can have different num_vars()
    ///
    /// The MLEs will be multiplied together, and then multiplied by the scalar
    /// `coefficient`.
    pub fn add_mle_list(&mut self, mle_list: Vec<ArcMultilinearExtension<'a, E>>, coefficient: E) {
        let mle_list: Vec<ArcMultilinearExtension<E>> = mle_list.into_iter().collect();
        let mut indexed_product = Vec::with_capacity(mle_list.len());

        assert!(!mle_list.is_empty(), "input mle_list is empty");
        // sanity check: all mle in mle_list must have same num_vars()
        assert!(
            mle_list
                .iter()
                .map(|m| {
                    assert!(m.num_vars() <= self.aux_info.max_num_variables);
                    m.num_vars()
                })
                .all_equal()
        );

        self.aux_info.max_degree = max(self.aux_info.max_degree, mle_list.len());

        for mle in mle_list {
            let mle_ptr: usize = Arc::as_ptr(&mle) as *const () as usize;
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
    pub fn merge(&mut self, other: &VirtualPolynomialV2<'a, E>) {
        let start = start_timer!(|| "virtual poly add");
        for (coeffient, products) in other.products.iter() {
            let cur: Vec<_> = products
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
    /// Returns an error if the MLE has a different `num_vars()` from self.
    #[tracing::instrument(skip_all, name = "mul_by_mle")]
    pub fn mul_by_mle(&mut self, mle: ArcMultilinearExtension<'a, E>, coefficient: E::BaseField) {
        let start = start_timer!(|| "mul by mle");

        assert_eq!(
            mle.num_vars(),
            self.aux_info.max_num_variables,
            "product has a multiplicand with wrong number of variables {} vs {}",
            mle.num_vars(),
            self.aux_info.max_num_variables
        );

        let mle_ptr = Arc::as_ptr(&mle) as *const () as usize;

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
            .map(|(c, p)| p.iter().map(|&i| evals[i]).product::<E>() * *c)
            .sum();

        end_timer!(start);
        res
    }

    /// Print out the evaluation map for testing. Panic if the num_vars() > 5.
    pub fn print_evals(&self) {
        if self.aux_info.max_num_variables > 5 {
            panic!("this function is used for testing only. cannot print more than 5 num_vars()")
        }
        for i in 0..1 << self.aux_info.max_num_variables {
            let point = bit_decompose(i, self.aux_info.max_num_variables);
            let point_fr: Vec<E> = point.iter().map(|&x| E::from(x as u64)).collect();
            println!("{} {:?}", i, self.evaluate(point_fr.as_ref()))
        }
        println!()
    }

    // // TODO: This seems expensive. Is there a better way to covert poly into its ext fields?
    // pub fn to_ext_field(&self) -> VirtualPolynomialV2<E> {
    //     let timer = start_timer!(|| "convert VP to ext field");
    //     let products = self.products.iter().map(|(f, v)| (*f, v.clone())).collect();

    //     let mut flattened_ml_extensions = vec![];
    //     let mut hm = HashMap::new();
    //     for mle in self.flattened_ml_extensions.iter() {
    //         let mle_ptr = Arc::as_ptr(mle) as *const () as usize;
    //         let index = self.raw_pointers_lookup_table.get(&mle_ptr).unwrap();

    //         let mle_ext_field = mle.as_ref().to_ext_field();
    //         let mle_ext_field = Arc::new(mle_ext_field);
    //         let mle_ext_field_ptr = Arc::as_ptr(&mle_ext_field) as usize;
    //         flattened_ml_extensions.push(mle_ext_field);
    //         hm.insert(mle_ext_field_ptr, *index);
    //     }
    //     end_timer!(timer);
    //     VirtualPolynomialV2 {
    //         aux_info: self.aux_info.clone(),
    //         products,
    //         flattened_ml_extensions,
    //         raw_pointers_lookup_table: hm,
    //     }
    // }
}
