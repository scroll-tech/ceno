use std::{collections::HashMap, sync::Arc};

use crate::{
    util::ceil_log2,
    virtual_poly::{ArcMultilinearExtension, VirtualPolynomial},
};
use ff_ext::ExtensionField;
use itertools::Itertools;

use crate::util::transpose;

pub struct VirtualPolynomials<'a, E: ExtensionField> {
    num_threads: usize,
    polys: Vec<VirtualPolynomial<'a, E>>,
    /// a storage to keep thread based mles, specific to multi-thread logic
    thread_based_mles_storage: HashMap<usize, Vec<ArcMultilinearExtension<'a, E>>>,
}

impl<'a, E: ExtensionField> VirtualPolynomials<'a, E> {
    pub fn new(num_threads: usize, max_num_variables: usize) -> Self {
        debug_assert!(num_threads > 0);
        VirtualPolynomials {
            num_threads,
            polys: (0..num_threads)
                .map(|_| VirtualPolynomial::new(max_num_variables - ceil_log2(num_threads)))
                .collect_vec(),
            thread_based_mles_storage: HashMap::new(),
        }
    }

    fn get_range_polys_by_thread_id(
        &self,
        thread_id: usize,
        polys: Vec<&'a ArcMultilinearExtension<'a, E>>,
    ) -> Vec<ArcMultilinearExtension<'a, E>> {
        polys
            .into_iter()
            .map(|poly| {
                let range_poly: ArcMultilinearExtension<E> =
                    Arc::new(poly.get_ranged_mle(self.num_threads, thread_id));
                range_poly
            })
            .collect_vec()
    }

    pub fn add_mle_list(&mut self, polys: Vec<&'a ArcMultilinearExtension<'a, E>>, coeff: E) {
        let polys = polys
            .into_iter()
            .map(|p| {
                let mle_ptr: usize = Arc::as_ptr(p) as *const () as usize;
                if let Some(mles) = self.thread_based_mles_storage.get(&mle_ptr) {
                    mles.clone()
                } else {
                    let mles = (0..self.num_threads)
                        .map(|thread_id| {
                            self.get_range_polys_by_thread_id(thread_id, vec![p])
                                .remove(0)
                        })
                        .collect_vec();
                    let mles_cloned = mles.clone();
                    self.thread_based_mles_storage.insert(mle_ptr, mles);
                    mles_cloned
                }
            })
            .collect_vec();

        // poly -> thread to thread -> poly
        let polys = transpose(polys);
        (0..self.num_threads)
            .zip_eq(polys)
            .for_each(|(thread_id, polys)| {
                self.polys[thread_id].add_mle_list(polys, coeff);
            });
    }

    /// in-place merge with another virtual polynomial
    pub fn merge(&mut self, other: &'a VirtualPolynomial<'a, E>) {
        for (coeffient, products) in other.products.iter() {
            let cur: Vec<_> = products
                .iter()
                .map(|&x| &other.flattened_ml_extensions[x])
                .collect();
            self.add_mle_list(cur, *coeffient);
        }
    }

    pub fn get_batched_polys(self) -> Vec<VirtualPolynomial<'a, E>> {
        self.polys
    }

    pub fn degree(&self) -> usize {
        assert!(self.polys.iter().map(|p| p.aux_info.max_degree).all_equal());
        self.polys
            .first()
            .map(|p| p.aux_info.max_degree)
            .unwrap_or_default()
    }
}
