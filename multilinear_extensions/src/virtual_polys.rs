use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use crate::{
    util::ceil_log2,
    virtual_poly::{ArcMultilinearExtension, VirtualPolynomial},
};
use ff_ext::ExtensionField;
use itertools::Itertools;
use p3::util::log2_strict_usize;

use crate::util::transpose;

#[derive(Debug, Default, Clone, Copy)]
pub enum PolyMeta {
    #[default]
    Normal,
    Phase2Only,
}

pub struct VirtualPolynomials<'a, E: ExtensionField> {
    pub num_threads: usize,
    polys: Vec<VirtualPolynomial<'a, E>>,
    /// a storage to keep thread based mles, specific to multi-thread logic
    thread_based_mles_storage: HashMap<usize, Vec<ArcMultilinearExtension<'a, E>>>,
    pub(crate) poly_meta: BTreeMap<usize, PolyMeta>,
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
            poly_meta: BTreeMap::new(),
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
        let log2_num_threads = log2_strict_usize(self.num_threads);
        let (poly_meta, polys): (Vec<PolyMeta>, Vec<Vec<ArcMultilinearExtension<E>>>) = polys
            .into_iter()
            .map(|p| {
                let mle_ptr: usize = Arc::as_ptr(p) as *const () as usize;
                let poly_meta = if p.num_vars() > log2_num_threads {
                    PolyMeta::Normal
                } else {
                    // polynomial is too small
                    PolyMeta::Phase2Only
                };
                let mles_cloned = if let Some(mles) = self.thread_based_mles_storage.get(&mle_ptr) {
                    mles.clone()
                } else {
                    let mles = (0..self.num_threads)
                        .map(|thread_id| match poly_meta {
                            PolyMeta::Normal => self
                                .get_range_polys_by_thread_id(thread_id, vec![p])
                                .remove(0),
                            PolyMeta::Phase2Only => Arc::new(p.get_ranged_mle(1, 0)),
                        })
                        .collect_vec();
                    let mles_cloned = mles.clone();
                    self.thread_based_mles_storage.insert(mle_ptr, mles);
                    mles_cloned
                };
                (poly_meta, mles_cloned)
            })
            .unzip();

        // poly -> thread to thread -> poly
        let polys = transpose(polys);
        let poly_index: &[usize] = self
            .polys
            .iter_mut()
            .zip_eq(polys)
            .map(|(poly, polys)| poly.add_mle_list(polys, coeff))
            .collect_vec()
            .first()
            .expect("expect to get at index from first thread");

        poly_index
            .iter()
            .zip_eq(&poly_meta)
            .for_each(|(index, poly_meta)| {
                self.poly_meta.insert(*index, *poly_meta);
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

    /// return thread_based polynomial with its polynomial type
    pub fn get_batched_polys(self) -> (Vec<VirtualPolynomial<'a, E>>, Vec<PolyMeta>) {
        let mut poly_meta = vec![PolyMeta::Normal; self.polys[0].flattened_ml_extensions.len()];
        for (index, poly_meta_by_index) in self.poly_meta {
            poly_meta[index] = poly_meta_by_index
        }
        (self.polys, poly_meta)
    }

    pub fn degree(&self) -> usize {
        assert!(self.polys.iter().map(|p| p.aux_info.max_degree).all_equal());
        self.polys
            .first()
            .map(|p| p.aux_info.max_degree)
            .unwrap_or_default()
    }
}
