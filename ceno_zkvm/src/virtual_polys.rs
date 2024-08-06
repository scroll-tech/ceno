use std::sync::Arc;

use ff_ext::ExtensionField;
use gkr::util::ceil_log2;
use itertools::Itertools;
use multilinear_extensions::virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2};

use crate::structs::VirtualPolynomials;

impl<'a, E: ExtensionField> VirtualPolynomials<'a, E> {
    pub fn new(num_threads: usize, num_variables: usize) -> Self {
        VirtualPolynomials {
            num_threads,
            polys: (0..num_threads)
                .map(|_| VirtualPolynomialV2::new(num_variables - ceil_log2(num_threads)))
                .collect_vec(),
        }
    }

    pub fn get_range_polys(
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

    pub fn add_mle_list(
        &mut self,
        thread_id: usize,
        polys: Vec<ArcMultilinearExtension<'a, E>>,
        coeff: E,
    ) {
        assert!(thread_id < self.polys.len());
        self.polys[thread_id].add_mle_list(polys, coeff);
    }

    pub fn get_batched_polys(self) -> Vec<VirtualPolynomialV2<'a, E>> {
        self.polys
    }
}
