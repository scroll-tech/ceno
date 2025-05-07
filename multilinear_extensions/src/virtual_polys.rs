use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
    sync::Arc,
};

use crate::{
    Expression, WitnessId,
    expression::monomial::Term,
    util::ceil_log2,
    utils::eval_by_expr_with_instance,
    virtual_poly::{ArcMultilinearExtension, MonomialTerms, VirtualPolynomial},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use p3::util::log2_strict_usize;

use crate::util::transpose;

pub type MonomialTermsType<'a, E> =
    Vec<Term<Either<<E as ExtensionField>::BaseField, E>, &'a ArcMultilinearExtension<'a, E>>>;

#[derive(Debug, Default, Clone, Copy)]
pub enum PolyMeta {
    #[default]
    Normal,
    Phase2Only,
}

/// a builder for constructing expressive polynomial formulas represented as expression,
/// primarily used in the sumcheck protocol.
///
/// this struct manages witness identifiers and multilinear extensions (mles),
/// enabling reuse and deduplication of polynomial
#[derive(Default)]
pub struct VirtualPolynomialsBuilder<'a, E: ExtensionField> {
    num_witin: WitnessId,
    mles_storage: BTreeMap<usize, (usize, &'a ArcMultilinearExtension<'a, E>)>,
    _phantom: PhantomData<E>,
}

impl<'a, E: ExtensionField> VirtualPolynomialsBuilder<'a, E> {
    pub fn lift(&mut self, mle: &'a ArcMultilinearExtension<'a, E>) -> Expression<E> {
        let mle_ptr: usize = Arc::as_ptr(mle) as *const () as usize;
        let (witin_id, _) = self.mles_storage.entry(mle_ptr).or_insert_with(|| {
            let witin_id = self.num_witin;
            self.num_witin = self.num_witin.strict_add(1);
            (witin_id as usize, mle)
        });

        Expression::WitIn(*witin_id as u16)
    }

    pub fn to_virtual_polys(
        self,
        num_threads: usize,
        max_num_variables: usize,
        half_eq_mles: Option<Vec<&'a ArcMultilinearExtension<'a, E>>>,
        expressions: &[Expression<E>],
        challenges: &[E],
    ) -> VirtualPolynomials<'a, E> {
        let mles_storage = self
            .mles_storage
            .values()
            .map(|(id, mle)| (*id, *mle))
            .collect::<BTreeMap<_, _>>();

        // when half_eq is provided, then all monomial term need to be in same num_vars
        let expected_num_vars_per_expr = if let Some(half_eq_mles) = half_eq_mles.as_ref() {
            assert_eq!(half_eq_mles.len(), expressions.len());
            Some(
                half_eq_mles
                    .iter()
                    .map(|half_eq| half_eq.num_vars() + 1) // half_eq
                    .collect_vec(),
            )
        } else {
            None
        };
        let mut virtual_polys = VirtualPolynomials::<E>::new(num_threads, max_num_variables);
        for (i, expression) in expressions.iter().enumerate() {
            let monomial_terms = expression
                .get_monomial_terms()
                .into_iter()
                .map(
                    |Term {
                         scalar: scalar_expr,
                         product,
                     }| {
                        let expected_num_vars = expected_num_vars_per_expr.as_ref().and_then(
                            |expected_num_vars_per_expr| expected_num_vars_per_expr.get(i),
                        );

                        let product_mle = product
                            .into_iter()
                            .map(|expr| match expr {
                                Expression::WitIn(witin_id) => {
                                    let mle = mles_storage
                                        .get(&(witin_id as usize))
                                        .cloned()
                                        .expect("invalid witin id");
                                    if let Some(expected_num_vars) = expected_num_vars {
                                        assert_eq!(*expected_num_vars, mle.num_vars());
                                    }
                                    mle
                                }
                                other => unimplemented!("un supported expression: {:?}", other),
                            })
                            .collect_vec();
                        let scalar = eval_by_expr_with_instance(
                            &[],
                            &[],
                            &[],
                            &[],
                            challenges,
                            &scalar_expr,
                        );
                        Term {
                            scalar,
                            product: product_mle,
                        }
                    },
                )
                .collect_vec();
            virtual_polys.add_monomial_terms(
                half_eq_mles
                    .as_ref()
                    .and_then(|half_eq_mles| half_eq_mles.get(i).cloned()),
                monomial_terms,
            );
        }
        virtual_polys
    }
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

    /// Adds a group of monomial terms to the current expression set.
    ///
    /// NOTE: When `zero_check_half_eq` is provided, no deduplication of equality constraints
    /// is performed internally. It is the caller’s responsibility to ensure that
    /// `zero_check_half_eq` contains only equality constraints unique to this `monomial_terms` group,
    /// as reusing the same equality across different groups is semantically invalid.
    pub fn add_monomial_terms(
        &mut self,
        zero_check_half_eq: Option<&'a ArcMultilinearExtension<'a, E>>,
        monomial_terms: MonomialTermsType<'a, E>,
    ) {
        let log2_num_threads = log2_strict_usize(self.num_threads);

        // process eq and separate to thread
        let zero_check_half_eq_per_threads = if let Some(zero_check_half_eq) = zero_check_half_eq {
            Some(
                (0..self.num_threads)
                    .map(|thread_id| {
                        if zero_check_half_eq.num_vars() > log2_num_threads {
                            self.get_range_polys_by_thread_id(thread_id, vec![zero_check_half_eq])
                                .remove(0)
                        } else {
                            // polynomial is too small
                            Arc::new(zero_check_half_eq.get_ranged_mle(1, 0))
                        }
                    })
                    .collect_vec(),
            )
        } else {
            None
        };

        let (poly_meta, momomial_terms): (Vec<_>, Vec<_>) = monomial_terms
            .into_iter()
            .map(|Term { scalar, product }| {
                assert!(!product.is_empty(), "some term product is empty");
                // all mle in product must have same num_vars()
                assert!(product.iter().map(|m| { m.num_vars() }).all_equal());

                let poly_meta = if product.first().unwrap().num_vars() > log2_num_threads {
                    PolyMeta::Normal
                } else {
                    // polynomial is too small
                    PolyMeta::Phase2Only
                };

                let product_per_threads: Vec<Vec<ArcMultilinearExtension<E>>> = product
                    .into_iter()
                    .map(|p| {
                        let mle_ptr: usize = Arc::as_ptr(p) as *const () as usize;
                        let mles_cloned =
                            if let Some(mles) = self.thread_based_mles_storage.get(&mle_ptr) {
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
                        mles_cloned
                    })
                    .collect_vec();

                // product -> thread to thread -> product
                (
                    poly_meta,
                    transpose(product_per_threads)
                        .into_iter()
                        .map(|product| Term { scalar, product })
                        // return Vec<Term>, with total length equal #threads
                        .collect_vec(),
                )
            })
            .unzip();

        let momomial_terms_threads = transpose(momomial_terms);
        assert_eq!(momomial_terms_threads.len(), self.num_threads);

        // collect per thread momomial_terms and add to thread-based virtual_poly
        let (hald_eq_index, monomial_term_product_index): (Option<usize>, &MonomialTerms<E>) =
            *momomial_terms_threads
                .into_iter()
                .zip_eq(self.polys.iter_mut())
                .enumerate()
                .map(|(thread_id, (momomial_terms, virtual_poly))| {
                    let zero_check_half_eq = zero_check_half_eq_per_threads
                        .as_ref()
                        .and_then(|zero_check_half_eq| zero_check_half_eq.get(thread_id).cloned());
                    virtual_poly.add_monomial_terms(zero_check_half_eq, momomial_terms)
                })
                .collect_vec()
                .first()
                .expect("");

        // update poly_meta w.r.t index, optionally record index for eq
        if let Some((index, half_eq_mle)) = hald_eq_index.as_ref().zip(zero_check_half_eq.as_ref())
        {
            let poly_meta = if half_eq_mle.num_vars() + 1 > log2_num_threads {
                PolyMeta::Normal
            } else {
                // polynomial is too small
                PolyMeta::Phase2Only
            };
            self.poly_meta.insert(*index, poly_meta);
        }
        for (poly_meta, term) in poly_meta.iter().zip_eq(&monomial_term_product_index.terms) {
            for index in &term.product {
                self.poly_meta.insert(*index, *poly_meta);
            }
        }
    }

    // add with only single monomial term
    pub fn add_mle_list(&mut self, polys: Vec<&'a ArcMultilinearExtension<'a, E>>, scalar: E) {
        self.add_monomial_terms(
            None,
            vec![Term {
                scalar: Either::Right(scalar),
                product: polys,
            }],
        );
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

    /// in-place merge with another virtual polynomial
    pub fn merge(&mut self, other: &'a VirtualPolynomial<'a, E>) {
        for (zero_check_half_eq_index, MonomialTerms { terms }) in other.products.iter() {
            let new_monomial_term = terms
                .iter()
                .map(|Term { scalar, product }| Term {
                    scalar: *scalar,
                    product: product
                        .iter()
                        .map(|&x| &other.flattened_ml_extensions[x])
                        .collect(),
                })
                .collect_vec();
            let zero_check_half_eq = zero_check_half_eq_index.map(|zero_check_half_eq_index| {
                &other.flattened_ml_extensions[zero_check_half_eq_index]
            });
            self.add_monomial_terms(zero_check_half_eq, new_monomial_term);
        }
    }
}
