use std::{borrow::Cow, collections::BTreeMap, marker::PhantomData, sync::Arc};

use crate::{
    Expression, WitnessId,
    expression::monomial::Term,
    macros::{entered_span, exit_span},
    mle::{ArcMultilinearExtension, MultilinearExtension},
    util::ceil_log2,
    utils::eval_by_expr_with_instance,
    virtual_poly::VirtualPolynomial,
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use p3::util::log2_strict_usize;
use rand::Rng;

pub type MonomialTermsType<'a, E> =
    Vec<Term<Either<<E as ExtensionField>::BaseField, E>, Expression<E>>>;

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
    mles_storage: BTreeMap<usize, (usize, Cow<'a, ArcMultilinearExtension<'a, E>>)>,
    _phantom: PhantomData<E>,
}

impl<'a, E: ExtensionField> VirtualPolynomialsBuilder<'a, E> {
    pub fn lift(&mut self, mle: Cow<'a, ArcMultilinearExtension<'a, E>>) -> Expression<E> {
        let mle_ptr: usize = Arc::as_ptr(mle.as_ref()) as *const () as usize;
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
        expressions: &[Expression<E>],
        challenges: &[E],
    ) -> VirtualPolynomials<'a, E> {
        let mles_storage = self
            .mles_storage
            .into_values()
            .collect::<Vec<_>>() // collect into Vec<&(usize, &ArcMultilinearExtension)>
            .into_iter()
            .sorted_by_key(|(witin_id, _)| *witin_id) // sort by witin_id
            .map(|(_, mle)| mle) // extract &ArcMultilinearExtension
            .collect::<Vec<_>>();

        let mut virtual_polys = VirtualPolynomials::<E>::new(num_threads, max_num_variables);
        // register mles to assure index matching the arc_poly order
        virtual_polys.register_mles(mles_storage);

        // convert expression into monomial_terms and add to virtual_polys
        for (_, expression) in expressions.iter().enumerate() {
            let monomial_terms_expr = expression.get_monomial_terms();
            let monomial_terms = monomial_terms_expr
                .into_iter()
                .map(
                    |Term {
                         scalar: scalar_expr,
                         product,
                     }| {
                        let scalar = eval_by_expr_with_instance(
                            &[],
                            &[],
                            &[],
                            &[],
                            challenges,
                            &scalar_expr,
                        );
                        Term { scalar, product }
                    },
                )
                .collect_vec();
            virtual_polys.add_monomial_terms(monomial_terms);
        }
        virtual_polys
    }
}

pub struct VirtualPolynomials<'a, E: ExtensionField> {
    pub num_threads: usize,
    polys: Vec<VirtualPolynomial<'a, E>>,
    /// a storage to keep thread based mles, specific to multi-thread logic
    // thread_based_mles_storage: HashMap<usize, Vec<ArcMultilinearExtension<'a, E>>>,
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
            // thread_based_mles_storage: HashMap::new(),
            poly_meta: BTreeMap::new(),
        }
    }

    fn get_subslice_polys_by_thread_id<'b>(
        &self,
        thread_id: usize,
        polys: Vec<&'b ArcMultilinearExtension<'a, E>>,
    ) -> Vec<ArcMultilinearExtension<'a, E>>
    where
        'b: 'a,
    {
        polys
            .into_iter()
            .map(|poly| {
                let range_poly: ArcMultilinearExtension<E> =
                    Arc::new(poly.as_subslice_mle(self.num_threads, thread_id));
                range_poly
            })
            .collect_vec()
    }

    /// registers a batch of multilinear extensions (MLEs) across all threads,
    /// distributing each based on num_vars.
    ///
    /// for each input `mle`, if it is large enough (i.e., has more variables than `log2(num_threads)`),
    /// it is split and assigned to the corresponding thread using `get_range_polys_by_thread_id`.
    /// otherwise, the full polynomial is duplicated across all threads.
    ///
    /// the per-thread instances are registered locally and stored in `thread_based_mles_storage`
    /// using the MLE’s raw pointer as the key to ensure uniqueness and reference consistency.
    pub fn register_mles(
        &mut self,
        mles: Vec<Cow<'a, ArcMultilinearExtension<'a, E>>>,
    ) -> Vec<usize> {
        let log2_num_threads = log2_strict_usize(self.num_threads);
        let mut indexes = vec![];
        for mle in mles {
            let poly_meta = if mle.num_vars() > log2_num_threads {
                PolyMeta::Normal
            } else {
                PolyMeta::Phase2Only
            };
            // let mle_ptr: usize = Arc::as_ptr(&mle) as *const () as usize;
            let mles = match mle {
                Cow::Borrowed(mle) => {
                    assert!(!mle.is_self_owned());
                    (0..self.num_threads)
                        .map(|thread_id| {
                            let mle_thread_based = if mle.num_vars() > log2_num_threads {
                                self.get_subslice_polys_by_thread_id(thread_id, vec![mle])
                                    .remove(0)
                            } else {
                                // polynomial is too small
                                Arc::new(mle.as_subslice_mle(1, 0))
                            };
                            mle_thread_based
                        })
                        .collect_vec()
                }
                Cow::Owned(mle) => {
                    assert!(mle.is_self_owned());
                    let mle = Arc::into_inner(mle).expect(">1 strong count of arc pointer");
                    if mle.num_vars() > log2_num_threads {
                        mle.split_mle_into_chunks(self.num_threads)
                            .into_iter()
                            .map(|mle| Arc::new(mle))
                            .collect_vec()
                    } else {
                        vec![mle; self.num_threads]
                            .into_iter()
                            .map(|mle| Arc::new(mle))
                            .collect_vec()
                    }
                }
            };
            let index = self
                .polys
                .iter_mut()
                .zip_eq(mles)
                .map(|(poly, mle)| poly.register_mle(mle))
                .collect_vec()
                .first()
                .cloned()
                .unwrap();
            self.poly_meta.insert(index, poly_meta);
            indexes.push(index);
            // self.thread_based_mles_storage.insert(mle_ptr, mles);
        }
        indexes
    }

    /// Adds a group of monomial terms to the current expression set.
    fn add_monomial_terms(&mut self, monomial_terms: MonomialTermsType<'a, E>) {
        self.polys
            .iter_mut()
            .for_each(|poly| poly.add_monomial_terms(monomial_terms.clone()));
    }

    /// Sample a random virtual polynomial, return the polynomial and its sum.
    pub fn random<R: Rng>(
        n_threads: usize,
        nv: &[usize],
        num_multiplicands_range: (usize, usize),
        num_products: usize,
        rng: &mut R,
    ) -> (Self, E) {
        let start = entered_span!("sample random virtual polynomial");

        let mut sum = E::ZERO;
        let mut poly = VirtualPolynomials::<E>::new(n_threads, *nv.iter().max().unwrap());
        for nv in nv {
            for _ in 0..num_products {
                let num_multiplicands =
                    rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
                let (product, product_sum) =
                    MultilinearExtension::random_mle_list(*nv, num_multiplicands, rng);
                let product: Vec<Expression<E>> = product
                    .into_iter()
                    .map(|mle| Cow::Owned(mle as _))
                    .map(|mle| Expression::WitIn(poly.register_mles(vec![mle])[0] as u16))
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
