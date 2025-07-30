use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};

use crate::{
    Expression, WitnessId,
    expression::monomial::Term,
    macros::{entered_span, exit_span},
    mle::{MultilinearExtension, Point},
    util::ceil_log2,
    utils::eval_by_expr_with_instance,
    virtual_poly::{MonomialTerms, VirtualPolynomial},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use p3::util::log2_strict_usize;
use rand::Rng;

pub type MonomialTermsType<S, P> = Vec<Term<S, P>>;
pub type MonomialTermsExpr<'a, E> =
    Vec<Term<Either<<E as ExtensionField>::BaseField, E>, Expression<E>>>;
pub type MonomialTermsMLE<'a, E> = Vec<Term<E, MultilinearExtension<'a, E>>>;
pub type EitherRefMLE<'a, E> =
    Either<&'a MultilinearExtension<'a, E>, &'a mut MultilinearExtension<'a, E>>;

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
pub struct VirtualPolynomialsBuilder<'a, E: ExtensionField> {
    num_witin: WitnessId,
    mle_ptr_registry: BTreeMap<usize, (usize, EitherRefMLE<'a, E>)>,
    num_threads: usize,
    max_num_variables: usize,
    _phantom: PhantomData<E>,
}

impl<'a, E: ExtensionField> VirtualPolynomialsBuilder<'a, E> {
    /// create a new `VirtualPolynomialsBuilder` with the given number and max number of vars
    pub fn new(num_threads: usize, max_num_variables: usize) -> Self {
        Self {
            num_witin: WitnessId::default(),
            mle_ptr_registry: BTreeMap::new(),
            num_threads,
            max_num_variables,
            _phantom: PhantomData,
        }
    }

    /// create a new `VirtualPolynomialsBuilder` with the given number and max number of vars
    pub fn new_with_mles(
        num_threads: usize,
        max_num_variables: usize,
        mles: Vec<Either<&'a MultilinearExtension<'a, E>, &'a mut MultilinearExtension<'a, E>>>,
    ) -> Self {
        let mut builder = Self::new(num_threads, max_num_variables);
        mles.into_iter().for_each(|mle| {
            let _ = builder.lift(mle);
        });
        builder
    }

    /// lifts a reference to a `MultilinearExtension` into an `Expression::WitIn`
    ///
    /// assigns a unique witness index based on pointer address, reusing the same index
    /// if the MLE was already lifted. supports both shared and mutable references.
    pub fn lift(
        &mut self,
        mle: Either<&'a MultilinearExtension<'a, E>, &'a mut MultilinearExtension<'a, E>>,
    ) -> Expression<E> {
        mle.map_left(|mle| {
            let mle_ptr = mle as *const MultilinearExtension<E> as usize;
            let (witin_id, _) = self.mle_ptr_registry.entry(mle_ptr).or_insert_with(|| {
                let witin_id = self.num_witin;
                self.num_witin = self.num_witin.strict_add(1);
                (witin_id as usize, Either::Left(mle))
            });
            Expression::WitIn(*witin_id as WitnessId)
        })
        .map_right(|mle| {
            let mle_ptr = mle as *const MultilinearExtension<E> as usize;
            let (witin_id, _) = self.mle_ptr_registry.entry(mle_ptr).or_insert_with(|| {
                let witin_id = self.num_witin;
                self.num_witin = self.num_witin.strict_add(1);
                (witin_id as usize, Either::Right(mle))
            });
            Expression::WitIn(*witin_id as WitnessId)
        })
        .into_inner()
    }

    pub fn to_virtual_polys_with_monomial_terms(
        self,
        monimial_terms: &[Term<Expression<E>, Expression<E>>],
        public_io_evals: &[E],
        challenges: &[E],
    ) -> VirtualPolynomials<'a, E> {
        let mles = self
            .mle_ptr_registry
            .into_values()
            .collect::<Vec<_>>() // collect into Vec<&(usize, &ArcMultilinearExtension)>
            .into_iter()
            .sorted_by_key(|(witin_id, _)| *witin_id) // sort by witin_id
            .map(|(_, mle)| mle) // extract &ArcMultilinearExtension
            .collect::<Vec<_>>();

        let mut virtual_polys =
            VirtualPolynomials::<E>::new(self.num_threads, self.max_num_variables);
        // register mles to assure index matching the arc_poly order
        virtual_polys.register_mles(mles);

        // convert expression into monomial_terms and add to virtual_polys
        let monomial_terms_scalar_evaluated = monimial_terms
            .iter()
            .map(
                |Term {
                     scalar: scalar_expr,
                     product,
                 }| {
                    let scalar = eval_by_expr_with_instance(
                        &[],
                        &[],
                        &[],
                        public_io_evals,
                        challenges,
                        scalar_expr,
                    );
                    Term {
                        scalar,
                        product: product.clone(),
                    }
                },
            )
            .collect_vec();

        virtual_polys.add_monomial_terms(monomial_terms_scalar_evaluated);
        virtual_polys
    }

    pub fn to_virtual_polys(
        self,
        expressions: &[Expression<E>],
        challenges: &[E],
    ) -> VirtualPolynomials<'a, E> {
        let mles = self
            .mle_ptr_registry
            .into_values()
            .collect::<Vec<_>>() // collect into Vec<&(usize, &ArcMultilinearExtension)>
            .into_iter()
            .sorted_by_key(|(witin_id, _)| *witin_id) // sort by witin_id
            .map(|(_, mle)| mle) // extract &ArcMultilinearExtension
            .collect::<Vec<_>>();

        let mut virtual_polys =
            VirtualPolynomials::<E>::new(self.num_threads, self.max_num_variables);
        // register mles to assure index matching the arc_poly order
        virtual_polys.register_mles(mles);

        // convert expression into monomial_terms and add to virtual_polys
        for expression in expressions {
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
            poly_meta: BTreeMap::new(),
        }
    }

    pub fn new_from_monimials(
        num_threads: usize,
        max_num_variables: usize,
        monomials: MonomialTermsType<Either<E::BaseField, E>, EitherRefMLE<'a, E>>,
    ) -> Self {
        assert!(!monomials.is_empty());

        let mut poly = VirtualPolynomials::new(num_threads, max_num_variables);
        for Term { scalar, product } in monomials {
            assert!(
                product.iter().map(|mle| mle.num_vars()).all_equal(),
                "all product must got same num_vars"
            );
            let product: Vec<Expression<E>> = product
                .into_iter()
                .map(|mle| Expression::WitIn(poly.register_mles(vec![mle])[0] as WitnessId))
                .collect_vec();
            poly.add_monomial_terms(vec![Term { scalar, product }]);
        }
        poly
    }

    /// registers a batch of multilinear extensions (MLEs) to be accessible across all threads.
    ///
    /// each input `mle` is either duplicated or split depending on its size:
    /// - if the MLE's number of variables is greater than `log2(num_threads)`, it is considered *large*
    ///   and is split per thread using `as_view_slice`.
    /// - otherwise, it is considered *small* and is duplicated identically across all threads.
    ///
    /// per-thread MLEs are registered in each thread’s `poly` instance. The function ensures:
    /// - a unique `index` is returned per registered MLE group (same across threads).
    /// -  `poly_meta` map tracks whether each MLE is `Normal` (large/split) or `Phase2Only` (small/duplicated)
    ///
    /// Returns:
    /// indices, each corresponding to one registered MLE batch
    fn register_mles(&mut self, mles: Vec<EitherRefMLE<'a, E>>) -> Vec<usize> {
        let log2_num_threads = log2_strict_usize(self.num_threads);
        let mut indexes = vec![];
        for mle in mles {
            let poly_meta = if mle.num_vars() > log2_num_threads {
                PolyMeta::Normal
            } else {
                PolyMeta::Phase2Only
            };
            let mles = match mle {
                Either::Left(mle) => {
                    if mle.num_vars() > log2_num_threads {
                        mle.as_view_chunks(self.num_threads).into_iter()
                    } else {
                        vec![mle.as_view(); self.num_threads].into_iter()
                    }
                }
                Either::Right(mle) => {
                    if mle.num_vars() > log2_num_threads {
                        mle.as_view_chunks_mut(self.num_threads).into_iter()
                    } else {
                        vec![mle.as_owned(); self.num_threads].into_iter()
                    }
                }
            }
            .map(Arc::new)
            .collect_vec();

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
        }
        indexes
    }

    /// Adds a group of monomial terms to the current expression set.
    fn add_monomial_terms(&mut self, monomial_terms: MonomialTermsExpr<'a, E>) {
        self.polys
            .iter_mut()
            .for_each(|poly| poly.add_monomial_terms(monomial_terms.clone()));
    }

    /// evaluate giving a point
    /// this function is expensive since there are bunch of clone
    pub fn evaluate_slow(&self, point: &Point<E>) -> E {
        // recover raw_mles and evaluate each under point
        let raw_mles_evals = (0..self.polys[0].flattened_ml_extensions.len())
            .map(|index| match self.poly_meta[&index] {
                PolyMeta::Normal => {
                    let mut iter = self
                        .polys
                        .iter()
                        .map(|poly| &poly.flattened_ml_extensions[index]);
                    let Some(first) = iter.next() else {
                        panic!("empty flattened_ml_extensions")
                    };
                    let mut first = first.as_ref().as_owned();
                    for mle in iter {
                        let mle: MultilinearExtension<E> = mle.as_ref().as_owned();
                        first.merge(mle);
                    }
                    first
                }
                PolyMeta::Phase2Only => self.polys[0].flattened_ml_extensions[index]
                    .as_ref()
                    .clone(),
            })
            .map(|mle: MultilinearExtension<E>| {
                mle.evaluate(&point[point.len() - mle.num_vars()..])
            })
            .collect_vec();
        // evaluate based on monimial expression
        self.polys[0]
            .products
            .iter()
            .map(|MonomialTerms { terms }|
                terms.iter().map(|Term { scalar, product }|
                    either::for_both!(scalar, scalar => product.iter().map(|index| raw_mles_evals[*index]).product::<E>() **scalar )).sum()
            ).sum()
    }

    pub fn as_view(&'a self) -> Self {
        Self {
            num_threads: self.num_threads,
            polys: self.polys.iter().map(|poly| poly.as_view()).collect_vec(),
            poly_meta: self.poly_meta.clone(),
        }
    }

    /// Sample a random virtual polynomial, return the polynomial and its sum.
    pub fn random_monimials<R: Rng>(
        nv: &[usize],
        num_multiplicands_range: (usize, usize),
        num_products: usize,
        rng: &mut R,
    ) -> (MonomialTermsMLE<'a, E>, E) {
        let start = entered_span!("sample random virtual polynomial");

        let mut sum = E::ZERO;
        let max_num_variables = *nv.iter().max().unwrap();
        let mut monimial_term = vec![];
        for nv in nv {
            for _ in 0..num_products {
                let num_multiplicands =
                    rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
                let (product, product_sum) =
                    MultilinearExtension::random_mle_list(*nv, num_multiplicands, rng);
                let scalar = E::random(&mut *rng);
                monimial_term.push(Term { scalar, product });
                // need to scale up for the smaller nv
                sum += E::from_canonical_u64(1 << (max_num_variables - nv)) * product_sum * scalar;
            }
        }
        exit_span!(start);
        (monimial_term, sum)
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
