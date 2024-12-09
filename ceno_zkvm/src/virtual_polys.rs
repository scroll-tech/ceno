use std::{
    collections::{BTreeSet, HashMap},
    mem,
    sync::Arc,
};

use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    util::ceil_log2,
    virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2},
};

use crate::{expression::Expression, utils::transpose};

pub struct VirtualPolynomials<'a, E: ExtensionField> {
    num_threads: usize,
    polys: Vec<VirtualPolynomialV2<'a, E>>,
    /// a storage to keep thread based mles, specific to multi-thread logic
    thread_based_mles_storage: HashMap<usize, Vec<ArcMultilinearExtension<'a, E>>>,
}

impl<'a, E: ExtensionField> VirtualPolynomials<'a, E> {
    pub fn new(num_threads: usize, max_num_variables: usize) -> Self {
        VirtualPolynomials {
            num_threads,
            polys: (0..num_threads)
                .map(|_| VirtualPolynomialV2::new(max_num_variables - ceil_log2(num_threads)))
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

    pub fn get_batched_polys(self) -> Vec<VirtualPolynomialV2<'a, E>> {
        self.polys
    }

    /// add mle terms into virtual poly by expression
    /// return distinct witin in set
    pub fn add_mle_list_by_expr(
        &mut self,
        selector: Option<&'a ArcMultilinearExtension<'a, E>>,
        wit_ins: Vec<&'a ArcMultilinearExtension<'a, E>>,
        expr: &Expression<E>,
        challenges: &[E],
        // sumcheck batch challenge
        alpha: E,
    ) -> BTreeSet<u16> {
        assert!(expr.is_monomial_form());
        let monomial_terms = expr.evaluate(
            &|_| unreachable!(),
            &|witness_id| vec![(E::ONE, { vec![witness_id] })],
            &|scalar| vec![(E::from(scalar), { vec![] })],
            &|challenge_id, pow, scalar, offset| {
                let challenge = challenges[challenge_id as usize];
                vec![(challenge.pow([pow as u64]) * scalar + offset, vec![])]
            },
            &|mut a, b| {
                a.extend(b);
                a
            },
            &|mut a, mut b| {
                assert!(a.len() <= 2);
                assert!(b.len() <= 2);
                // special logic to deal with scaledsum
                // scaledsum second parameter must be 0
                if a.len() == 2 {
                    assert!((a[1].0, a[1].1.is_empty()) == (E::ZERO, true));
                    a.truncate(1);
                }
                if b.len() == 2 {
                    assert!((b[1].0, b[1].1.is_empty()) == (E::ZERO, true));
                    b.truncate(1);
                }

                a[0].1.extend(mem::take(&mut b[0].1));
                // return [ab]
                vec![(a[0].0 * b[0].0, mem::take(&mut a[0].1))]
            },
            &|mut x, a, b| {
                assert!(a.len() == 1 && a[0].1.is_empty()); // for challenge or constant, term should be empty
                assert!(b.len() == 1 && b[0].1.is_empty()); // for challenge or constant, term should be empty
                assert!(x.len() == 1 && (x[0].0, x[0].1.len()) == (E::ONE, 1)); // witin size only 1
                if b[0].0 == E::ZERO {
                    // only include first term if b = 0
                    vec![(a[0].0, mem::take(&mut x[0].1))]
                } else {
                    // return [ax, b]
                    vec![(a[0].0, mem::take(&mut x[0].1)), (b[0].0, vec![])]
                }
            },
        );
        for (constant, monomial_term) in monomial_terms.iter() {
            if *constant != E::ZERO && monomial_term.is_empty() && selector.is_none() {
                todo!("make virtual poly support pure constant")
            }
            let sel = selector.map(|sel| vec![sel]).unwrap_or_default();
            let terms_polys = monomial_term
                .iter()
                .map(|wit_id| wit_ins[*wit_id as usize])
                .collect_vec();

            self.add_mle_list([sel, terms_polys].concat(), *constant * alpha);
        }

        monomial_terms
            .into_iter()
            .flat_map(|(_, monomial_term)| monomial_term.into_iter().collect_vec())
            .collect::<BTreeSet<u16>>()
    }

    #[cfg(test)]
    pub fn degree(&self) -> usize {
        assert!(self.polys.iter().map(|p| p.aux_info.max_degree).all_equal());
        self.polys
            .first()
            .map(|p| p.aux_info.max_degree)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {

    use ark_std::test_rng;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use multilinear_extensions::{
        mle::IntoMLE,
        virtual_poly::VPAuxInfo,
        virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2},
    };
    use sumcheck::structs::{IOPProverStateV2, IOPVerifierState};
    use transcript::BasicTranscript as Transcript;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        expression::{Expression, ToExpr},
        virtual_polys::VirtualPolynomials,
    };
    use ff::Field;
    type E = GoldilocksExt2;

    #[test]
    fn test_add_mle_list_by_expr() {
        let mut cs = ConstraintSystem::new(|| "test_root");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);
        let x = cb.create_witin(|| "x");
        let y = cb.create_witin(|| "y");

        let wits_in: Vec<ArcMultilinearExtension<E>> = (0..cs.num_witin as usize)
            .map(|_| vec![Goldilocks::from(1)].into_mle().into())
            .collect();

        let mut virtual_polys = VirtualPolynomials::new(1, 0);

        // 3xy + 2y
        let expr: Expression<E> = 3 * x.expr() * y.expr() + 2 * y.expr();

        let distrinct_zerocheck_terms_set = virtual_polys.add_mle_list_by_expr(
            None,
            wits_in.iter().collect_vec(),
            &expr,
            &[],
            1.into(),
        );
        assert!(distrinct_zerocheck_terms_set.len() == 2);
        assert!(virtual_polys.degree() == 2);

        // 3x^3
        let expr: Expression<E> = 3 * x.expr() * x.expr() * x.expr();
        let distrinct_zerocheck_terms_set = virtual_polys.add_mle_list_by_expr(
            None,
            wits_in.iter().collect_vec(),
            &expr,
            &[],
            1.into(),
        );
        assert!(distrinct_zerocheck_terms_set.len() == 1);
        assert!(virtual_polys.degree() == 3);
    }

    #[test]
    fn test_sumcheck_different_degree() {
        let max_num_vars = 3;
        let fn_eval = |fs: &[ArcMultilinearExtension<E>]| -> E {
            let base_2 = Goldilocks::from(2);

            let evals = fs.iter().fold(
                vec![Goldilocks::ONE; 1 << fs[0].num_vars()],
                |mut evals, f| {
                    evals
                        .iter_mut()
                        .zip(f.get_base_field_vec())
                        .for_each(|(e, v)| {
                            *e *= v;
                        });
                    evals
                },
            );

            GoldilocksExt2::from(
                evals.iter().sum::<Goldilocks>()
                    * base_2.pow([(max_num_vars - fs[0].num_vars()) as u64]),
            )
        };
        let num_threads = 1;
        let mut transcript = Transcript::new(b"test");

        let mut rng = test_rng();

        let f1: [ArcMultilinearExtension<E>; 2] = std::array::from_fn(|_| {
            (0..1 << (max_num_vars - 2))
                .map(|_| Goldilocks::random(&mut rng))
                .collect_vec()
                .into_mle()
                .into()
        });
        let f2: [ArcMultilinearExtension<E>; 1] = std::array::from_fn(|_| {
            (0..1 << (max_num_vars))
                .map(|_| Goldilocks::random(&mut rng))
                .collect_vec()
                .into_mle()
                .into()
        });
        let f3: [ArcMultilinearExtension<E>; 3] = std::array::from_fn(|_| {
            (0..1 << (max_num_vars - 1))
                .map(|_| Goldilocks::random(&mut rng))
                .collect_vec()
                .into_mle()
                .into()
        });

        let mut virtual_polys = VirtualPolynomials::<E>::new(num_threads, max_num_vars);

        virtual_polys.add_mle_list(f1.iter().collect(), E::ONE);
        virtual_polys.add_mle_list(f2.iter().collect(), E::ONE);
        virtual_polys.add_mle_list(f3.iter().collect(), E::ONE);

        let (sumcheck_proofs, _) = IOPProverStateV2::prove_batch_polys(
            num_threads,
            virtual_polys.get_batched_polys(),
            &mut transcript,
        );

        let mut transcript = Transcript::new(b"test");
        let subclaim = IOPVerifierState::<E>::verify(
            fn_eval(&f1) + fn_eval(&f2) + fn_eval(&f3),
            &sumcheck_proofs,
            &VPAuxInfo {
                max_degree: 3,
                num_variables: max_num_vars,
                phantom: std::marker::PhantomData,
            },
            &mut transcript,
        );

        let mut verifier_poly = VirtualPolynomialV2::new(max_num_vars);
        verifier_poly.add_mle_list(f1.to_vec(), E::ONE);
        verifier_poly.add_mle_list(f2.to_vec(), E::ONE);
        verifier_poly.add_mle_list(f3.to_vec(), E::ONE);
        assert!(
            verifier_poly.evaluate(
                subclaim
                    .point
                    .iter()
                    .map(|c| c.elements)
                    .collect::<Vec<_>>()
                    .as_ref()
            ) == subclaim.expected_evaluation,
            "wrong subclaim"
        );
    }
}
