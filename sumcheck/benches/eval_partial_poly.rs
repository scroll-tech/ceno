use std::sync::Arc;

use ark_std::rand::thread_rng;
use criterion::*;
use ff::Field;
use goldilocks::{Goldilocks, GoldilocksExt2};
use multilinear_extensions::{
    commutative_op_mle_pair, mle::DenseMultilinearExtension, op_mle,
    virtual_poly::VirtualPolynomial,
};
use sumcheck::util::{barycentric_weights, extrapolate, AdditiveArray, AdditiveVec};

fn eval_partial_poly(c: &mut Criterion) {
    type E = GoldilocksExt2;
    type F = Goldilocks;
    let mut rng = thread_rng();

    const NUM_SAMPLES: usize = 10;
    for nv in 12..20 {
        let mut group = c.benchmark_group("mle");
        group.sample_size(NUM_SAMPLES);

        let points = (0..=2u64).map(E::from).collect::<Vec<_>>();
        let weights = barycentric_weights(&points);
        let mut setup = |nv, i| {
            let mut f = Arc::new(DenseMultilinearExtension::<E>::random(nv, &mut rng));
            let mut g = Arc::new(DenseMultilinearExtension::<E>::random(nv, &mut rng));
            let mut h = Arc::new(DenseMultilinearExtension::<E>::random(nv, &mut rng));
            let r = E::random(&mut rng);
            for _ in 0..i {
                Arc::get_mut(&mut f).unwrap().fix_variables_in_place(&[r]);
                Arc::get_mut(&mut g).unwrap().fix_variables_in_place(&[r]);
                Arc::get_mut(&mut h).unwrap().fix_variables_in_place(&[r]);
            }
            let mut p = VirtualPolynomial::new_from_mle(f, F::from(2_u64));
            p.mul_by_mle(g.clone(), F::from(3u64));

            let mut q = VirtualPolynomial::new_from_mle(g, F::from(5u64));
            q.mul_by_mle(h, F::from(7u64));

            p.merge(&q);

            assert_eq!(p.products.len(), 2);
            assert_eq!(p.flattened_ml_extensions.len(), 3);

            p
        };

        let routine = |poly: VirtualPolynomial<E>| {
            let AdditiveVec(products_sum) = poly.products.iter().fold(
                AdditiveVec::new(poly.aux_info.max_degree + 1),
                |mut products_sum, (coefficient, products)| {
                    assert_eq!(products.len(), 2);
                    let mut sum = match products.len() {
                        1 => {
                            let f = &poly.flattened_ml_extensions[products[0]];
                            op_mle! {
                                |f| (0..f.len())
                                .into_iter()
                                .step_by(2)
                                .map(|b| {
                                    AdditiveArray([
                                        f[b],
                                        f[b + 1]
                                    ])
                                })
                                .sum::<AdditiveArray<_, 2>>(),
                                |sum| AdditiveArray(sum.0.map(E::from))
                            }
                            .to_vec()
                        }
                        2 => {
                            let (f, g) = (
                                &poly.flattened_ml_extensions[products[0]],
                                &poly.flattened_ml_extensions[products[1]],
                            );
                            commutative_op_mle_pair!(
                                |f, g| (0..f.len())
                                    .into_iter()
                                    .step_by(2)
                                    .map(|b| {
                                        AdditiveArray([
                                            f[b] * g[b],
                                            f[b + 1] * g[b + 1],
                                            (f[b + 1] + f[b + 1] - f[b])
                                                * (g[b + 1] + g[b + 1] - g[b]),
                                        ])
                                    })
                                    .sum::<AdditiveArray<_, 3>>(),
                                |sum| AdditiveArray(sum.0.map(E::from))
                            )
                            .to_vec()
                        }
                        _ => unimplemented!("do not support degree > 2"),
                    };
                    sum.iter_mut().for_each(|sum| *sum *= coefficient);

                    let extrapolation = (0..poly.aux_info.max_degree - products.len())
                        .into_iter()
                        .map(|i| {
                            let at = E::from((products.len() + 1 + i) as u64);
                            extrapolate(&points, &weights, &sum, &at)
                        })
                        .collect::<Vec<_>>();
                    sum.extend(extrapolation);

                    products_sum += AdditiveVec(sum);
                    products_sum
                },
            );
        };
        for i in 0..nv {
            group.bench_function(
                BenchmarkId::new("eval_partial_poly", format!("({},{})", nv, nv - i)),
                |b| {
                    b.iter_with_setup(|| setup(nv, i), routine);
                },
            );
        }
        group.finish();
    }
}

criterion_group!(benches, eval_partial_poly);
criterion_main!(benches);
