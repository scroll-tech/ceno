use ark_std::test_rng;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ff::Field;
use goldilocks::GoldilocksExt2;
use rayon::prelude::*;
use std::ops::Range;

fn eq_new<F: Field>(r: &[F]) -> Vec<F> {
    let num_vars = r.len();
    let lo_num_vars = num_vars.next_multiple_of(2) >> 1;

    let (r_lo, r_hi) = r.split_at(lo_num_vars);
    let (lo, hi) = rayon::join(|| eq_expand_serial(r_lo), || eq_expand_serial(r_hi));

    let lo_mask = (1 << lo_num_vars) - 1;
    return (0..1 << num_vars)
        .into_par_iter()
        .map(|b| lo[b & lo_mask] * hi[b >> lo_num_vars])
        .collect();

    fn eq_expand_serial<F: Field>(y: &[F]) -> Vec<F> {
        let mut out = vec![F::ZERO; 1 << y.len()];
        out[0] = F::ONE;
        y.iter().enumerate().for_each(|(idx, y_i)| {
            let (lo, hi) = out[..2 << idx].split_at_mut(1 << idx);
            hi.iter_mut().zip(&*lo).for_each(|(hi, lo)| *hi = *lo * y_i);
            lo.iter_mut().zip(&*hi).for_each(|(lo, hi)| *lo -= hi);
        });
        out
    }
}

fn eq_old<F: Field>(r: &[F]) -> Vec<F> {
    let mut eval = Vec::new();
    inner(r, &mut eval);
    return eval;

    fn inner<F: Field>(r: &[F], buf: &mut Vec<F>) {
        if r.is_empty() {
            buf.resize(1, F::ZERO);
            buf[0] = F::ONE;
            return;
        }

        if r.len() == 1 {
            buf.push(F::ONE - r[0]);
            buf.push(r[0]);
        } else {
            inner(&r[1..], buf);
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
}

fn criterion_benchmark(c: &mut Criterion) {
    const RANGE: Range<usize> = 16..23;

    let mut rng = test_rng();
    let y = std::iter::repeat_with(|| GoldilocksExt2::random(&mut rng))
        .take(RANGE.end)
        .collect::<Vec<_>>();
    for num_vars in RANGE {
        assert_eq!(eq_new(&y[..num_vars]), eq_old(&y[..num_vars]));
    }

    for num_vars in RANGE {
        let y = &y[..num_vars];
        let id = BenchmarkId::new("eq_new", y.len());
        c.bench_with_input(id, &y, |b, y| b.iter(|| eq_new(black_box(y))));
    }
    for num_vars in RANGE {
        let y = &y[..num_vars];
        let id = BenchmarkId::new("eq_old", y.len());
        c.bench_with_input(id, &y, |b, y| b.iter(|| eq_old(black_box(y))));
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
