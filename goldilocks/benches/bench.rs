use criterion::{criterion_group, criterion_main, Criterion};
use ff::Field;
use goldilocks::{Goldilocks, GoldilocksExt3};
use halo2curves::bn256::Fr;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

const SIZE: usize = 1000;

criterion_main!(bench);

criterion_group!(bench, bench_goldilocks, bench_goldilocks_ext3, bench_bn256);

fn bench_goldilocks(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("Goldilocks");

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let a = (0..SIZE)
        .map(|_| Goldilocks::random(&mut rng))
        .collect::<Vec<_>>();
    let b = (0..SIZE)
        .map(|_| Goldilocks::random(&mut rng))
        .collect::<Vec<_>>();

    let bench_str = format!("{} additions", SIZE);
    bench_group.bench_function(bench_str, |bencher| {
        bencher.iter(|| {
            a.iter()
                .zip(b.iter())
                .map(|(&ai, &bi)| ai + bi)
                .collect::<Vec<_>>()
        })
    });

    let bench_str = format!("{} multiplications", SIZE);
    bench_group.bench_function(bench_str, |bencher| {
        bencher.iter(|| {
            a.iter()
                .zip(b.iter())
                .map(|(&ai, &bi)| ai * bi)
                .collect::<Vec<_>>()
        })
    });
    bench_group.finish();
}

fn bench_goldilocks_ext3(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("Goldilocks Ext3");

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let a = (0..SIZE)
        .map(|_| GoldilocksExt3::random(&mut rng))
        .collect::<Vec<_>>();
    let b = (0..SIZE)
        .map(|_| GoldilocksExt3::random(&mut rng))
        .collect::<Vec<_>>();

    let bench_str = format!("{} additions", SIZE);
    bench_group.bench_function(bench_str, |bencher| {
        bencher.iter(|| {
            a.iter()
                .zip(b.iter())
                .map(|(&ai, &bi)| ai + bi)
                .collect::<Vec<_>>()
        })
    });

    let bench_str = format!("{} multiplications", SIZE);
    bench_group.bench_function(bench_str, |bencher| {
        bencher.iter(|| {
            a.iter()
                .zip(b.iter())
                .map(|(&ai, &bi)| ai * bi)
                .collect::<Vec<_>>()
        })
    });
    bench_group.finish();
}

fn bench_bn256(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("Bn256");

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let a = (0..SIZE).map(|_| Fr::random(&mut rng)).collect::<Vec<_>>();
    let b = (0..SIZE).map(|_| Fr::random(&mut rng)).collect::<Vec<_>>();

    let bench_str = format!("{} additions", SIZE);
    bench_group.bench_function(bench_str, |bencher| {
        bencher.iter(|| {
            a.iter()
                .zip(b.iter())
                .map(|(&ai, &bi)| ai + bi)
                .collect::<Vec<_>>()
        })
    });

    let bench_str = format!("{} multiplications", SIZE);
    bench_group.bench_function(bench_str, |bencher| {
        bencher.iter(|| {
            a.iter()
                .zip(b.iter())
                .map(|(&ai, &bi)| ai * bi)
                .collect::<Vec<_>>()
        })
    });
    bench_group.finish();
}
