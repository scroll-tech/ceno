use ark_std::rand::thread_rng;
use criterion::*;
use ff::Field;
use goldilocks::Goldilocks;
use mpcs::util::{hash::new_hasher, merkle_tree::MerkleTree};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Sample},
    hash::{merkle_tree::MerkleTree as Plonky2MerkleTree, poseidon::PoseidonHash},
};

fn bench_merkle_internal(c: &mut Criterion) {
    const NUM_SAMPLES: usize = 10;
    let mut rng = thread_rng();
    let group_name = "merkle";
    let mut group = c.benchmark_group(group_name);
    group.sample_size(NUM_SAMPLES);

    for num_vars in 15..24 {
        group.bench_function(format!("{}", num_vars), |b| {
            let leaves = (0..(1 << num_vars))
                .map(|_| Goldilocks::random(&mut rng))
                .collect::<Vec<Goldilocks>>();
            let hasher = new_hasher::<Goldilocks>();
            b.iter_batched(
                || leaves.clone(),
                |leaves| {
                    MerkleTree::from_leaves(leaves, &hasher);
                },
                BatchSize::LargeInput,
            );
        });
    }
}

fn bench_plonky2_merkle_internal(c: &mut Criterion) {
    const NUM_SAMPLES: usize = 10;
    let group_name = "plonky2 merkle";
    let mut group = c.benchmark_group(group_name);
    group.sample_size(NUM_SAMPLES);

    for num_vars in 15..24 {
        group.bench_function(format!("{}", num_vars), |b| {
            let leaves = (0..(1 << num_vars))
                .map(|_| vec![GoldilocksField::rand()])
                .collect::<Vec<Vec<GoldilocksField>>>();
            b.iter_batched(
                || leaves.clone(),
                |leaves| {
                    Plonky2MerkleTree::<_, PoseidonHash>::new(leaves, 1);
                },
                BatchSize::LargeInput,
            );
        });
    }
}

fn bench_merkle(c: &mut Criterion) {
    bench_plonky2_merkle_internal(c);
    bench_merkle_internal(c);
}

criterion_group!(benches, bench_merkle);
criterion_main!(benches);
