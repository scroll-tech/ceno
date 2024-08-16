use std::time::Instant;

use ark_std::test_rng;
use ceno_zkvm::{
    circuit_builder::{CircuitBuilder, ConstraintSystem, ProvingKey},
    instructions::{riscv::addsub::AddInstruction, Instruction},
    scheme::prover::ZKVMProver,
};
use const_env::from_env;

use ff_ext::ff::Field;
use goldilocks::{Goldilocks, GoldilocksExt2};
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLE;
use sumcheck::util::is_power_of_2;
use tracing_flame::FlameLayer;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};
use transcript::Transcript;

#[from_env]
const RAYON_NUM_THREADS: usize = 8;

fn main() {
    let max_threads = {
        if !is_power_of_2(RAYON_NUM_THREADS) {
            #[cfg(not(feature = "non_pow2_rayon_thread"))]
            {
                panic!(
                    "add --features non_pow2_rayon_thread to enable unsafe feature which support non pow of 2 rayon thread pool"
                );
            }

            #[cfg(feature = "non_pow2_rayon_thread")]
            {
                use sumcheck::{local_thread_pool::create_local_pool_once, util::ceil_log2};
                let max_thread_id = 1 << ceil_log2(RAYON_NUM_THREADS);
                create_local_pool_once(1 << ceil_log2(RAYON_NUM_THREADS), true);
                max_thread_id
            }
        } else {
            RAYON_NUM_THREADS
        }
    };
    let mut cs = ConstraintSystem::new(|| "risv_add");
    let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);
    let _ = AddInstruction::construct_circuit(&mut circuit_builder);
    let vk = cs.key_gen();
    let pk = ProvingKey::create_pk(vk);
    let num_witin = pk.get_cs().num_witin;

    let prover = ZKVMProver::new(pk);
    let mut transcript = Transcript::new(b"riscv");
    let mut rng = test_rng();
    let real_challenges = [E::random(&mut rng), E::random(&mut rng)];

    let (flame_layer, _guard) = FlameLayer::with_file("./tracing.folded").unwrap();
    let subscriber = Registry::default()
        .with(
            fmt::layer()
                .compact()
                .with_thread_ids(false)
                .with_thread_names(false),
        )
        .with(EnvFilter::from_default_env())
        .with(flame_layer.with_threads_collapsed(true));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    for instance_num_vars in 20..22 {
        // generate mock witness
        let num_instances = 1 << instance_num_vars;
        let wits_in = (0..num_witin as usize)
            .map(|_| {
                (0..num_instances)
                    .map(|_| Goldilocks::random(&mut rng))
                    .collect::<Vec<Goldilocks>>()
                    .into_mle()
                    .into()
            })
            .collect_vec();
        let timer = Instant::now();
        let _ = prover
            .create_proof(
                wits_in,
                num_instances,
                max_threads,
                &mut transcript,
                &real_challenges,
            )
            .expect("create_proof failed");
        println!(
            "AddInstruction::create_proof, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }

    type E = GoldilocksExt2;
}
