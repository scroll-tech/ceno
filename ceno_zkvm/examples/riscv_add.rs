use std::{collections::BTreeMap, time::Instant};

use ark_std::test_rng;
use ceno_zkvm::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{riscv::addsub::AddInstruction, Instruction},
    scheme::prover::ZKVMProver,
};
use const_env::from_env;

use ceno_emul::StepRecord;
use ceno_zkvm::{
    circuit_builder::{ZKVMConstraintSystem, ZKVMVerifyingKey},
    scheme::verifier::ZKVMVerifier,
    tables::{RangeTableCircuit, TableCircuit},
};
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
    type E = GoldilocksExt2;

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

    // keygen
    let mut zkvm_fixed_traces = BTreeMap::default();
    let mut zkvm_cs = ZKVMConstraintSystem::default();

    let (add_cs, add_config) = {
        let mut cs = ConstraintSystem::new(|| "riscv_add");
        let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
        let config = AddInstruction::construct_circuit(&mut circuit_builder).unwrap();
        zkvm_cs.add_cs(AddInstruction::<E>::name(), cs.clone());
        zkvm_fixed_traces.insert(AddInstruction::<E>::name(), None);
        (cs, config)
    };
    let (range_cs, range_config) = {
        let mut cs = ConstraintSystem::new(|| "riscv_range");
        let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
        let config = RangeTableCircuit::construct_circuit(&mut circuit_builder).unwrap();
        zkvm_cs.add_cs(
            <RangeTableCircuit<E> as TableCircuit<E>>::name(),
            cs.clone(),
        );
        zkvm_fixed_traces.insert(
            <RangeTableCircuit<E> as TableCircuit<E>>::name(),
            Some(RangeTableCircuit::<E>::generate_fixed_traces(
                &config,
                cs.num_fixed,
            )),
        );
        (cs, config)
    };
    let pk = zkvm_cs.key_gen(zkvm_fixed_traces);
    let vk = pk.get_vk();

    // proving
    let prover = ZKVMProver::new(pk);
    let verifier = ZKVMVerifier::new(vk);

    for instance_num_vars in 20..22 {
        // TODO: witness generation from step records emitted by tracer
        let num_instances = 1 << instance_num_vars;
        let mut zkvm_witness = BTreeMap::default();
        let add_witness = AddInstruction::assign_instances(
            &add_config,
            add_cs.num_witin as usize,
            vec![StepRecord::default(); num_instances],
        )
        .unwrap();
        let range_witness = RangeTableCircuit::<E>::assign_instances(
            &range_config,
            range_cs.num_witin as usize,
            &[],
        )
        .unwrap();

        zkvm_witness.insert(AddInstruction::<E>::name(), add_witness);
        zkvm_witness.insert(RangeTableCircuit::<E>::name(), range_witness);

        let timer = Instant::now();

        let mut transcript = Transcript::new(b"riscv");
        let mut rng = test_rng();
        let real_challenges = [E::random(&mut rng), E::random(&mut rng)];

        let zkvm_proof = prover
            .create_proof(zkvm_witness, max_threads, &mut transcript, &real_challenges)
            .expect("create_proof failed");

        assert!(
            verifier
                .verify_proof(zkvm_proof, &mut transcript, &real_challenges,)
                .expect("verify proof return with error"),
        );

        println!(
            "AddInstruction::create_proof, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );
    }
}
