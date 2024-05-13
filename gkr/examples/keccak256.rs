#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use ark_std::rand::{
    rngs::{OsRng, StdRng},
    Rng, RngCore, SeedableRng,
};
use ff::Field;
use gkr::{
    error::GKRError,
    gadgets::keccak256::keccak256_circuit,
    structs::{Circuit, CircuitWitness, GKRInputClaims, IOPProof, PointAndEval},
    utils::MultilinearExtensionFromVectors,
};
use goldilocks::{GoldilocksExt2, SmallField};
use itertools::{izip, Itertools};
use multilinear_extensions::mle::ArcDenseMultilinearExtension;
use std::iter;
use tracing_flame::FlameLayer;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};
use transcript::Transcript;

fn prove_keccak256<F: SmallField>(
    instance_num_vars: usize,
    circuit: &Circuit<F>,
) -> Option<(IOPProof<F>, ArcDenseMultilinearExtension<F>)> {
    let mut rng = StdRng::seed_from_u64(OsRng.next_u64());
    let mut witness = CircuitWitness::new(&circuit, Vec::new());
    for _ in 0..1 << instance_num_vars {
        let [rand_state, rand_input] = [25 * 64, 17 * 64].map(|n| {
            iter::repeat_with(|| rng.gen_bool(0.5) as u64)
                .take(n)
                .map(F::BaseField::from)
                .collect_vec()
        });
        witness.add_instance(&circuit, vec![rand_state, rand_input]);
    }

    let lo_num_vars = witness.witness_out_ref()[0].instances[0]
        .len()
        .next_power_of_two()
        .ilog2() as usize;
    let output_mle = witness.witness_out_ref()[0]
        .instances
        .as_slice()
        .mle(lo_num_vars, instance_num_vars);

    let mut prover_transcript = Transcript::<F>::new(b"test");
    let output_point = iter::repeat_with(|| {
        prover_transcript
            .get_and_append_challenge(b"output point")
            .elements
    })
    .take(output_mle.num_vars)
    .collect_vec();
    let output_eval = output_mle.evaluate(&output_point);

    let start = std::time::Instant::now();
    let (proof, _) = gkr::structs::IOPProverState::prove_parallel(
        &circuit,
        &witness,
        vec![],
        vec![PointAndEval::new(output_point, output_eval)],
        &mut prover_transcript,
    );
    println!("{}: {:?}", 1 << instance_num_vars, start.elapsed());
    Some((proof, output_mle))
}

fn verify_keccak256<F: SmallField>(
    instance_num_vars: usize,
    output_mle: ArcDenseMultilinearExtension<F>,
    proof: IOPProof<F>,
    circuit: &Circuit<F>,
) -> Result<GKRInputClaims<F>, GKRError> {
    let mut verifer_transcript = Transcript::<F>::new(b"test");
    let output_point = iter::repeat_with(|| {
        verifer_transcript
            .get_and_append_challenge(b"output point")
            .elements
    })
    .take(output_mle.num_vars)
    .collect_vec();
    let output_eval = output_mle.evaluate(&output_point);
    gkr::structs::IOPVerifierState::verify_parallel(
        &circuit,
        &[],
        vec![],
        vec![PointAndEval::new(output_point, output_eval)],
        proof,
        instance_num_vars,
        &mut verifer_transcript,
    )
}

fn main() {
    println!(
        "#layers: {}",
        keccak256_circuit::<GoldilocksExt2>().layers.len()
    );

    let circuit = keccak256_circuit::<GoldilocksExt2>();
    // Sanity-check
    {
        let all_zero = vec![
            vec![<GoldilocksExt2 as SmallField>::BaseField::ZERO; 25 * 64],
            vec![<GoldilocksExt2 as SmallField>::BaseField::ZERO; 17 * 64],
        ];
        let all_one = vec![
            vec![<GoldilocksExt2 as SmallField>::BaseField::ONE; 25 * 64],
            vec![<GoldilocksExt2 as SmallField>::BaseField::ZERO; 17 * 64],
        ];
        let mut witness = CircuitWitness::new(&circuit, Vec::new());
        witness.add_instance(&circuit, all_zero);
        witness.add_instance(&circuit, all_one);

        izip!(
            &witness.witness_out_ref()[0].instances,
            [[0; 25], [u64::MAX; 25]]
        )
        .for_each(|(wire_out, state)| {
            let output = wire_out[..256]
                .chunks_exact(64)
                .map(|bits| {
                    bits.iter().fold(0, |acc, bit| {
                        (acc << 1) + (*bit == <GoldilocksExt2 as SmallField>::BaseField::ONE) as u64
                    })
                })
                .collect_vec();
            let expected = {
                let mut state = state;
                tiny_keccak::keccakf(&mut state);
                state[0..4].to_vec()
            };
            assert_eq!(output, expected)
        });
    }

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

    for log2_n in 1..12 {
        let Some((proof, output_mle)) = prove_keccak256::<GoldilocksExt2>(log2_n, &circuit) else {
            return;
        };
        assert!(verify_keccak256(log2_n, output_mle, proof, &circuit).is_ok());
    }
}
