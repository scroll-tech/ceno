use std::time::Instant;

use rand::thread_rng;
use whir::{
    cmdline_utils::{AvailableFields, AvailableMerkle, WhirType},
    crypto::{Poseidon2ExtMerkleMmcs, poseidon2_ext_merkle_tree},
    parameters::*,
    whir::Statement,
};

use nimue_pow::blake3::Blake3PoW;

use clap::Parser;

type E = ff_ext::GoldilocksExt2;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 't', long = "type", default_value = "PCS")]
    protocol_type: WhirType,

    #[arg(short = 'l', long, default_value = "100")]
    security_level: usize,

    #[arg(short = 'p', long)]
    pow_bits: Option<usize>,

    #[arg(short = 'd', long, default_value = "20")]
    num_variables: usize,

    #[arg(short = 'e', long = "evaluations", default_value = "1")]
    num_evaluations: usize,

    #[arg(short = 'r', long, default_value = "1")]
    rate: usize,

    #[arg(long = "reps", default_value = "1000")]
    verifier_repetitions: usize,

    #[arg(short = 'i', long = "initfold", default_value = "4")]
    first_round_folding_factor: usize,

    #[arg(short = 'k', long = "fold", default_value = "4")]
    folding_factor: usize,

    #[arg(long = "sec", default_value = "ConjectureList")]
    soundness_type: SoundnessType,

    #[arg(long = "fold_type", default_value = "ProverHelps")]
    fold_optimisation: FoldType,

    #[arg(short = 'f', long = "field", default_value = "Goldilocks2")]
    field: AvailableFields,

    #[arg(long = "hash", default_value = "Blake3")]
    merkle_tree: AvailableMerkle,
}

type PowStrategy = Blake3PoW;

fn main() {
    let mut args = Args::parse();

    if args.pow_bits.is_none() {
        args.pow_bits = Some(default_max_pow(args.num_variables, args.rate));
    }

    let hash_params = poseidon2_ext_merkle_tree();
    run_whir(args, hash_params);
}

fn run_whir(args: Args, hash_params: Poseidon2ExtMerkleMmcs<E>) {
    match args.protocol_type {
        WhirType::PCS => run_whir_pcs(args, hash_params),
        WhirType::LDT => run_whir_as_ldt(args, hash_params),
    }
}

fn run_whir_as_ldt(args: Args, hash_params: Poseidon2ExtMerkleMmcs<E>) {
    use whir::whir::{
        committer::Committer, parameters::WhirConfig, prover::Prover, verifier::Verifier,
    };

    // Runs as a LDT
    let security_level = args.security_level;
    let pow_bits = args.pow_bits.unwrap();
    let num_variables = args.num_variables;
    let starting_rate = args.rate;
    let reps = args.verifier_repetitions;
    let first_round_folding_factor = args.first_round_folding_factor;
    let folding_factor = args.folding_factor;
    let fold_optimisation = args.fold_optimisation;
    let soundness_type = args.soundness_type;

    if args.num_evaluations > 1 {
        println!("Warning: running as LDT but a number of evaluations to be proven was specified.");
    }

    let num_coeffs = 1 << num_variables;

    let mv_params = MultivariateParameters::<E>::new(num_variables);

    let whir_params = WhirParameters {
        initial_statement: false,
        security_level,
        pow_bits,
        folding_factor: FoldingFactor::ConstantFromSecondRound(
            first_round_folding_factor,
            folding_factor,
        ),
        hash_params,
        soundness_type,
        fold_optimisation,
        starting_log_inv_rate: starting_rate,
    };

    let params = WhirConfig::<E>::new(mv_params, whir_params.clone());

    let mut transcript = io.to_transcript();

    println!("=========================================");
    println!("Whir (LDT) 🌪️");
    println!("Field: {:?} and MT: {:?}", args.field, args.merkle_tree);
    println!("{}", params);
    if !params.check_pow_bits() {
        println!("WARN: more PoW bits required than what specified.");
    }

    use ark_ff::Field;
    let polynomial = DenseMultilinearExtension::from_evaluations_ext_vec(
        (0..num_coeffs)
            .map(<F as Field>::BasePrimeField::from)
            .collect(),
    );

    let whir_prover_time = Instant::now();

    let committer = Committer::new(params.clone());
    let witness = committer.commit(&mut transcript, polynomial).unwrap();

    let prover = Prover(params.clone());

    let proof = prover
        .prove(&mut transcript, Statement::default(), witness)
        .unwrap();

    dbg!(whir_prover_time.elapsed());

    // Serialize proof
    let transcript = transcript.transcript().to_vec();
    let mut proof_bytes = vec![];
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    let proof_size = transcript.len() + proof_bytes.len();
    dbg!(proof_size);

    // Just not to count that initial inversion (which could be precomputed)
    let verifier = Verifier::new(params.clone());

    HashCounter::reset();
    let whir_verifier_time = Instant::now();
    for _ in 0..reps {
        let mut arthur = io.to_arthur(&transcript);
        verifier
            .verify(&mut arthur, &Statement::default(), &proof)
            .unwrap();
    }
    dbg!(whir_verifier_time.elapsed() / reps as u32);
    dbg!(HashCounter::get() as f64 / reps as f64);
}

fn run_whir_pcs(args: Args, hash_params: Poseidon2ExtMerkleMmcs<E>) {
    use whir::whir::{
        Statement, committer::Committer, parameters::WhirConfig, prover::Prover,
        verifier::Verifier, whir_proof_size,
    };

    // Runs as a PCS
    let security_level = args.security_level;
    let pow_bits = args.pow_bits.unwrap();
    let num_variables = args.num_variables;
    let starting_rate = args.rate;
    let reps = args.verifier_repetitions;
    let first_round_folding_factor = args.first_round_folding_factor;
    let folding_factor = args.folding_factor;
    let fold_optimisation = args.fold_optimisation;
    let soundness_type = args.soundness_type;
    let num_evaluations = args.num_evaluations;

    if num_evaluations == 0 {
        println!("Warning: running as PCS but no evaluations specified.");
    }

    let num_coeffs = 1 << num_variables;

    let mv_params = MultivariateParameters::<F>::new(num_variables);

    let whir_params = WhirParameters::<MerkleConfig> {
        initial_statement: true,
        security_level,
        pow_bits,
        folding_factor: FoldingFactor::ConstantFromSecondRound(
            first_round_folding_factor,
            folding_factor,
        ),
        leaf_hash_params,
        two_to_one_params,
        soundness_type,
        fold_optimisation,
        _pow_parameters: Default::default(),
        starting_log_inv_rate: starting_rate,
    };

    let params = WhirConfig::<F>::new(mv_params, whir_params);

    let io = IOPattern::<DefaultHash>::new("🌪️")
        .commit_statement(&params)
        .add_whir_proof(&params)
        .clone();

    let mut transcript = io.to_transcript();

    println!("=========================================");
    println!("Whir (PCS) 🌪️");
    println!("Field: {:?} and MT: {:?}", args.field, args.merkle_tree);
    println!("{}", params);
    if !params.check_pow_bits() {
        println!("WARN: more PoW bits required than what specified.");
    }

    let polynomial = DenseMultilinearExtension::from_evaluations_ext_vec(
        (0..num_coeffs)
            .map(<F as Field>::BasePrimeField::from)
            .collect(),
    );
    let points: Vec<_> = (0..num_evaluations)
        .map(|i| Vec(vec![F::from_u64(i as u64); num_variables]))
        .collect();
    let evaluations = points
        .iter()
        .map(|point| polynomial.evaluate_at_extension(point))
        .collect();

    let statement = Statement {
        points,
        evaluations,
    };

    let whir_prover_time = Instant::now();

    let committer = Committer::new(params.clone());
    let witness = committer.commit(&mut transcript, polynomial).unwrap();

    let prover = Prover(params.clone());

    let proof = prover
        .prove(&mut transcript, statement.clone(), witness)
        .unwrap();

    println!("Prover time: {:.1?}", whir_prover_time.elapsed());
    println!(
        "Proof size: {:.1} KiB",
        whir_proof_size(transcript.transcript(), &proof) as f64 / 1024.0
    );

    // Just not to count that initial inversion (which could be precomputed)
    let verifier = Verifier::new(params);

    HashCounter::reset();
    let whir_verifier_time = Instant::now();
    for _ in 0..reps {
        let mut arthur = io.to_arthur(transcript.transcript());
        verifier.verify(&mut arthur, &statement, &proof).unwrap();
    }
    println!(
        "Verifier time: {:.1?}",
        whir_verifier_time.elapsed() / reps as u32
    );
    println!(
        "Average hashes: {:.1}k",
        (HashCounter::get() as f64 / reps as f64) / 1000.0
    );
}
