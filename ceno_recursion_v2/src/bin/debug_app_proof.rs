#[cfg(debug_assertions)]
use std::{fs, path::PathBuf, sync::Arc};

#[cfg(debug_assertions)]
use ceno_recursion_v2::{
    continuation::prover::{AggProver, AggregationOptions},
    system::{RecursionProof, RecursionVk, utils::test_system_params_zero_pow},
};
#[cfg(debug_assertions)]
use clap::Parser;
#[cfg(debug_assertions)]
use eyre::{Context, Result};

#[cfg(debug_assertions)]
#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    proof: PathBuf,
    #[arg(long)]
    vk: PathBuf,
}

#[cfg(debug_assertions)]
fn main() -> Result<()> {
    let args = Args::parse();
    let proofs: Vec<RecursionProof> = bincode::deserialize(
        &fs::read(&args.proof)
            .wrap_err_with(|| format!("read proof fixture {}", args.proof.display()))?,
    )
    .wrap_err("decode proof fixture")?;
    let mut vk: RecursionVk = bincode::deserialize(
        &fs::read(&args.vk).wrap_err_with(|| format!("read vk fixture {}", args.vk.display()))?,
    )
    .wrap_err("decode vk fixture")?;
    vk.rebuild_circuit_index();

    let matrix_chips = proofs
        .iter()
        .flat_map(|proof| proof.chip_proofs.values())
        .filter(|chip| chip.matrix_reduction.is_some())
        .count();
    assert!(matrix_chips > 0, "fixture has no matrix reduction proof");

    let options = AggregationOptions::new(test_system_params_zero_pow(5, 17, 3));
    let prover = AggProver::<2, 2>::new(Arc::new(vk), options);
    prover.debug_app_proof_constraints(&proofs);
    println!(
        "recursion-v2 app replay constraints verified: proofs={} matrix_chips={matrix_chips}",
        proofs.len()
    );
    Ok(())
}

#[cfg(not(debug_assertions))]
fn main() {
    panic!("debug_app_proof must be built with debug assertions");
}
