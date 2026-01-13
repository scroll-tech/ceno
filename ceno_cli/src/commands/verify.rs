use crate::utils::print_cargo_message;
use anyhow::{Context, bail};
use ceno_zkvm::{
    e2e::{FieldType, PcsKind, verify},
    scheme::{
        ZKVMProof,
        verifier::{RV32imMemStateConfig, ZKVMVerifier},
    },
    structs::ZKVMVerifyingKey,
};
use clap::Parser;
use ff_ext::{BabyBearExt4, ExtensionField, GoldilocksExt2};
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme, Whir, WhirDefaultSpec};
use serde::Serialize;
use std::{fs::File, path::PathBuf};

#[derive(Parser)]
#[command(name = "run", about = "Verify a Ceno proof")]
pub struct VerifyCmd {
    /// The polynomial commitment scheme to use.
    #[arg(long, value_enum, default_value_t = PcsKind::default())]
    pcs: PcsKind,
    /// The field to use, eg. goldilocks
    #[arg(long, value_enum, default_value_t = FieldType::default())]
    field: FieldType,

    /// Path to the serialized proof file
    #[clap(long)]
    proof: PathBuf,
    /// Path to the verifying key file
    #[clap(long)]
    vk: PathBuf,
}

impl VerifyCmd {
    pub fn run(self) -> anyhow::Result<()> {
        match (self.pcs, self.field) {
            (PcsKind::Basefold, FieldType::Goldilocks) => {
                run_inner::<GoldilocksExt2, Basefold<GoldilocksExt2, BasefoldRSParams>>(self)
            }
            (PcsKind::Basefold, FieldType::BabyBear) => {
                run_inner::<BabyBearExt4, Basefold<BabyBearExt4, BasefoldRSParams>>(self)
            }
            (PcsKind::Whir, FieldType::Goldilocks) => {
                run_inner::<GoldilocksExt2, Whir<GoldilocksExt2, WhirDefaultSpec>>(self)
            }
            (PcsKind::Whir, FieldType::BabyBear) => {
                run_inner::<BabyBearExt4, Whir<BabyBearExt4, WhirDefaultSpec>>(self)
            }
        }
    }
}

fn run_inner<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + Serialize>(
    args: VerifyCmd,
) -> anyhow::Result<()> {
    let start = std::time::Instant::now();

    let zkvm_proofs: Vec<ZKVMProof<E, PCS>> =
        bincode::deserialize_from(File::open(&args.proof).context("Failed to open proof file")?)
            .context("Failed to deserialize proof file")?;
    print_cargo_message(
        "Loaded",
        format_args!(
            "proof from {} in {:.2}s",
            args.proof.canonicalize().unwrap().display(),
            start.elapsed().as_secs_f32()
        ),
    );

    let start = std::time::Instant::now();
    let vk: ZKVMVerifyingKey<E, PCS, RV32imMemStateConfig> =
        bincode::deserialize_from(File::open(&args.vk).context("Failed to open vk file")?)
            .context("Failed to deserialize vk file")?;
    print_cargo_message(
        "Loaded",
        format_args!(
            "verifying key from {} in {:.2}s",
            args.vk.canonicalize().unwrap().display(),
            start.elapsed().as_secs_f32()
        ),
    );

    let start = std::time::Instant::now();
    let verifier = ZKVMVerifier::new(vk);
    if let Err(e) = verify(zkvm_proofs, &verifier) {
        bail!("Verification failed: {e:?}");
    }

    print_cargo_message(
        "Verified",
        format_args!("in {:.2}s", start.elapsed().as_secs_f32()),
    );
    Ok(())
}
