use crate::utils::print_cargo_message;
use anyhow::{Context, bail};
use ceno_zkvm::{
    e2e::verify,
    scheme::{ZKVMProof, verifier::ZKVMVerifier},
    structs::ZKVMVerifyingKey,
};
use clap::Parser;
use ff_ext::GoldilocksExt2;
use mpcs::{Basefold, BasefoldRSParams};
use std::{fs::File, path::PathBuf};

#[derive(Parser)]
#[command(name = "run", about = "Verify a Ceno proof")]
pub struct VerifyCmd {
    /// Path to the serialized proof file
    #[clap(long)]
    proof: PathBuf,
    /// Path to the verifying key file
    #[clap(long)]
    vk: PathBuf,
}

impl VerifyCmd {
    pub fn run(self) -> anyhow::Result<()> {
        type E = GoldilocksExt2;
        type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;

        let start = std::time::Instant::now();
        let zkvm_proof: ZKVMProof<E, Pcs> = bincode::deserialize_from(
            File::open(&self.proof).context("Failed to open proof file")?,
        )
        .context("Failed to deserialize proof file")?;
        print_cargo_message(
            "Loaded",
            format_args!(
                "proof from {} in {:.2}s",
                self.proof.canonicalize().unwrap().display(),
                start.elapsed().as_secs_f32()
            ),
        );

        let start = std::time::Instant::now();
        let vk: ZKVMVerifyingKey<E, Pcs> =
            bincode::deserialize_from(File::open(&self.vk).context("Failed to open vk file")?)
                .context("Failed to deserialize vk file")?;
        print_cargo_message(
            "Loaded",
            format_args!(
                "verifying key from {} in {:.2}s",
                self.vk.canonicalize().unwrap().display(),
                start.elapsed().as_secs_f32()
            ),
        );

        let start = std::time::Instant::now();
        let verifier = ZKVMVerifier::new(vk);
        if let Err(e) = verify(&zkvm_proof, &verifier) {
            bail!("Verification failed: {e:?}");
        }
        print_cargo_message(
            "Verified",
            format_args!("in {:.2}s", start.elapsed().as_secs_f32()),
        );
        Ok(())
    }
}
