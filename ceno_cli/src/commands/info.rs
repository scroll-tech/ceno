use clap::Parser;

#[derive(Parser)]
#[command(name = "info", about = "Show info of current ceno cli")]
pub struct InfoCmd;


impl InfoCmd {
    pub fn run(self) -> anyhow::Result<()> {
        eprintln!("OS: {}", std::env::consts::OS);
        eprintln!("Arch: {}", std::env::consts::ARCH);

        let mut enabled_features = vec![];

        if cfg!(debug_assertions) {
            enabled_features.push("debug_assertions");
        }

        if cfg!(feature = "nightly-features") {
            enabled_features.push("nightly-features");
        }

        if cfg!(target_feature = "neon") {
            enabled_features.push("neon");
        }
        if cfg!(target_feature = "avx2") {
            enabled_features.push("avx2");
        }
        if cfg!(target_feature = "avx512f") {
            enabled_features.push("avx512f");
        }
        
        if cfg!(target_feature = "sha3") {
            enabled_features.push("sha3");
        }
        
        eprintln!("Enabled features: {}", enabled_features.join(", "));
        Ok(())
    }
}
