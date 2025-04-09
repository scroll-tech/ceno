use glob::glob;
use std::{fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Path to the file that, when changed, should trigger a cache cleanup
    let watched_file = "src/scheme/mock_prover.rs";

    // Path to the cache file to remove when the watched file changes
    let cache_file = "table_cache_dev_*";

    // Instruct Cargo to rerun this script if the watched file changes
    println!("cargo:rerun-if-changed={}", watched_file);

    // Use the glob crate to find files matching the pattern
    for entry in glob(cache_file)? {
        match entry {
            Ok(path) => {
                // Check if the path exists and delete it
                if Path::new(&path).exists() {
                    fs::remove_file(&path)?;
                    println!("Deleted file: {}", path.display());
                }
            }
            Err(e) => println!("Error reading file: {:?}", e),
        }
    }

    Ok(())
}
