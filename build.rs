fn main() {
    println!("cargo:rerun-if-env-changed=RAYON_NUM_THREADS");
}
