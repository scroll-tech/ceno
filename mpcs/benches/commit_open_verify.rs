#[cfg(feature = "benchmark")]
use goldilocks::GoldilocksExt2;
#[cfg(feature = "benchmark")]
use mpcs::{
    test_util::{run_batch_commit_open_verify, run_commit_open_verify},
    util::transcript::PoseidonTranscript,
    Basefold, BasefoldDefaultParams,
};
#[cfg(feature = "benchmark")]
type PcsGoldilocks = Basefold<GoldilocksExt2, BasefoldDefaultParams>;

#[cfg(feature = "benchmark")]
fn commit_open_verify_goldilocks_base() {
    // Challenge is over extension field, poly over the base field
    run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<GoldilocksExt2>>(
        true, 20, 21,
    );
}

#[cfg(feature = "benchmark")]
fn commit_open_verify_goldilocks_2() {
    // Both challenge and poly are over extension field
    run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<_>>(false, 20, 21);
}

#[cfg(feature = "benchmark")]
fn batch_commit_open_verify_goldilocks_base() {
    // Both challenge and poly are over base field
    run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<GoldilocksExt2>>(
        true, 20, 21,
    );
}

#[cfg(feature = "benchmark")]
fn batch_commit_open_verify_goldilocks_2() {
    // Both challenge and poly are over extension field
    run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<_>>(
        false, 20, 21,
    );
}

#[cfg(feature = "benchmark")]
fn main() {
    commit_open_verify_goldilocks_base();
    commit_open_verify_goldilocks_2();
    batch_commit_open_verify_goldilocks_base();
    batch_commit_open_verify_goldilocks_2();
}

#[cfg(not(feature = "benchmark"))]
fn main() {
    panic!("Please run with --features 'benchmark'")
}
