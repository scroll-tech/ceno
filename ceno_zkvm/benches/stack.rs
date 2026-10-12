//! Helpers for running Criterion benches on a larger OS thread stack.
//!
//! Criterion's generated `main` (via `criterion_main!`) does not spawn a
//! thread that respects `RUST_MIN_STACK`, and linker stack-size flags are also
//! unreliable for these benches. Use [`run_with_stack`] from a custom `main`
//! instead — it honors `RUST_MIN_STACK` when set, otherwise the provided default.

/// Default stack used by weierstrass precompile benches (32 MiB).
pub const DEFAULT_BENCH_STACK: usize = 32 * 1024 * 1024;

/// Resolve the stack size for bench worker threads.
///
/// Prefers `RUST_MIN_STACK` (bytes) when set and parseable, otherwise `default`.
pub fn bench_stack_size(default: usize) -> usize {
    std::env::var("RUST_MIN_STACK")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

/// Run `f` on a dedicated thread with [`bench_stack_size`].
pub fn run_with_stack(default: usize, f: impl FnOnce() + Send + 'static) {
    let stack_size = bench_stack_size(default);
    std::thread::Builder::new()
        .stack_size(stack_size)
        .spawn(f)
        .expect("failed to spawn bench thread")
        .join()
        .expect("bench thread panicked");
}
