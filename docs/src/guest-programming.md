# Guest Programming (`ceno_rt`)

The `ceno_rt` crate provides the runtime environment for guest programs running inside the Ceno ZKVM. It offers essential functionalities for interacting with the host and the ZKVM environment.

## Execution Environment

A guest program's execution begins at the `_start` symbol, which is defined in `ceno_rt`. This entry point sets up the global pointer and stack, and then calls the standard Rust `main` function.

After `main` returns, or to exit explicitly, the program can call `ceno_rt::halt(exit_code)`. An `exit_code` of 0 indicates success.

## Key features of `ceno_rt` include:

### Memory-Mapped I/O (`mmio`)

The `ceno_rt::mmio` module provides a way to read data provided by the host through memory-mapped regions.

- **Hints**: These are private inputs from the host. You can read them using `ceno_rt::mmio::read_slice()` to get a byte slice or `ceno_rt::mmio::read::<T>()` to deserialize a specific type.
- **Public I/O**: The `ceno_rt::mmio::commit` function is used to reveal public outputs. It verifies that the output produced by the guest matches the expected output provided by the host.

### Standard I/O (`io`)

The `ceno_rt::io` module contains `IOWriter` for writing data. In debug builds, a global `IOWriter` instance is available through `ceno_rt::io::info_out()`. You can use the `debug_print!` and `debug_println!` macros for logging during development.

### Dynamic Memory (`allocator`)

For dynamic memory needs, `ceno_rt::allocator` provides a simple allocator.

### System Calls (`syscalls`)

The `ceno_rt::syscalls` module offers low-level functions to access precompiled operations for performance-critical tasks. For more details, see the "Accelerated Operations with Precompiles" chapter.

### Weakly Linked Functions

`ceno_rt` defines several weakly linked functions (e.g., `sys_write`, `sys_alloc_words`, `sys_rand`) that provide default implementations for certain system-level operations. These can be overridden by the host environment.

When writing a guest program, you will typically include `ceno_rt` as a dependency in your `Cargo.toml`.