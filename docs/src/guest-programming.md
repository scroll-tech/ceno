# Guest Programming (`ceno_rt`)

The `ceno_rt` crate provides the runtime environment for guest programs running inside the Ceno ZKVM. It offers essential functionalities for interacting with the host and the ZKVM environment.

Key features of `ceno_rt` include:

- **I/O:** Functions for reading input from the host and writing output. See the `ceno_rt::io` module.
- **Memory Management:** A simple allocator for dynamic memory allocation within the guest. See the `ceno_rt::allocator` module.
- **Syscalls:** Low-level functions to access precompiled operations for performance-critical tasks. See the `ceno_rt::syscalls` module and the "Accelerated Operations with Precompiles" chapter.
- **Panicking:** Macros and functions for handling unrecoverable errors in the guest.

When writing a guest program, you will typically include `ceno_rt` as a dependency in your `Cargo.toml`.
