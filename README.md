# Ceno: Non-uniform, Segment and Parallel Risc-V Zero-knowledge Virtual Machine

Please see [the slightly outdated paper](https://eprint.iacr.org/2024/387) for an introduction to Ceno.

🚧 This project is currently under construction and not suitable for use in production. 🚧

If you are unfamiliar with the RISC-V instruction set, please have a look at the [RISC-V instruction set reference](https://github.com/jameslzhu/riscv-card/blob/master/riscv-card.pdf).

## Local build requirements

Ceno is built in Rust, so [installing the Rust toolchain](https://www.rust-lang.org/tools/install) is a pre-requisite, if you want to develop on your local machine.  We also use [cargo-make](https://sagiegurari.github.io/cargo-make/) to build Ceno. You can install cargo-make with the following command:

```sh
cargo install cargo-make
```

## Building Ceno and running tests

To run the tests, you can use the following command:

```sh
cargo make tests
```

Clippy and check work as usual:

```sh
cargo check
cargo clippy
```

Neither `cargo build` nor `cargo make build` work.  That's a known problem and we're working on it.
