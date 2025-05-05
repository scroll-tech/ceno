# Ceno: Non-uniform, Segment and Parallel Risc-V Zero-knowledge Virtual Machine

Please see [the slightly outdated paper](https://eprint.iacr.org/2024/387) for an introduction to Ceno.

🚧 This project is currently under construction and not suitable for use in production. 🚧

If you are unfamiliar with the RISC-V instruction set, please have a look at the [RISC-V instruction set reference](https://github.com/jameslzhu/riscv-card/releases/download/latest/riscv-card.pdf).

## Local build requirements

Ceno is built in Rust, so [installing the Rust toolchain](https://www.rust-lang.org/tools/install) is a pre-requisite if you want to develop on your local machine.  We also use [cargo-make](https://sagiegurari.github.io/cargo-make/) to build Ceno. You can install cargo-make with the following command:

```sh
cargo install cargo-make
```

You will also need to install the Risc-V target for Rust. You can do this with the following command:

```sh
rustup target add riscv32im-unknown-none-elf
```

## Try end-to-end with examples
A variety of [examples](https://github.com/scroll-tech/ceno/tree/master/examples/examples) are availables.

To run an example in e2e, use the following command:

```sh
cargo run --release --package ceno_zkvm --bin e2e -- \
    --profiling=1 \
    --platform=ceno \
    --hints=<hint value> \
    --public-io=<pub io> \
    examples/target/riscv32im-ceno-zkvm-elf/release/examples/<example name>
```

The example will be automatically compiled before execution

For instance, with [fibonacci](https://github.com/scroll-tech/ceno/blob/master/examples/examples/fibonacci.rs)

```sh
cargo run --release --package ceno_zkvm --bin e2e -- --profiling=1 --platform=ceno --hints=10 --public-io=4191 examples/target/riscv32im-ceno-zkvm-elf/release/examples/fibonacci
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
cargo build
```

### Setting up self-hosted CI docker container

To set up docker container for CI, you can run the following command:

```sh
docker build -t ceno-runner scripts/ci/
docker run -d ceno-runner
```
