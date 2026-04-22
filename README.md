# Ceno: Non-uniform, Segment and Parallel Risc-V Zero-knowledge Virtual Machine

[Run Book](https://scroll-tech.github.io/ceno/) | [Try Examples](#try-end-to-end-with-examples) | [Paper](https://eprint.iacr.org/2024/387)

🚧 This project is currently under construction and not suitable for use in production. 🚧

If you are unfamiliar with the RISC-V instruction set, please have a look at
the [RISC-V instruction set reference](https://github.com/jameslzhu/riscv-card/releases/download/latest/riscv-card.pdf).

## Installing Ceno command line tools

The `cargo ceno` command is the primary tool for interacting with the Ceno zkVM. You can install it by running the
following command from the root of the repository:

```sh
cargo install --path ceno_cli
```

## Try end-to-end with examples

A variety of [examples](https://github.com/scroll-tech/ceno/tree/master/examples/examples) are availables.

To run an example, you first need to build it. You can run a specific example using the `cargo ceno run` command. For
instance, to run the [fibonacci](https://github.com/scroll-tech/ceno/blob/master/examples/examples/fibonacci.rs)
example, use the following command:

```sh
cargo ceno run --example fibonacci --hints=10 --public-io=4191
```

This command runs **2^10 (1024) Fibonacci steps** via `--hints=10`. The expected result is `4191`, which is verified
against the `--public-io=4191` argument.

## Local build requirements

Ceno is built in Rust, so [installing the Rust toolchain](https://www.rust-lang.org/tools/install) is a pre-requisite if
you want to develop on your local machine. We also use [cargo-make](https://sagiegurari.github.io/cargo-make/) to build
Ceno. You can install cargo-make with the following command:

```sh
cargo install cargo-make
```

You will also need to install the Risc-V target for Rust. You can do this with the following command:

```sh
rustup target add riscv32im-unknown-none-elf
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

### Acknowledgements

Ceno stands on the shoulders of remarkable projects in the zero-knowledge ecosystem.
We extend our appreciation to the following works, which have shaped Ceno's design and direction:

- [Plonky3](https://github.com/Plonky3/Plonky3) — Inspired by Plonky3’s modular architecture, enabling support for
  diverse field arithmetics.
- [OpenVM](https://github.com/openvm-org/openvm) — Ceno's recursion stack builds upon OpenVM's eDSL + native VM, while
  also borrowing its limb-based constraint design for RISC-V opcodes.
- [SP1](https://github.com/succinctlabs/sp1) — Derived significant insights from SP1's RISC-V emulator and memory
  layout strategy.
