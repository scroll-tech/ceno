# Getting Started

This chapter will guide you through setting up your local development environment for Ceno and running your first zero-knowledge program.

## Local Build Requirements

Ceno is built in Rust, so you must [install the Rust toolchain](https://www.rust-lang.org/tools/install) first.

We also use `cargo-make` to orchestrate the build process. You can install it with the following command:

```sh
cargo install cargo-make
```

Ceno executes RISC-V instructions, so you will also need to install the Risc-V target for Rust. You can do this with the following command:

```sh
rustup target add riscv32im-unknown-none-elf
```

## Running an Example

The Ceno project includes a variety of [examples](https://github.com/scroll-tech/ceno/tree/master/examples/examples) to help you get started. We will run the Fibonacci example.

This example calculates the `n`-th Fibonacci number, where `n` is determined by a hint value provided at runtime. For this guide, we will calculate the 1024-th number (corresponding to hint value `10` as `2^10=1024`) in the sequence.

Execute the following command in the Ceno repository root directory to compile and run the end-to-end example:

```sh
RUST_LOG=info cargo run --release --package ceno_zkvm --bin e2e -- --platform=ceno --hints=10 --public-io=4191 examples/target/riscv32im-ceno-zkvm-elf/release/examples/fibonacci
```

Let's break down the command:

- `cargo run --release --package ceno_zkvm --bin e2e`: This command runs the end-to-end test binary from the `ceno_zkvm` crate in release mode.
- `--platform=ceno`: Specifies that we are running on the Ceno zkVM.
- `--hints=10`: This is a private input to our program. In this case, it tells the program to run 2^10 (1024) Fibonacci steps.
- `--public-io=4191`: This is the expected public output. The program will verify that the result of the computation matches this value.
- `examples/target/riscv32im-ceno-zkvm-elf/release/examples/fibonacci`: This is the path to the compiled guest program.

If the command runs successfully, you have just run your first ZK program with Ceno! The next chapter will dive into the code for this example.
