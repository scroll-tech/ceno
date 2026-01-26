# Getting Started

This chapter will guide you through setting up your local development environment for Ceno and running your first
zero-knowledge program.

## Local Build Requirements

Ceno is built in Rust, so you must [install the Rust toolchain](https://www.rust-lang.org/tools/install) first.

We also use `cargo-make` to orchestrate the build process. You can install it with the following command:

```sh
cargo install cargo-make
```

Ceno executes RISC-V instructions, so you will also need to install the Risc-V target for Rust. You can do this with the
following command:

```sh
rustup target add riscv32im-ceno-zkvm-elf
```

## Installing `cargo ceno`

The `cargo ceno` command is the primary tool for interacting with the Ceno zkVM. You can install it by running the
following command from the root of the repository:

```sh
JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,metadata_thp:always,thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true" \
    cargo install --git https://github.com/scroll-tech/ceno.git --features jemalloc --features nightly-features cargo-ceno
```

## Building the Examples

The Ceno project includes a variety of [examples](https://github.com/scroll-tech/ceno/tree/master/examples/examples) to
help you get started.

You can build all the examples using the `cargo ceno` command-line tool. Execute the following command in the Ceno
repository root directory:

```sh
cargo ceno build --example fibonacci
```

This command will compile the example `fibonacci` located in the `examples/examples` directory and place the resulting
ELF files in the `examples/target/riscv32im-ceno-zkvm-elf/release` directory.

## Running an Example

Once the examples are built, you can run any of them using the `cargo ceno run` command. We will run the Fibonacci
example.

This example calculates the `n`-th Fibonacci number, where `n` is determined by a hint value provided at runtime. For
this guide, we will calculate the 1024-th number (corresponding to hint value `10` as `2^10=1024`) in the sequence.

Execute the following command in the Ceno repository root directory to run the Fibonacci example with prove/verify:

```sh
cargo ceno prove --example fibonacci --hints=10 --public-io=4191
```

Let's break down the command:

- `cargo ceno prove`: This is the command to prove a Ceno program.
- `--example fibonacci`: This specifies that we want to run the `fibonacci` example.
- `--hints=10`: This is a private input to our program. In this case, it tells the program to run 2^10 (1024) Fibonacci
  steps.
- `--public-io=4191`: This is the expected public output. The program will verify that the result of the computation
  matches this value.

If the command runs successfully, you have just run your first ZK program with Ceno! The next chapter will dive into the
code for this example.
