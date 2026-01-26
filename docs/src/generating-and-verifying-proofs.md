# Generating and Verifying Proofs

The `cargo ceno` command provides a streamlined workflow for generating and verifying proofs of your ZK programs. This
is handled primarily by the `keygen`, `prove` and `verify` subcommands.

Here's a more detailed look at the steps involved in generating a proof:

1. **Key Generation (`cargo ceno keygen`):** Before proving, you need a proving key and a verification key. The `keygen`
   command generates these keys for a given guest program.

   ```bash
   cargo ceno keygen --example <GUEST_EXAMPLE_NAME> --out-vk <PATH_TO_VERIFICATION_KEY_FILE>
   ```

2. **Proof Generation (using the witness):** The final step is to use the proving key and the witness to generate the
   proof. The `prove` command automates this, but you can also perform this step manually using the lower-level
   `raw-prove` command if you have the ELF file, proving key, and witness.

By using `cargo ceno prove`, you get a simplified experience that handles these steps for you. For most use cases,
`cargo ceno prove` and `cargo ceno verify` are the primary commands you will use.

```bash
cargo ceno prove --example <GUEST_EXAMPLE_NAME> --hints=<HINTS_SEPARATED_BY_COMMA> --public-io=<PUBLIC_IO> --out-proof target/fibonacci.proof
```

## Concrete Example

You can use `ceno` to generate proofs for your own custom Rust programs. Let's walk through how to set up a new project
and use `ceno` with it.

### 1. Project Setup

First, create a new binary crate with `cargo`:

```bash
cargo new my-ceno-program
cd my-ceno-program
```

Your project will have the following structure:

```
my-ceno-program/
├── Cargo.toml
└── src/
    └── main.rs
```

### 2. Cargo.toml

Next, you need to add `ceno_rt` as a dependency in your `Cargo.toml`. `ceno_rt` provides the runtime environment and
syscalls for guest programs.

```toml
[package]
name = "my-ceno-program"
version = "0.1.0"
edition = "2024"

[dependencies]
ceno_rt = { git = "https://github.com/scroll-tech/ceno.git" }
rkyv = { version = "0.8", default-features = false, features = [
    "alloc",
    "bytecheck",
] }
```

_Note: For local development, you can use a path dependency: `ceno_rt = { path = "../ceno/ceno_rt" }`_

Special notes, as ceno rely on nightly rust toolchain, please also add file `rust-toolchain.toml` with example content

```toml
[toolchain]
# refer toolchain from https://github.com/scroll-tech/ceno/blob/master/rust-toolchain.toml#L2
channel = "nightly-2025-11-20"
targets = ["riscv32im-unknown-none-elf"]
# We need the sources for build-std.
components = ["rust-src"]
```

### 3. Writing the Guest Program

Now, let's write a simple guest program in `src/main.rs`. This program will read one `u32` values from the input, add a
constant to it, and write the result to the output.

```rust
extern crate ceno_rt;

fn main() {
    let a: u32 = ceno_rt::read();
    let b: u32 = 3;
    let c = a.wrapping_add(b);

    ceno_rt::commit(&c);
}
```

### 4. Building, Proving, and Verifying

With your custom program ready, you can use `ceno` to manage the workflow. These commands are typically run from the
root of your project (`my-ceno-program`).

#### 4.1. Build the program

The `build` command compiles your guest program into a RISC-V ELF file.

```bash
cargo ceno build
```

This will create an ELF file at `target/riscv32im-ceno-zkvm-elf/debug/my-ceno-program`.

#### 4.2. Generate Keys

Next, generate the proving and verification keys.

```bash
cargo ceno keygen --out-vk vk.bin
```

This will save the keys in a `keys` directory.

#### 4.3. Generate a Proof

Now, run the program and generate a proof. You can provide input via the `--stdin` flag.

```bash
cargo ceno prove --hints=5 --public-io=8 --out-proof proof.bin
```

This command executes the ELF, generates a proof, and saves it as `proof.bin`.

#### 4.4. Providing Inputs via File

In addition to providing hints and public I/O directly on the command line, you can also use files to provide these
inputs. This is particularly useful for larger inputs or when you want to reuse the same inputs across multiple runs.

**Hints via File**

You can provide hints to the prover using the `--hints-file` flag. The hints file should be a raw binary file containing
the hint data. You can create this file using a simple Rust program. For example, to create a hints file with the value
`5u32` and `8u32`:

```rust
use std::fs::File;
use std::io::Write;

fn main() {
    let mut file = File::create("hints.bin").unwrap();
    file.write_all(&5u32.to_le_bytes()).unwrap();
}
```

Then, you can use this file when generating a proof:

```bash
cargo ceno prove --hints-file hints.bin --public-io=8 --out-proof proof.bin
```

This approach is useful when you have a large amount of hint data that is inconvenient to pass through the command line.

#### 4.5. Verify the Proof

Finally, verify the generated proof.

```bash
cargo ceno verify --vk vk.bin --proof proof.bin
```

If the proof is valid, you'll see a success message. This workflow allows you to integrate `ceno`'s proving capabilities
into your own Rust projects.
