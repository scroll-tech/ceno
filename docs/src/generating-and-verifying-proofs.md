# Generating and Verifying Proofs

The `cargo ceno` command provides a streamlined workflow for generating and verifying proofs of your ZK programs. This is handled primarily by the `keygen`, `prove` and `verify` subcommands.

Here's a more detailed look at the steps involved in generating a proof:

1.  **Key Generation (`cargo ceno keygen`):** Before proving, you need a proving key and a verification key. The `keygen` command generates these keys for a given guest program.

    ```bash
    cargo ceno keygen --example <GUEST_EXAMPLE_NAME> --out-vk <PATH_TO_VERIFICATION_KEY_FILE>
    ```

2.  **Proof Generation (using the witness):** The final step is to use the proving key and the witness to generate the proof. The `prove` command automates this, but you can also perform this step manually using the lower-level `raw-prove` command if you have the ELF file, proving key, and witness.

By using `cargo ceno prove`, you get a simplified experience that handles these steps for you. For most use cases, `cargo ceno prove` and `cargo ceno verify` are the primary commands you will use.

```bash
cargo ceno prove --example <GUEST_EXAMPLE_NAME> --hints=<HINTS_SEPARATED_BY_COMMA> --public-io=<PUBLIC_IO> --out-vk <PATH_TO_VERIFICATION_KEY_FILE> --out-proof target/fibonacci.proof
```

## Concrete Example: Fibonacci

Let's walk through a concrete example using the `fibonacci` guest program included in the `examples` directory.

### 1. Writing the Code

The `fibonacci` example is already written. You can find it in `examples/examples/fibonacci.rs`. This program calculates the `n`-th Fibonacci number.

### 2. Key Generation

Before generating a proof, you need to generate a verification key. You can do this with the `keygen` subcommand:

```bash
cargo ceno keygen --example fibonacci --out-vk target/fibonacci.vk
```

This will create a `fibonacci.vk` file (the verification key) in the `target` directory.

### 3. Generating the Proof

To generate a proof for the `fibonacci` program, run the following command from the root of the project:

```bash
cargo ceno prove --example fibonacci --out-proof target/fibonacci.proof
```

This command will compile the `fibonacci` package, execute it in the ZKVM, and generate a proof file named `fibonacci.proof` in the `target` directory. It will also generate the verification key.

### 4. Verifying the Proof

Now that you have a proof file, you can verify it with the following command:

```bash
cargo ceno verify --proof target/fibonacci.proof --vk target/fibonacci.vk
```

If the proof is valid, you will see a confirmation message, and the command will exit successfully.

## Using a custom program

You can also use `ceno` to generate proofs for your own custom Rust programs. Let's walk through how to set up a new project and use `ceno` with it.

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

Next, you need to add `ceno_rt` as a dependency in your `Cargo.toml`. `ceno_rt` provides the runtime environment and syscalls for guest programs.

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

### 3. Writing the Guest Program

Now, let's write a simple guest program in `src/main.rs`. This program will read two `u32` values from the input, add them, and write the result to the output.

```rust
extern crate ceno_rt;
use rkyv::Archived;

fn main() {
    let a: &Archived<u32> = ceno_rt::read();
    let a: u32 = a.into();
    let b: u32 = 3;
    let c = a.wrapping_add(b);

    ceno_rt::commit::<Archived<u32>, _>(&c);
}
```

### 4. Building, Proving, and Verifying

With your custom program ready, you can use `ceno` to manage the workflow. These commands are typically run from the root of your project (`my-ceno-program`).

1.  **Build the program:**

    The `build` command compiles your guest program into a RISC-V ELF file.

    ```bash
    cargo ceno build
    ```

    This will create an ELF file at `target/riscv32im-ceno-zkvm-elf/debug/my-ceno-program`.

2.  **Generate Keys:**

    Next, generate the proving and verification keys.

    ```bash
    cargo ceno keygen --out-vk vk.bin
    ```

    This will save the keys in a `keys` directory.

3.  **Generate a Proof:**

    Now, run the program and generate a proof. You can provide input via the `--stdin` flag.

    ```bash
    cargo ceno prove --hints=5 --public-io=8 --out-proof proof.bin
    ```

    This command executes the ELF, generates a proof, and saves it as `proof.bin`. The output of the program will be printed to your console.

4.  **Verify the Proof:**

    Finally, verify the generated proof.

    ```bash
    cargo ceno verify --vk vk.bin --proof proof.bin
    ```

If the proof is valid, you'll see a success message. This workflow allows you to integrate `ceno`'s proving capabilities into your own Rust projects.
