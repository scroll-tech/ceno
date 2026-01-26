# Run, prove, and keygen

The `run`, `prove`, and `keygen` commands are used to execute Ceno programs. They all share a similar set of options.

- `cargo ceno run`: Executes a Ceno program in the ZKVM.
- `cargo ceno prove`: Executes a Ceno program and generates a proof of its execution.
- `cargo ceno keygen`: Generates a proving key and a verification key for a Ceno program.

## Usage

```bash
cargo ceno run [OPTIONS]
cargo ceno prove [OPTIONS]
cargo ceno keygen [OPTIONS]
```

## Options

These commands accept all the same options as `cargo build`. Some of the most common options are:

- `--example <NAME>`: Run a specific example.
- `--release`: Run in release mode.
- `--package <NAME>` or `-p <NAME>`: Specify which package to run.

In addition, the `prove` and `keygen` commands have some Ceno-specific options:

- `--proof <PATH>`: Path to the output proof file (for `prove`). Defaults to `proof.bin`.
- `--out-vk <PATH>`: Path to the output verification key file (for `keygen`). Defaults to `vk.bin`.

For a full list of options, run `cargo ceno <COMMAND> --help`.
