# Raw Commands

The `raw-run`, `raw-prove`, and `raw-keygen` commands are lower-level commands that operate on ELF files directly. These are useful for debugging and for integrating Ceno with other build systems.

## `cargo ceno raw-run`

Executes a pre-compiled ELF file in the Ceno ZKVM.

### Usage

```bash
cargo ceno raw-run <ELF_PATH>
```

## `cargo ceno raw-prove`

Generates a proof for a pre-compiled ELF file.

### Usage

```bash
cargo ceno raw-prove <ELF_PATH>
```

## `cargo ceno raw-keygen`

Generates a proving key and a verification key for a pre-compiled ELF file.

### Usage

```bash
cargo ceno raw-keygen <ELF_PATH>
```
