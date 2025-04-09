# Ceno VM Runtime

This crate provides the runtime for programs running on the Ceno VM. It provides:

- Configuration of compilation and linking.
- Program startup and termination.
- Memory setup.

### Build examples

See the [examples](../examples/) directory for example programs.

### Updating the RISC-V target

From time to time the Rust compiler or LLVM change enough so that we need to update our configuration files for building.  Especially [the JSON target specification](riscv32im-ceno-zkvm-elf.json).

Unfortunately, the exact details border on black magic.  But you can generally try to follow [The Embedonomicon](https://docs.rust-embedded.org/embedonomicon/custom-target.html) and start with the output of this:

```
rustc +nightly -Z unstable-options --print target-spec-json --target riscv32im-unknown-none-elf
```
