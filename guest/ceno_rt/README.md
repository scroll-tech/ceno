# Ceno VM Runtime

This crate provides the runtime for program running on the Ceno VM. It provides:

- Configuration of compilation and linking.
- Program startup and termination.
- Memory setup.

### Build examples

```bash
rustup target add riscv32im-unknown-none-elf

cargo build --release --examples
```

### Development tools

```bash
cargo install cargo-binutils
rustup component add llvm-tools

# Look at the disassembly of a compiled program.
cargo objdump --release --example ceno_rt_mini -- --all-headers --disassemble
```
