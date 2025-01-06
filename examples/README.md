# Ceno VM examples guest programs

You can directly build the RiscV examples by running the following commands:

```bash
rustup target add riscv32im-unknown-none-elf
cargo build --release --examples
```

But that won't be very useful by itself.  You probably want to execute and prove these examples.  Have a look at [test\_elf.rs](../ceno_host/tests/test_elf.rs)
and the [examples-builder](../examples-builder/) for one way to run the examples from tests.  Or see [the end-to-end integration tests](../.github/workflows/integration.yml) for how to run the examples as stand-alone ELF files.
