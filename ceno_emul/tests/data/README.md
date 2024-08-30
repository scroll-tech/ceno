### Generate test programs:

```bash
cd ceno_rt
cargo build --release
cp ../target/riscv32im-unknown-none-elf/release/ceno_rt ../ceno_emul/tests/data/ceno_rt_mini
```