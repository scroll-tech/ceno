### Generate test programs:

```bash
cd ceno_rt
cargo build --release --examples
cp ../target/riscv32im-unknown-none-elf/release/examples/ceno_rt_{mini,panic,mem} ../ceno_emul/tests/data/
```