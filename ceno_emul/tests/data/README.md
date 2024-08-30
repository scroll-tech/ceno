### Generate test programs:

```bash
cd ceno_rt
cargo build --release --examples
cp ../target/riscv32im-unknown-none-elf/release/examples/ceno_rt_mini ../ceno_emul/tests/data/
```