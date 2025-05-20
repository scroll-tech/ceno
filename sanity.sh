#!/bin/bash

cargo make build

# Run the first command
cargo run --bin e2e --release -- examples/target/riscv32im-ceno-zkvm-elf/release/examples/secp256k1_add_syscall
if [ $? -ne 0 ]; then
    echo "Command 1 failed"
    exit 1
fi

# Run the second command
cargo run --bin e2e --release -- examples/target/riscv32im-ceno-zkvm-elf/release/examples/ceno_rt_keccak
if [ $? -ne 0 ]; then
    echo "Command 2 failed"
    exit 1
fi
