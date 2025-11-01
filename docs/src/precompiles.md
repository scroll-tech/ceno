# Accelerated Operations with Precompiles (Syscalls)

Ceno provides "precompiles" to accelerate common, computationally intensive operations. These are implemented as `syscalls` that the guest program can invoke. Using precompiles is much more efficient than executing the equivalent logic in standard RISC-V instructions.

## Using Precompiles

To use a precompile, you need to call the corresponding function from the `ceno_rt::syscalls` module in your guest code.

For example, to compute a Keccak permutation, you can use `syscall_keccak_permute`:

```rust
use ceno_rt::syscalls::syscall_keccak_permute;

let mut state = [0u64; 25];
// ... initialize state ...
syscall_keccak_permute(&mut state);
```

## Available Precompiles

Ceno currently offers the following precompiles:

- **Hashing:**
  - `syscall_keccak_permute`: For Keccak-f[1600] permutation, the core of Keccak and SHA-3.
  - `syscall_sha256_extend`: For the SHA-256 message schedule (`W` table) extension.

- **Cryptography:**
  - `syscall_secp256k1_add`: Elliptic curve addition on secp256k1.
  - `syscall_secp256k1_double`: Elliptic curve point doubling on secp256k1.
  - `syscall_secp256k1_decompress`: Decompress a secp256k1 public key.
  - `syscall_bn254_add`: Elliptic curve addition on BN254.
  - `syscall_bn254_double`: Elliptic curve point doubling on BN254.
  - `syscall_bn254_fp_addmod`, `syscall_bn254_fp_mulmod`: Field arithmetic for BN254's base field.
  - `syscall_bn254_fp2_addmod`, `syscall_bn254_fp2_mulmod`: Field arithmetic for BN254's quadratic extension field.


You can find examples of how to use each of these syscalls in the `examples/` directory of the project.
