# Ceno Crypto Providers

**WORKING IN PROGRESS**

TODOs:
- [ ] secp256k1
- [ ] bn254
- [ ] sha256
- [ ] secp256r1

## Usage

Enable the `crypto-backend` feature of `alloy-consensus` in your `Cargo.toml`:

```toml
[dependencies]
alloy-consensus = { version = "1.0", features = ["crypto-backend"] }
```

In your guest program:

```rust
use ceno_crypto::ceno_crypto;

// By default, it generates a struct named `CenoCrypto`,
// using `revm_precompile` crate as revm_precompile,
// `alloy_consensus` crate as alloy_consensus, and `alloy_primitives::Address` as Address type,
// and implements the `Crypto` trait of revm_precompile and `CryptoProvider` of alloy_consensus.
ceno_crypto!();

// You can change the name of generated struct
// ceno_crypto!(name = MyCryptoProvider);

// or using different revm_precompile crate (default is revm_precompile)
// ceno_crypto!(revm_precompile = revm::precompile);

// or using different alloy_consensus crate (default is alloy_consensus)
// ceno_crypto!(alloy_consensus = alloy::consensus);

// or using different `Address` type (default is alloy_primitives::Address)
// ceno_crypto!(address_type = alloy::primitives::Address);

// or mix above options in arbitrary order

fn main() {
    CenoCrypto::install();
    
    // or use fallible version
    // CenoCrypto::try_install().ok();
    
    // Your other code here
}
```

## Development

### k256

This crate use patched [k256](https://docs.rs/k256/latest/k256/) crate.

Our patched [k256](https://github.com/scroll-tech/elliptic-curves) is modified from the sp1 fork
[k256](https://github.com/sp1-patches/elliptic-curves/tree/patch-k256-13.4-sp1-5.0.0/k256).

The sp1 patches: https://github.com/RustCrypto/elliptic-curves/compare/k256/v0.13.4...sp1-patches:elliptic-curves:patch-k256-13.4-sp1-5.0.0

The scroll-tech patches: https://github.com/RustCrypto/elliptic-curves/compare/k256/v0.13.4...scroll-tech:elliptic-curves:ceno/k256-13.4
