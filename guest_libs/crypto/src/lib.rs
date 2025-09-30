#![deny(missing_docs)]
//! Ceno zkVM guest implementations for the revm precompile crypto interface.
//!
//! This crate is revm version ir-relevant, unless the signature of the precompiles change.

/// BN254 elliptic curve
pub mod bn254;
/// secp256k1
pub mod secp256k1;
/// secp256r1
pub mod secp256r1;
/// SHA-256 implementation.
pub mod sha256;

mod macros;

/// Error returned when trying to install the crypto provider more than once.
#[derive(Debug, thiserror::Error)]
#[error("Crypto provider has already been installed")]
pub struct CenoCryptoInstallError;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CenoCryptoError {
    /// Bn254 errors
    #[error("Bn254 field point is not a member of the field")]
    Bn254FieldPointNotAMember,
    /// Bn254 affine g failed to create
    #[error("Bn254 affine G failed to create")]
    Bn254AffineGFailedToCreate,
    /// Bn254 pair length
    #[error("Bn254 pair length error")]
    Bn254PairLength,
    /// Sepk256k1 ecrecover error
    #[error("Secp256k1 ecrecover error")]
    Secp256k1Ecrecover(#[from] k256::ecdsa::Error),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_install() {
        {
            ceno_crypto!(name = MyCustomName);
        }
        {
            use revm_precompile as another_crate;
            ceno_crypto!(revm_precompile = another_crate);
        }
        {
            use alloy_consensus as another_crate;
            ceno_crypto!(alloy_consensus = another_crate);
        }
        {
            use alloy_primitives::Address as AnotherAddress;
            ceno_crypto!(address_type = AnotherAddress);
        }
        {
            use alloy_primitives::Address as AnotherAddress;
            ceno_crypto!(address_type = AnotherAddress);
        }
        {
            use alloy_consensus as another_crate;
            use alloy_primitives::Address as AnotherAddress;
            ceno_crypto!(
                address_type = AnotherAddress,
                alloy_consensus = another_crate
            );
        }
        {
            use alloy_consensus as another_crate;
            use alloy_primitives::Address as AnotherAddress;
            ceno_crypto!(
                alloy_consensus = another_crate,
                address_type = AnotherAddress
            );
        }

        ceno_crypto!();
        CenoCrypto::install();
    }
}
