#![deny(missing_docs)]
//! Ceno zkVM guest implementations for the revm precompile crypto interface.
//!
//! This crate is revm version ir-relevant, unless the signature of the precompiles change.

/// SHA-256 implementation.
pub mod sha256;
/// BN254 elliptic curve
pub mod bn254;
/// secp256k1
pub mod secp256k1;
/// secp256r1
pub mod secp256r1;

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
    Secp256k1EcRecover,
}

/// Declare a revm precompile crypto operations provider using the Ceno zkVM guest implementations.
///
/// This macro declares a struct with the given name (or `CenoCrypto` if no name is provided) that
/// implements the `revm_precompile::Crypto` trait using the Ceno zkVM syscalls.
#[macro_export]
macro_rules! declare_precompile {
    () => {
        $crate::declare_precompile!(::revm_precompile, CenoCrypto);
    };
    ($struct_name:ident) => {
        $crate::declare_precompile!(::revm_precompile, $struct_name);
    };
    ($revm_precompile_path:path) => {
        $crate::declare_precompile!($revm_precompile_path, CenoCrypto);
    };
    ($revm_precompile_path:path, $struct_name:ident) => {
        use $revm_precompile_path as __rp;

        /// revm precompile crypto operations provider
        #[derive(Debug)]
        pub struct $struct_name;

        impl $struct_name {
            /// Install this as the global crypto provider.
            ///
            /// # Panics
            ///
            /// Panics if a crypto provider has already been installed.
            pub fn install() {
                Self::try_install().unwrap();
            }

            /// Install this as the global crypto provider.
            pub fn try_install() -> Result<(), $crate::CenoCryptoInstallError> {
                if !__rp::install_crypto(Self) {
                    Err($crate::CenoCryptoInstallError)
                } else {
                    Ok(())
                }
            }
        }

        fn __map_err(e: $crate::CenoCryptoError) -> __rp::PrecompileError {
            match e {
                $crate::CenoCryptoError::Bn254FieldPointNotAMember => __rp::PrecompileError::Bn254FieldPointNotAMember,
                $crate::CenoCryptoError::Bn254AffineGFailedToCreate => __rp::PrecompileError::Bn254AffineGFailedToCreate,
                $crate::CenoCryptoError::Bn254PairLength => __rp::PrecompileError::Bn254PairLength,
                _ => __rp::PrecompileError::Other(e.to_string()),
            }
        }

        impl __rp::Crypto for $struct_name {
            #[inline]
            fn sha256(&self, input: &[u8]) -> [u8; 32] {
                $crate::sha256::sha256(input)
            }
            #[inline]
            fn bn254_g1_add(&self, p1: &[u8], p2: &[u8]) -> Result<[u8; 64], __rp::PrecompileError> {
                $crate::bn254::bn254_g1_add(p1, p2).map_err(__map_err)
            }
            #[inline]
            fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], __rp::PrecompileError> {
                $crate::bn254::bn254_g1_mul(point, scalar).map_err(__map_err)
            }
            #[inline]
            fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, __rp::PrecompileError> {
                $crate::bn254::bn254_pairing_check(pairs).map_err(__map_err)
            }
            #[inline]
            fn secp256k1_ecrecover(
                &self,
                sig: &[u8; 64],
                recid: u8,
                msg: &[u8; 32],
            ) -> Result<[u8; 32], __rp::PrecompileError> {
                $crate::secp256k1::secp256k1_ecrecover(sig, recid, msg).map_err(__map_err)
            }
            #[inline]
            fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
                $crate::secp256r1::secp256r1_verify_signature(msg, sig, pk)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_install() {
        declare_precompile!();
        CenoCrypto::install();
    }
}
