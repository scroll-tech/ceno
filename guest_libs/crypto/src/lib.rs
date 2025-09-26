//! Ceno zkVM guest implementations for the revm precompile crypto interface.
//!
//! This crate is revm version ir-relevant, unless the signature of the precompiles change.

pub mod sha256;
pub mod bn254;
pub mod secp256k1;

/// Error returned when trying to install the crypto provider more than once.
#[derive(Debug, thiserror::Error)]
#[error("Crypto provider has already been installed")]
pub struct CenoCryptoInstallError;

pub enum CenoCryptoError {
    /// Bn254 errors
    Bn254FieldPointNotAMember,
    /// Bn254 affine g failed to create
    Bn254AffineGFailedToCreate,
    /// Bn254 pair length
    Bn254PairLength,
}

#[macro_export]
macro_rules! declare_precompile {
    ($revm_precompile_path:path) => {
        /// revm precompile crypto operations provider
        #[derive(Debug)]
        pub struct CenoCrypto;

        impl CenoCrypto {
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
                if !$revm_precompile_path::install_crypto(Self) {
                    Err($crate::CenoCryptoInstallError)
                } else {
                    Ok(())
                }
            }
        }

        impl From<$crate::CenoCryptoError> for $revm_precompile_path::PrecompileError {
            fn from(err: $crate::CenoCryptoError) -> Self {
                match err {
                    $crate::CenoCryptoError::Bn254FieldPointNotAMember => $revm_precompile_path::PrecompileError::Bn254FieldPointNotAMember,
                    $crate::CenoCryptoError::Bn254AffineGFailedToCreate => $revm_precompile_path::PrecompileError::Bn254AffineGFailedToCreate,
                    $crate::CenoCryptoError::Bn254PairLength => $revm_precompile_path::PrecompileError::Bn254PairLength,
                }
            }
        }

        impl $revm_precompile_path::Crypto for Crypto {
            #[inline]
            fn sha256(&self, input: &[u8]) -> [u8; 32] {
                $crate::sha256::sha256(input)
            }
            #[inline]
            fn bn254_g1_add(p1: &[u8], p2: &[u8]) -> Result<[u8; 64], $revm_precompile_path::PrecompileError> {
                $crate::bn254::bn254_g1_add(p1, p2)
            }
            #[inline]
            fn bn254_g1_mul(point: &[u8], scalar: &[u8]) -> Result<[u8; 64], $revm_precompile_path::PrecompileError> {
                $crate::bn254::bn254_g1_mul(point, scalar)
            }
            #[inline]
            fn bn254_pairing_check(pairs: &[(&[u8], &[u8])]) -> Result<bool, $revm_precompile_path::PrecompileError> {
                $crate::bn254::bn254_pairing_check(pairs)
            }
            #[inline]
            fn secp256k1_ecrecover(
                sig: &[u8; 64],
                recid: u8,
                msg: &[u8; 32],
            ) -> Result<[u8; 32], $revm_precompile_path::PrecompileError> {
                $crate::secp256k1::secp256k1_ecrecover(sig, recid, msg)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_install() {
        declare_precompile!(revm_precompile);
        CenoCrypto::install();
    }
}
