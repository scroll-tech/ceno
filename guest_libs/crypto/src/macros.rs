/// Declare a crypto operations provider using the Ceno zkVM guest implementations.
#[macro_export]
macro_rules! ceno_crypto {
    ( $( $key:ident = $val:tt ),* $(,)? ) => {
        // default values
        ceno_crypto!(@parse {
            revm_precompile: ::revm_precompile,
            alloy_consensus: ::alloy_consensus,
            address_type:    ::alloy_primitives::Address,
            name:            CenoCrypto
        } $( $key = $val, )* );
    };

    // parse optional args
    (@parse { revm_precompile: $r:path, alloy_consensus: $ac:path, address_type: $addr:path, name: $n:tt }
        revm_precompile = $nr:path $(, $($rest:tt)*)?
    ) => {
        ceno_crypto!(@parse { revm_precompile: $nr, alloy_consensus: $ac, address_type: $addr, name: $n } $($($rest)*)? );
    };

    (@parse { revm_precompile: $r:path, alloy_consensus: $ac:path, address_type: $addr:path, name: $n:tt }
        alloy_consensus = $nac:path $(, $($rest:tt)*)?
    ) => {
        ceno_crypto!(@parse { revm_precompile: $r,  alloy_consensus: $nac, address_type: $addr, name: $n } $($($rest)*)? );
    };

    (@parse { revm_precompile: $r:path, alloy_consensus: $ac:path, address_type: $addr:path, name: $n:tt }
        address_type = $na:path $(, $($rest:tt)*)?
    ) => {
        ceno_crypto!(@parse { revm_precompile: $r,  alloy_consensus: $ac,  address_type: $na,   name: $n } $($($rest)*)? );
    };

    (@parse { revm_precompile: $r:path, alloy_consensus: $ac:path, address_type: $addr:path, name: $n:tt }
        name = $nn:ident $(, $($rest:tt)*)?
    ) => {
        ceno_crypto!(@parse { revm_precompile: $r,  alloy_consensus: $ac,  address_type: $addr, name: $nn } $($($rest)*)? );
    };

    // unknown key
    (@parse { $($state:tt)* } $bad:ident = $($rest:tt)*) => {
        compile_error!(concat!("unknown option: ", stringify!($bad)));
    };


    // finish parsing
    (@parse { revm_precompile: $r:path, alloy_consensus: $ac:path, address_type: $addr:path, name: $n:ident } $(,)?) => {
        use $ac as __ac;
        use $r  as __rp;

        /// Ceno zkVM crypto operations provider
        #[derive(Debug)]
        #[allow(dead_code)]
        pub struct $n;

        impl $n {
            /// Install this as the global crypto provider.
            ///
            /// # Panics
            ///
            /// Panics if a crypto provider has already been installed.
            #[allow(dead_code)]
            pub fn install() {
                Self::try_install().unwrap();
            }

            /// Install this as the global crypto provider.
            #[allow(dead_code)]
            pub fn try_install() -> Result<(), $crate::CenoCryptoInstallError> {
                let revm_install = __rp::install_crypto(Self);
                let alloy_install =
                    __ac::crypto::install_default_provider(::std::sync::Arc::new(Self)).is_ok();
                if !(revm_install && alloy_install) {
                    Err($crate::CenoCryptoInstallError)
                } else {
                    Ok(())
                }
            }
        }

        #[allow(dead_code)]
        fn __map_err(e: $crate::CenoCryptoError) -> __rp::PrecompileError {
            match e {
                $crate::CenoCryptoError::Bn254FieldPointNotAMember => {
                    __rp::PrecompileError::Bn254FieldPointNotAMember
                }
                $crate::CenoCryptoError::Bn254AffineGFailedToCreate => {
                    __rp::PrecompileError::Bn254AffineGFailedToCreate
                }
                $crate::CenoCryptoError::Bn254PairLength => __rp::PrecompileError::Bn254PairLength,
                _ => __rp::PrecompileError::Other(e.to_string()),
            }
        }

        impl __rp::Crypto for $n {
            #[inline]
            fn sha256(&self, input: &[u8]) -> [u8; 32] {
                use ceno_sha2::{Digest, Sha256};
                let output = Sha256::digest(input);
                output.into()
            }
            #[inline]
            fn bn254_g1_add(
                &self,
                p1: &[u8],
                p2: &[u8],
            ) -> Result<[u8; 64], __rp::PrecompileError> {
                $crate::bn254::g1_point_add(p1, p2).map_err(__map_err)
            }
            #[inline]
            fn bn254_g1_mul(
                &self,
                point: &[u8],
                scalar: &[u8],
            ) -> Result<[u8; 64], __rp::PrecompileError> {
                $crate::bn254::g1_point_mul(point, scalar).map_err(__map_err)
            }
            #[inline]
            fn bn254_pairing_check(
                &self,
                pairs: &[(&[u8], &[u8])],
            ) -> Result<bool, __rp::PrecompileError> {
                $crate::bn254::pairing_check(pairs).map_err(__map_err)
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
            fn secp256r1_verify_signature(
                &self,
                msg: &[u8; 32],
                sig: &[u8; 64],
                pk: &[u8; 64],
            ) -> bool {
                $crate::secp256r1::secp256r1_verify_signature(msg, sig, pk)
            }
        }

        impl __ac::crypto::backend::CryptoProvider for $n {
            #[inline]
            fn recover_signer_unchecked(
                &self,
                sig: &[u8; 65],
                msg: &[u8; 32],
            ) -> Result<$addr, __ac::crypto::RecoveryError> {
                use $addr as Address;
                $crate::secp256k1::secp256k1_ecrecover(
                    (&sig[..64]).try_into().unwrap(),
                    sig[64],
                    msg,
                )
                .map(|res| Address::from_slice(&res[12..]))
                .map_err(__ac::crypto::RecoveryError::from_source)
            }
        }
    };
}
