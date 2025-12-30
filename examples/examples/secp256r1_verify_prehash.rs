extern crate ceno_rt;

use alloy_primitives::hex;
use p256::{
    AffinePoint, EncodedPoint, Scalar,
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    elliptic_curve::{Field, generic_array::GenericArray, sec1::FromEncodedPoint},
};

fn main() {
    // The following test vector adapted from the FIPS 186-4 ECDSA test vectors
    // (P-256, SHA-384, from `SigGen.txt` in `186-4ecdsatestvectors.zip`)
    // <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>
    let verifier = VerifyingKey::from_affine(
        AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            GenericArray::from_slice(&hex!(
                "e0e7b99bc62d8dd67883e39ed9fa0657789c5ff556cc1fd8dd1e2a55e9e3f243"
            )),
            GenericArray::from_slice(&hex!(
                "63fbfd0232b95578075c903a4dbf85ad58f8350516e1ec89b0ee1f5e1362da69"
            )),
            false,
        ))
        .unwrap(),
    )
    .unwrap();
    let signature = Signature::from_scalars(
        GenericArray::clone_from_slice(&hex!(
            "f5087878e212b703578f5c66f434883f3ef414dc23e2e8d8ab6a8d159ed5ad83"
        )),
        GenericArray::clone_from_slice(&hex!(
            "306b4c6c20213707982dffbb30fba99b96e792163dd59dbe606e734328dd7c8a"
        )),
    )
    .unwrap();
    let result = verifier.verify_prehash(
        &hex!("d9c83b92fa0979f4a5ddbd8dd22ab9377801c3c31bf50f932ace0d2146e2574da0d5552dbed4b18836280e9f94558ea6"),
        &signature,
    );
    assert!(result.is_ok());
}
