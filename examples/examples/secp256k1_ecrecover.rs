// Test ecrecover of real world signatures from scroll mainnet. Assert result inside the guest.
extern crate ceno_rt;

use alloy_primitives::{Address, B256, address, b256, hex};
use ceno_crypto::secp256k1::secp256k1_ecrecover;

const TEST_CASES: [(&[u8], u8, B256, Address); 5] = [
    // (sig, recid, tx_hash, signer)
    (
        &hex!(
            "15a7bb615483f66a697431cd414294b6bd1e1b9b9d6d163cfd97290ea77b53061810c4d228e424087ad77ee75bb25e77c832ad9038b89f7e573a34b574648348"
        ),
        0,
        b256!("b329f831352e37f4426583986465b065d9c867901b42f576f00ef36dfac1cfdf"),
        address!("ca585e09df67e83106c9bcd839c989ace537bf95"),
    ),
    (
        &hex!(
            "870077f742ca34760810033caf13c99e90e207db6f820124b827907e9658d7d04f302d6675c8625c02fc95c131a3ce77e7f90dba10dbda368efeaaba9be60916"
        ),
        0,
        b256!("4e13990772a9454712c7560ad8a64b845fd472b913b90d680867ab3dad56a18d"),
        address!("a79c12bcf11133af01b6b20f16f8aafaecdebc93"),
    ),
    (
        &hex!(
            "455a6249244154e8f5d516a3036e26576449bef05171657dbf3a5d7b9c02fe96629f7eb0aa2a006ff4ac6fc0523a6f5a365cf375240f5a560b1972eb21cec087"
        ),
        1,
        b256!("4dedbd995fc79db979c6484132568fe30fdf6bfa8b64ac74ba844cc30e764b0c"),
        address!("c623f214c8eefc771147c5806be250db39555555"),
    ),
    (
        &hex!(
            "854c4656c421158b4e5d8c29ccc3adcaee329587cee630398f3ce2e32745e45b67b1fc40e3206c70a75bcdf3c877c26874c75c2fabd5566c85b58c7c7d872e00"
        ),
        0,
        b256!("e4559e37c72fb3df0349df42b3aa0e94607287ecb3e6530b7c50ed984e0428a2"),
        address!("b82def35c814584d3d929cfb3a1fb1b886b6e57b"),
    ),
    (
        &hex!(
            "004a0ac1306d096c06fb77f82b76f43fb2459638826f4846444686b3036b9a4b3d6bf124bf22f23b851adfa2c4bdc670b4ecb5129186a4e89032916a77a56b90"
        ),
        0,
        b256!("83e5e11daa2d14736ab1d578c41250c6f6445782c215684a18f67b44686ccb90"),
        address!("0a6f0ed4896be1caa9e37047578e7519481f22ea"),
    ),
];

fn main() {
    for (sig, recid, tx_hash, signer) in TEST_CASES {
        let recovered = secp256k1_ecrecover(sig.try_into().unwrap(), recid, &tx_hash.0).unwrap();
        assert_eq!(&recovered[12..], &signer.0);
    }
}
