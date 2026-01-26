mod bitwise_keccakf;
mod fptower;
mod lookup_keccakf;
mod sha256;
mod uint256;
mod utils;
mod weierstrass;

pub use lookup_keccakf::{
    AND_LOOKUPS, KECCAK_INPUT32_SIZE, KECCAK_OUT_EVAL_SIZE, KeccakInstance, KeccakLayout,
    KeccakParams, KeccakStateInstance, KeccakTrace, KeccakWitInstance, RANGE_LOOKUPS,
    ROUNDS as KECCAK_ROUNDS, ROUNDS_CEIL_LOG2 as KECCAK_ROUNDS_CEIL_LOG2, XOR_LOOKUPS,
    run_lookup_keccakf, setup_gkr_circuit as setup_lookup_keccak_gkr_circuit,
};

pub use bitwise_keccakf::{
    KeccakLayout as BitwiseKeccakLayout, run_keccakf as run_bitwise_keccakf,
    setup_gkr_circuit as setup_bitwise_keccak_gkr_circuit,
};
use ff_ext::ExtensionField;
pub use fptower::{
    fp::{FpOpInstance, FpOpLayout, FpOpTrace},
    fp2_addsub::{Fp2AddSubAssignLayout, Fp2AddSubInstance, Fp2AddSubTrace},
    fp2_mul::{Fp2MulAssignLayout, Fp2MulInstance, Fp2MulTrace},
};
use gkr_iop::selector::SelectorType;
pub use sha256::{
    SHA_EXTEND_ROUNDS, ShaExtendInstance, ShaExtendLayout, ShaExtendTrace, ShaExtendWitInstance,
};
pub use uint256::{
    Uint256InvLayout, Uint256InvSpec, Uint256InvTrace, Uint256MulInstance, Uint256MulLayout,
    Uint256MulTrace, run_uint256_mul, setup_uint256mul_gkr_circuit as setup_uint256_mul_circuit,
};
pub use weierstrass::{
    EllipticCurveAddInstance, EllipticCurveDecompressInstance, EllipticCurveDoubleInstance,
    test_utils::{random_point_pairs, random_points},
    weierstrass_add::{
        WeierstrassAddAssignLayout, WeierstrassAddAssignTrace, run_weierstrass_add,
        setup_gkr_circuit as setup_weierstrass_add_circuit,
    },
    weierstrass_decompress::{
        WeierstrassDecompressLayout, WeierstrassDecompressTrace, run_weierstrass_decompress,
        setup_gkr_circuit as setup_weierstrass_decompress_circuit,
    },
    weierstrass_double::{
        WeierstrassDoubleAssignLayout, WeierstrassDoubleAssignTrace, run_weierstrass_double,
        setup_gkr_circuit as setup_weierstrass_double_circuit,
    },
};

#[derive(Clone, Debug)]
pub struct SelectorTypeLayout<E: ExtensionField> {
    pub sel_first: Option<SelectorType<E>>,
    pub sel_last: Option<SelectorType<E>>,
    pub sel_all: SelectorType<E>,
}
