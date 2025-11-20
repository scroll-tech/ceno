mod bitwise_keccakf;
mod lookup_keccakf;
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
use gkr_iop::selector::SelectorType;
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
    pub sel_mem_read: SelectorType<E>,
    pub sel_mem_write: SelectorType<E>,
    pub sel_lookup: SelectorType<E>,
    pub sel_zero: SelectorType<E>,
}
