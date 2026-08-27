mod bitwise_keccakf;
mod fptower;
pub(crate) mod lookup_keccakf;
mod pubio_commit;
mod sha256;
mod tensor;
mod uint256;
mod utils;
mod weierstrass;

pub use lookup_keccakf::{
    AND_LOOKUPS, KECCAK_INPUT32_SIZE, KECCAK_OUT_EVAL_SIZE, KECCAK_STATE_PHASE_INPUT,
    KECCAK_STATE_PHASE_OUTPUT, KeccakInstance, KeccakLayout, KeccakParams, KeccakStateInstance,
    KeccakTrace, KeccakWitInstance, RANGE_LOOKUPS, ROUNDS as KECCAK_ROUNDS,
    ROUNDS_CEIL_LOG2 as KECCAK_ROUNDS_CEIL_LOG2, XOR_LOOKUPS, keccak_state_record,
    run_lookup_keccakf, setup_gkr_circuit as setup_lookup_keccak_gkr_circuit,
};
pub use pubio_commit::{PUBIO_COMMIT_WORDS, PUBIO_DIGEST_U16_LIMBS, PubioCommitLayout};
pub use tensor::{
    ATTENTION_STATE_PHASE_INPUT, ATTENTION_STATE_PHASE_OUTPUT, BLOCK_STATE_PHASE_INPUT,
    BLOCK_STATE_PHASE_OUTPUT, RESIDUAL_LOOKUP_PACKED_REDUCED_V1, RESIDUAL_TABLE_REDUCED_V1,
    RMS_INV_LOOKUP_V1, RMS_INV_TABLE_REDUCED_V1, RMS_STATE_PHASE_INPUT, RMS_STATE_PHASE_OUTPUT,
    ROPE_LOOKUP_Q16_REDUCED_V1, ROPE_TABLE_REDUCED_V1, SWIGLU_LOOKUP_V1, SWIGLU_TABLE_REDUCED_V1,
    TENSOR_GATE2_OUTPUTS, TENSOR_STATE_PHASE_INPUT, TENSOR_STATE_PHASE_OUTPUT,
    TensorAttentionStateRecord, TensorGate2AirConfig, TensorMatMulCoreConfig,
    TensorProductionFinalizeCoreConfig, TensorProductionRawCoreConfig,
    TensorProductionTileCoreConfig, TensorRmsLookupCoreConfig, TensorRmsStateRecord,
    TensorSignedWord, TensorStateRecord, assign_gate2_core_witness, production_raw_state_record,
    production_tile_input_record, tensor_attention_state_record, tensor_block_state_record,
    tensor_rms_state_record, tensor_state_record,
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
