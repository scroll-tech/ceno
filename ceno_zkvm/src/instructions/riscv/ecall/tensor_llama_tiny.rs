//! Complete one-layer `llama-tiny` semantic Core family.
//!
//! The operation circuits deliberately share one narrow row shape. They are
//! separate chips because a chip has one circuit-wide lookup selector;
//! consequently every selected row in a lookup chip has the same lookup arity
//! and table. Seven ordinal bits and small chip-local stages replace the former
//! 112 circuit-wide one-hot columns.

use std::{collections::BTreeMap, marker::PhantomData};

use ceno_emul::{InsnKind, StepIndex, StepRecord, tensor};
use ff_ext::{ExtensionField, FieldInto};
use gkr_iop::{tables::LookupTable, utils::lk_multiplicity::Multiplicity};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::PrimeCharacteristicRing;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::ecall::tensor_batched_matmul::{
            TENSOR_BATCHED_MATMUL_SCALE, TensorBatchedMatMulSection, tensor_resident_claim_record,
            tensor_space_record,
        },
    },
    structs::{CustomRWTag, ProgramParams, RAMType},
    tables::{LlamaTinyRom, RMMCollections, SoftmaxExp3Rom, SoftmaxExp4Rom},
    witness::{LkMultiplicity, set_val},
};

pub const LLAMA_TINY_LAYER_STATE_VERSION: u32 = 8;
const LLAMA_TINY_SOFTMAX_LIMB_VERSION: u32 = 9;
pub const LLAMA_TINY_ATTENTION_ROWS: usize = 76;
pub const LLAMA_TINY_FFN_ROWS: usize = 36;
pub const LLAMA_TINY_TOTAL_ROWS: usize = LLAMA_TINY_ATTENTION_ROWS + LLAMA_TINY_FFN_ROWS;

const CHIP_RMS_ARITHMETIC: usize = 0;
const CHIP_RMS_LOOKUP: usize = 1;
const CHIP_MATMUL_BRIDGE: usize = 2;
const CHIP_ROPE: usize = 3;
const CHIP_SOFTMAX_ARITHMETIC: usize = 4;
const CHIP_SOFTMAX_LOW_DIGIT: usize = 5;
const CHIP_SOFTMAX_EXP3: usize = 6;
const CHIP_SOFTMAX_EXP4: usize = 7;
const CHIP_RESIDUAL: usize = 8;
const CHIP_SWIGLU_LOOKUP: usize = 9;
const CHIP_SWIGLU_ARITHMETIC: usize = 10;

// These values are part of the private-state record and remain byte-for-byte
// compatible with the complete-layer proof introduced before the chip split.
const STATE_ATTENTION_LINEAR: usize = 0;
const STATE_ATTENTION_RMS: usize = 1;
const STATE_ATTENTION_LOW_DIGIT: usize = 2;
const STATE_ATTENTION_EXP3: usize = 3;
const STATE_ATTENTION_EXP4: usize = 4;
const STATE_FFN_LINEAR: usize = 5;
const STATE_FFN_RMS: usize = 6;
const STATE_FFN_SWIGLU: usize = 7;

const ORDINAL_BITS: usize = 7;
const LOCAL_INDEX_BITS: usize = 2;
const MAX_LOCAL_STAGES: usize = 8;

const RMS_ARITHMETIC_ORDINALS: [usize; 20] = [
    0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 76, 77, 78, 79, 82, 83, 84, 85, 86, 87,
];
const RMS_LOOKUP_ORDINALS: [usize; 4] = [4, 5, 80, 81];
const MATMUL_BRIDGE_ORDINALS: [usize; 32] = [
    12, 13, 14, 15, 20, 21, 22, 23, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 88, 89, 90, 91,
    92, 93, 94, 95, 96, 97, 98, 99,
];
const ROPE_ORDINALS: [usize; 4] = [16, 17, 18, 19];
const SOFTMAX_ARITHMETIC_ORDINALS: [usize; 24] = [
    24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 52, 53, 54, 55, 56, 57, 58, 59,
];
const SOFTMAX_LOW_DIGIT_ORDINALS: [usize; 4] = [40, 41, 42, 43];
const SOFTMAX_EXP3_ORDINALS: [usize; 4] = [44, 45, 46, 47];
const SOFTMAX_EXP4_ORDINALS: [usize; 4] = [48, 49, 50, 51];
const RESIDUAL_ORDINALS: [usize; 8] = [72, 73, 74, 75, 108, 109, 110, 111];
const SWIGLU_LOOKUP_ORDINALS: [usize; 4] = [100, 101, 102, 103];
const SWIGLU_ARITHMETIC_ORDINALS: [usize; 4] = [104, 105, 106, 107];

const CHIP_ROWS: [usize; 11] = [20, 4, 32, 4, 24, 4, 4, 4, 8, 4, 4];
const CHIP_ORDINALS: [&[usize]; 11] = [
    &RMS_ARITHMETIC_ORDINALS,
    &RMS_LOOKUP_ORDINALS,
    &MATMUL_BRIDGE_ORDINALS,
    &ROPE_ORDINALS,
    &SOFTMAX_ARITHMETIC_ORDINALS,
    &SOFTMAX_LOW_DIGIT_ORDINALS,
    &SOFTMAX_EXP3_ORDINALS,
    &SOFTMAX_EXP4_ORDINALS,
    &RESIDUAL_ORDINALS,
    &SWIGLU_LOOKUP_ORDINALS,
    &SWIGLU_ARITHMETIC_ORDINALS,
];

const CHIP_NAMES: [&str; 11] = [
    "LlamaTinyRmsArithmeticCore",
    "LlamaTinyRmsLookupCore",
    "LlamaTinyMatMulBridgeCore",
    "LlamaTinyRoPECore",
    "LlamaTinySoftmaxArithmeticCore",
    "LlamaTinySoftmaxLowDigitCore",
    "LlamaTinySoftmaxExp3Core",
    "LlamaTinySoftmaxExp4Core",
    "LlamaTinyResidualCore",
    "LlamaTinySwiGluLookupCore",
    "LlamaTinySwiGluArithmeticCore",
];

// (first ordinal, ordinal stride, rows). Every operation stage has at most four
// rows, so its fixed data is a multilinear polynomial in two local bits.
const CHIP_STAGES: [&[(usize, usize, usize)]; 11] = [
    &[
        (0, 1, 4),
        (6, 1, 2),
        (8, 1, 4),
        (76, 1, 4),
        (82, 1, 2),
        (84, 1, 4),
    ],
    &[(4, 1, 2), (80, 1, 2)],
    &[
        (12, 1, 4),
        (20, 1, 4),
        (60, 1, 4),
        (64, 1, 4),
        (68, 1, 4),
        (88, 1, 4),
        (92, 1, 4),
        (96, 1, 4),
    ],
    &[(16, 1, 4)],
    &[
        (24, 1, 4),
        (28, 3, 4),
        (29, 3, 4),
        (30, 3, 4),
        (52, 1, 4),
        (56, 1, 2),
        (58, 1, 2),
    ],
    &[(40, 1, 4)],
    &[(44, 1, 4)],
    &[(48, 1, 4)],
    &[(72, 1, 4), (108, 1, 4)],
    &[(100, 1, 4)],
    &[(104, 1, 4)],
];

const MATRIX_ROLES: [u32; 9] = [
    tensor::TENSOR_HINT_ROLE_Q,
    tensor::TENSOR_HINT_ROLE_K,
    tensor::TENSOR_HINT_ROLE_V,
    tensor::TENSOR_HINT_ROLE_QK,
    tensor::TENSOR_HINT_ROLE_PV,
    tensor::TENSOR_HINT_ROLE_O,
    tensor::TENSOR_HINT_ROLE_GATE,
    tensor::TENSOR_HINT_ROLE_UP,
    tensor::TENSOR_HINT_ROLE_DOWN,
];
const WEIGHT_ROLES: [u32; 7] = [
    tensor::TENSOR_HINT_ROLE_Q,
    tensor::TENSOR_HINT_ROLE_K,
    tensor::TENSOR_HINT_ROLE_V,
    tensor::TENSOR_HINT_ROLE_O,
    tensor::TENSOR_HINT_ROLE_GATE,
    tensor::TENSOR_HINT_ROLE_UP,
    tensor::TENSOR_HINT_ROLE_DOWN,
];

#[derive(Clone, Debug)]
pub struct LlamaTinyLayerSection {
    pub import_cycle: u64,
    pub attention_cycle: u64,
    pub ffn_cycle: u64,
    pub input_tensor_id: u64,
    pub input_version: u32,
    pub attention_tensor_id: u64,
    pub attention_version: u32,
    pub output_tensor_id: u64,
    pub output_version: u32,
    pub trace: tensor::llama_tiny::LlamaTinyLayerTrace,
    pub matrices: [TensorBatchedMatMulSection; 9],
    pub hints: [(tensor::TensorHintRef, [[i32; 2]; 2]); 7],
}

fn invalid(message: impl Into<String>) -> ZKVMError {
    ZKVMError::InvalidWitness(message.into().into())
}

fn internal_tensor_id(section: &LlamaTinyLayerIdentity, domain: u32) -> u64 {
    section.input_tensor_id
        ^ 0x8000_0000_0000_0000
        ^ (u64::from(domain) << 32)
        ^ section.import_cycle.rotate_left(17)
}

#[derive(Clone, Copy)]
struct LlamaTinyLayerIdentity {
    import_cycle: u64,
    attention_cycle: u64,
    ffn_cycle: u64,
    input_tensor_id: u64,
    input_version: u32,
    attention_tensor_id: u64,
    attention_version: u32,
    output_tensor_id: u64,
    output_version: u32,
}

fn flatten(values: [[i32; 2]; 2]) -> [i32; 4] {
    [values[0][0], values[0][1], values[1][0], values[1][1]]
}

fn make_matrix(
    identity: LlamaTinyLayerIdentity,
    role: u32,
    matrix: tensor::TensorBatchedMatMul2x2Witness,
    rhs_domain: Option<u32>,
) -> Result<TensorBatchedMatMulSection, ZKVMError> {
    let mut output = [[0_i32; 2]; 2];
    for row in 0..2 {
        for col in 0..2 {
            let accum = (0..2)
                .map(|inner| i64::from(matrix.a[row][inner]) * i64::from(matrix.w[inner][col]))
                .sum::<i64>();
            output[row][col] = i32::try_from(accum)
                .map_err(|_| invalid(format!("llama-tiny role {role} accumulator overflow")))?;
            if i64::from(matrix.quotient[row][col]) * TENSOR_BATCHED_MATMUL_SCALE
                + i64::from(matrix.remainder[row][col])
                != accum
            {
                return Err(invalid(format!(
                    "llama-tiny role {role} provider quotient/remainder mismatch"
                )));
            }
        }
    }
    let cycle = if role <= tensor::TENSOR_HINT_ROLE_O {
        identity.attention_cycle
    } else {
        identity.ffn_cycle
    };
    let input_tensor_id = internal_tensor_id(&identity, 0x100 + role);
    let output_tensor_id = internal_tensor_id(&identity, 0x200 + role);
    let resident = tensor::TensorResidentMatMulWitness {
        import_cycle: identity.import_cycle,
        input_tensor_id,
        input_version: 1,
        output_tensor_id,
        output_version: 1,
        rhs_tensor_id: rhs_domain.map(|domain| internal_tensor_id(&identity, domain)),
        rhs_tensor_version: rhs_domain.map(|_| 1),
        hint: tensor::TensorHintRef {
            profile: tensor::TENSOR_PROFILE_LLAMA_TINY,
            layer: 0,
            role,
            tile_index: 0,
        },
        input: flatten(matrix.a),
        output: flatten(output),
        matrix,
    };
    Ok(TensorBatchedMatMulSection {
        cycle,
        call_id: cycle,
        a: matrix.a,
        w: matrix.w,
        resident: Some(resident),
    })
}

/// Pair complete attention/FFN calls and derive the independent full-layer
/// oracle exactly once for a shard assignment.
pub fn collect_layer_sections(
    shard_ctx: &mut ShardContext,
    steps: &[StepRecord],
    attention_indices: &[StepIndex],
    ffn_indices: &[StepIndex],
) -> Result<Vec<LlamaTinyLayerSection>, ZKVMError> {
    if attention_indices.len() != ffn_indices.len() || attention_indices.is_empty() {
        return Err(invalid(
            "llama-tiny needs complete attention/FFN call pairs",
        ));
    }
    attention_indices
        .iter()
        .zip(ffn_indices)
        .map(|(attention_index, ffn_index)| {
            if attention_index >= ffn_index {
                return Err(invalid("llama-tiny handle calls are reordered"));
            }
            let attention_step = &steps[*attention_index];
            let ffn_step = &steps[*ffn_index];
            let mut attention = attention_step
                .syscall(&shard_ctx.syscall_witnesses)
                .and_then(|syscall| syscall.tensor_resident_matmul)
                .ok_or_else(|| invalid("llama-tiny attention payload missing"))?;
            let ffn = ffn_step
                .syscall(&shard_ctx.syscall_witnesses)
                .and_then(|syscall| syscall.tensor_resident_matmul)
                .ok_or_else(|| invalid("llama-tiny FFN payload missing"))?;
            let mut provider = ffn_step
                .syscall(&shard_ctx.syscall_witnesses)
                .and_then(|syscall| syscall.tensor_llama_tiny_layer)
                .ok_or_else(|| invalid("llama-tiny provider layer snapshot missing"))?;
            if let Some(tamper) = std::env::var_os("CENO_LLAMA_TINY_TAMPER") {
                match tamper.to_str() {
                    Some("tensor-slot") => attention.input_tensor_id ^= 1,
                    Some("tensor-version") => attention.input_version ^= 1,
                    Some("row-coverage") => provider.matrices[0].a[0][0] ^= 1,
                    Some("row-order") => provider.matrices.swap(0, 1),
                    Some("hint-identity") => provider.matrices.swap(1, 2),
                    Some("hint-value") => provider.matrices[0].w[0][0] ^= 1,
                    Some("product") => provider.matrices[3].a[0][0] ^= 1,
                    Some("quotient") => provider.matrices[3].quotient[0][0] ^= 1,
                    Some("remainder") => provider.matrices[3].remainder[0][0] ^= 1,
                    Some("causal-mask") => provider.trace.probabilities[0][1] = 1,
                    Some("lookup-rms") => provider.trace.input_energy[0] ^= 1,
                    Some("lookup-low-digit") => provider.trace.shifted_magnitudes[0][0] ^= 1,
                    Some("lookup-exp3") => provider.trace.shifted_magnitudes[0][0] ^= 1 << 48,
                    Some("lookup-exp4") => provider.trace.shifted_magnitudes[0][0] ^= 1 << 64,
                    Some("lookup-swiglu") => provider.trace.swiglu[0][0] ^= 1,
                    Some(other) => {
                        return Err(invalid(format!("unknown llama-tiny tamper hook {other}")));
                    }
                    None => return Err(invalid("llama-tiny tamper hook is not UTF-8")),
                }
            }
            let oracle =
                tensor::llama_tiny::execute().map_err(|error| invalid(error.to_string()))?;
            if provider.trace != oracle {
                return Err(invalid(
                    "llama-tiny provider snapshot disagrees with host oracle",
                ));
            }
            if attention.hint.profile != tensor::TENSOR_PROFILE_LLAMA_TINY
                || ffn.hint.profile != tensor::TENSOR_PROFILE_LLAMA_TINY
                || attention.hint.layer != 0
                || ffn.hint.layer != 0
                || attention.hint.role != tensor::TENSOR_HINT_ROLE_ATTENTION
                || ffn.hint.role != tensor::TENSOR_HINT_ROLE_FFN
                || attention.output_tensor_id != ffn.input_tensor_id
                || attention.output_version != ffn.input_version
                || attention.import_cycle != ffn.import_cycle
            {
                return Err(invalid("llama-tiny handle chain/profile/layer mismatch"));
            }
            let identity = LlamaTinyLayerIdentity {
                import_cycle: shard_ctx.aligned_current_ts(attention.import_cycle),
                attention_cycle: attention_step.cycle() - shard_ctx.current_shard_offset_cycle(),
                ffn_cycle: ffn_step.cycle() - shard_ctx.current_shard_offset_cycle(),
                input_tensor_id: attention.input_tensor_id,
                input_version: attention.input_version,
                attention_tensor_id: attention.output_tensor_id,
                attention_version: attention.output_version,
                output_tensor_id: ffn.output_tensor_id,
                output_version: ffn.output_version,
            };
            let matrices = [
                make_matrix(identity, MATRIX_ROLES[0], provider.matrices[0], None)?,
                make_matrix(identity, MATRIX_ROLES[1], provider.matrices[1], None)?,
                make_matrix(identity, MATRIX_ROLES[2], provider.matrices[2], None)?,
                make_matrix(identity, MATRIX_ROLES[3], provider.matrices[3], Some(0x300))?,
                make_matrix(identity, MATRIX_ROLES[4], provider.matrices[4], Some(0x301))?,
                make_matrix(identity, MATRIX_ROLES[5], provider.matrices[5], None)?,
                make_matrix(identity, MATRIX_ROLES[6], provider.matrices[6], None)?,
                make_matrix(identity, MATRIX_ROLES[7], provider.matrices[7], None)?,
                make_matrix(identity, MATRIX_ROLES[8], provider.matrices[8], None)?,
            ];
            let weight_matrix_indices = [0_usize, 1, 2, 5, 6, 7, 8];
            let hints = std::array::from_fn(|index| {
                let role = WEIGHT_ROLES[index];
                let hint = tensor::TensorHintRef {
                    profile: tensor::TENSOR_PROFILE_LLAMA_TINY,
                    layer: 0,
                    role,
                    tile_index: 0,
                };
                let values = provider.matrices[weight_matrix_indices[index]].w;
                (hint, values)
            });
            Ok(LlamaTinyLayerSection {
                import_cycle: identity.import_cycle,
                attention_cycle: identity.attention_cycle,
                ffn_cycle: identity.ffn_cycle,
                input_tensor_id: identity.input_tensor_id,
                input_version: identity.input_version,
                attention_tensor_id: identity.attention_tensor_id,
                attention_version: identity.attention_version,
                output_tensor_id: identity.output_tensor_id,
                output_version: identity.output_version,
                trace: provider.trace,
                matrices,
                hints,
            })
        })
        .collect()
}

pub(crate) fn llama_tiny_layer_state_record<E: ExtensionField>(
    import_cycle: Expression<E>,
    call_cycle: Expression<E>,
    input_id_lo: Expression<E>,
    input_id_hi: Expression<E>,
    input_version: Expression<E>,
    output_id_lo: Expression<E>,
    output_id_hi: Expression<E>,
    output_version: Expression<E>,
    ordinal: Expression<E>,
    family: Expression<E>,
    stage: Expression<E>,
    op: Expression<E>,
    row: Expression<E>,
    col: Expression<E>,
    accumulator: Expression<E>,
    value: Expression<E>,
    limbs: [Expression<E>; 5],
) -> Vec<Expression<E>> {
    let mut record = vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(LLAMA_TINY_LAYER_STATE_VERSION).expr(),
        import_cycle,
        call_cycle,
        input_id_lo,
        input_id_hi,
        input_version,
        output_id_lo,
        output_id_hi,
        output_version,
        ordinal,
        family,
        stage,
        op,
        row,
        col,
        accumulator,
        value,
    ];
    record.extend(limbs);
    record
}

fn llama_tiny_softmax_limb_record<E: ExtensionField>(
    import_cycle: Expression<E>,
    score: Expression<E>,
    limbs: [Expression<E>; 5],
) -> Vec<Expression<E>> {
    let mut record = vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(LLAMA_TINY_SOFTMAX_LIMB_VERSION).expr(),
        import_cycle,
        score,
    ];
    record.extend(limbs);
    record
}

#[derive(Clone, Copy, Debug)]
struct ArithmeticLaneConfig {
    enabled: WitIn,
    rescale: WitIn,
    q20: WitIn,
    normalize: WitIn,
    operands: [WitIn; 4],
    result: WitIn,
    quotient: WitIn,
    remainder: WitIn,
}

#[derive(Clone, Copy, Debug)]
struct ResidentClaimPortConfig {
    enabled: WitIn,
    cycle: WitIn,
    input_id_lo: WitIn,
    input_id_hi: WitIn,
    input_version: WitIn,
    output_id_lo: WitIn,
    output_id_hi: WitIn,
    output_version: WitIn,
    role: WitIn,
    row: WitIn,
    value: WitIn,
}

#[derive(Debug)]
pub struct LlamaTinyCoreConfig {
    active: WitIn,
    import_cycle: WitIn,
    call_cycle: WitIn,
    next_call_cycle: WitIn,
    input_id_lo: WitIn,
    input_id_hi: WitIn,
    input_version: WitIn,
    next_input_id_lo: WitIn,
    next_input_id_hi: WitIn,
    next_input_version: WitIn,
    output_id_lo: WitIn,
    output_id_hi: WitIn,
    output_version: WitIn,
    next_output_id_lo: WitIn,
    next_output_id_hi: WitIn,
    next_output_version: WitIn,
    ordinal_bits: [WitIn; ORDINAL_BITS],
    next_ordinal_bits: [WitIn; ORDINAL_BITS],
    local_index_bits: [WitIn; LOCAL_INDEX_BITS],
    stage_selectors: [WitIn; MAX_LOCAL_STAGES],
    family: WitIn,
    next_family: WitIn,
    stage: WitIn,
    next_stage: WitIn,
    op: WitIn,
    next_op: WitIn,
    accumulator: WitIn,
    next_accumulator: WitIn,
    value: WitIn,
    next_value: WitIn,
    limbs: [WitIn; 5],
    next_limbs: [WitIn; 5],
    lanes: [ArithmeticLaneConfig; 2],
    remainder_bits: [[WitIn; 20]; 2],
    tensor_read_enabled: WitIn,
    tensor_read_id_lo: WitIn,
    tensor_read_id_hi: WitIn,
    tensor_read_version: WitIn,
    tensor_read_index: WitIn,
    tensor_read_value: WitIn,
    tensor_read2_enabled: WitIn,
    tensor_read2_id_lo: WitIn,
    tensor_read2_id_hi: WitIn,
    tensor_read2_version: WitIn,
    tensor_read2_index: WitIn,
    tensor_read2_value: WitIn,
    tensor_read3_enabled: WitIn,
    tensor_read3_id_lo: WitIn,
    tensor_read3_id_hi: WitIn,
    tensor_read3_version: WitIn,
    tensor_read3_index: WitIn,
    tensor_read3_value: WitIn,
    tensor_write_enabled: WitIn,
    tensor_write_id_lo: WitIn,
    tensor_write_id_hi: WitIn,
    tensor_write_version: WitIn,
    tensor_write_index: WitIn,
    tensor_write_value: WitIn,
    tensor_write2_enabled: WitIn,
    tensor_write2_id_lo: WitIn,
    tensor_write2_id_hi: WitIn,
    tensor_write2_version: WitIn,
    tensor_write2_index: WitIn,
    tensor_write2_value: WitIn,
    tensor_write3_enabled: WitIn,
    tensor_write3_id_lo: WitIn,
    tensor_write3_id_hi: WitIn,
    tensor_write3_version: WitIn,
    tensor_write3_index: WitIn,
    tensor_write3_value: WitIn,
    claims: [ResidentClaimPortConfig; 2],
    lookup_inputs: [WitIn; 5],
    lookup_output: WitIn,
}

pub struct LlamaTinyCoreInstruction<E, const CHIP: usize>(PhantomData<E>);
pub type LlamaTinyRmsArithmeticCore<E> = LlamaTinyCoreInstruction<E, 0>;
pub type LlamaTinyRmsLookupCore<E> = LlamaTinyCoreInstruction<E, 1>;
pub type LlamaTinyMatMulBridgeCore<E> = LlamaTinyCoreInstruction<E, 2>;
pub type LlamaTinyRoPECore<E> = LlamaTinyCoreInstruction<E, 3>;
pub type LlamaTinySoftmaxArithmeticCore<E> = LlamaTinyCoreInstruction<E, 4>;
pub type LlamaTinySoftmaxLowDigitCore<E> = LlamaTinyCoreInstruction<E, 5>;
pub type LlamaTinySoftmaxExp3Core<E> = LlamaTinyCoreInstruction<E, 6>;
pub type LlamaTinySoftmaxExp4Core<E> = LlamaTinyCoreInstruction<E, 7>;
pub type LlamaTinyResidualCore<E> = LlamaTinyCoreInstruction<E, 8>;
pub type LlamaTinySwiGluLookupCore<E> = LlamaTinyCoreInstruction<E, 9>;
pub type LlamaTinySwiGluArithmeticCore<E> = LlamaTinyCoreInstruction<E, 10>;

fn conditional_type<E: ExtensionField>(selector: Expression<E>) -> Expression<E> {
    E::BaseField::from_u64(RAMType::Custom as u64).expr() * selector.clone()
        + E::BaseField::from_u64(RAMType::Undefined as u64).expr()
            * (E::BaseField::ONE.expr() - selector)
}

fn conditional_rlc<E: ExtensionField>(
    cb: &CircuitBuilder<E>,
    selector: Expression<E>,
    record: &[Expression<E>],
) -> Expression<E> {
    cb.rlc_chip_record(record.to_vec()) * selector.clone() + (E::BaseField::ONE.expr() - selector)
}

const fn semantic_read_enabled(ordinal: usize, port: usize) -> bool {
    match port {
        0 => !matches!(ordinal, 28..=39),
        1 => matches!(
            ordinal,
            8..=11 | 16..=19 | 40..=43 | 52..=59 | 72..=75 | 84..=87 | 104..=111
        ),
        2 => matches!(ordinal, 40..=43 | 58..=59),
        _ => false,
    }
}

const fn semantic_write_enabled(ordinal: usize, port: usize) -> bool {
    match port {
        0 => !matches!(ordinal, 24..=27 | 40..=43),
        1 => {
            matches!(
                ordinal,
                0..=3 | 6..=7 | 12..=19 | 28..=38 | 56..=59 | 76..=79 | 82..=83 | 88..=91
            ) && !matches!(ordinal, 30 | 33 | 36 | 39)
        }
        2 => matches!(ordinal, 1 | 3 | 12..=15 | 56..=57 | 77 | 79),
        _ => false,
    }
}

const fn semantic_claim_enabled(ordinal: usize, port: usize) -> bool {
    match port {
        0 => matches!(ordinal, 16..=27 | 64..=71 | 92..=99 | 108..=111),
        1 => matches!(ordinal, 16..=19),
        _ => false,
    }
}

const fn semantic_lane_enabled(ordinal: usize, lane: usize) -> bool {
    match lane {
        0 => matches!(
            ordinal,
            0..=3
                | 8..=11
                | 16..=23
                | 52..=59
                | 64..=79
                | 84..=87
                | 92..=99
                | 104..=111
        ),
        1 => matches!(
            ordinal,
            1 | 3 | 8..=11 | 16..=19 | 52..=55 | 58..=59 | 77 | 79 | 84..=87 | 108..=111
        ),
        _ => false,
    }
}

const fn semantic_lane_shift(ordinal: usize, lane: usize) -> Option<u32> {
    if matches!(ordinal, 64..=67 | 92..=95) && lane == 0 {
        Some(tensor::llama_tiny::Q20_SHIFT)
    } else if (matches!(ordinal, 8..=23 | 68..=71 | 84..=87 | 96..=99 | 104..=107)
        && semantic_lane_enabled(ordinal, lane))
        || (matches!(ordinal, 108..=111) && lane == 0)
    {
        Some(tensor::llama_tiny::Q16_SHIFT)
    } else {
        None
    }
}

const fn semantic_read_index(ordinal: usize, port: usize) -> usize {
    match ordinal {
        0..=3 => ordinal,
        4..=7 => ordinal - if ordinal < 6 { 4 } else { 6 },
        8..=11 => ordinal - 8,
        12..=15 => ordinal - 12,
        16..=17 => (ordinal - 16) * 2 + port,
        18..=19 => (ordinal - 18) * 2 + port,
        20..=23 => ordinal - 20,
        24..=27 => ordinal - 24,
        40..=43 => ordinal - 40,
        44..=47 => ordinal - 44,
        48..=51 => ordinal - 48,
        52..=55 => ordinal - 52,
        56..=57 => (ordinal - 56) * 2 + port,
        58..=59 => {
            if port == 2 {
                ordinal - 58
            } else {
                (ordinal - 58) * 2 + port
            }
        }
        60..=63 => ordinal - 60,
        64..=67 => ordinal - 64,
        68..=71 => ordinal - 68,
        72..=75 => ordinal - 72,
        76..=79 => ordinal - 76,
        80..=83 => ordinal - if ordinal < 82 { 80 } else { 82 },
        84..=87 => ordinal - 84,
        88..=91 => ordinal - 88,
        92..=95 => ordinal - 92,
        96..=99 => ordinal - 96,
        100..=103 => ordinal - 100,
        104..=107 => ordinal - 104,
        108..=111 => ordinal - 108,
        _ => 0,
    }
}

const fn semantic_write_index(ordinal: usize, port: usize) -> usize {
    match ordinal {
        0..=3 => {
            if port == 2 {
                ordinal / 2
            } else {
                ordinal
            }
        }
        4..=5 => ordinal - 4,
        6..=7 => (ordinal - 6) * 2 + port,
        8..=11 => ordinal - 8,
        12..=15 => ordinal - 12,
        16..=17 => (ordinal - 16) * 2 + port,
        18..=19 => port * 2 + ordinal - 18,
        20..=23 => ordinal - 20,
        28..=39 => (ordinal - 28) / 3,
        44..=47 => ordinal - 44,
        48..=51 => ordinal - 48,
        52..=55 => ordinal - 52,
        56..=57 => {
            if port == 2 {
                ordinal - 56
            } else {
                (ordinal - 56) * 2 + port
            }
        }
        58..=59 => (ordinal - 58) * 2 + port,
        60..=63 => ordinal - 60,
        64..=67 => ordinal - 64,
        68..=71 => ordinal - 68,
        72..=75 => ordinal - 72,
        76..=79 => {
            if port == 2 {
                (ordinal - 76) / 2
            } else {
                ordinal - 76
            }
        }
        80..=81 => ordinal - 80,
        82..=83 => (ordinal - 82) * 2 + port,
        84..=87 => ordinal - 84,
        88..=91 => ordinal - 88,
        92..=95 => ordinal - 92,
        96..=99 => ordinal - 96,
        100..=103 => ordinal - 100,
        104..=107 => ordinal - 104,
        108..=111 => ordinal - 108,
        _ => 0,
    }
}

fn binary_expression<E: ExtensionField>(bits: &[WitIn]) -> Expression<E> {
    bits.iter()
        .enumerate()
        .fold(E::BaseField::ZERO.expr(), |sum, (bit, column)| {
            sum + column.expr() * (1_u64 << bit)
        })
}

fn multilinear_constant<E: ExtensionField>(
    bits: &[WitIn; LOCAL_INDEX_BITS],
    values: [i64; 4],
) -> Expression<E> {
    let x = bits[0].expr();
    let y = bits[1].expr();
    signed_constant(values[0])
        + x.clone() * signed_constant(values[1] - values[0])
        + y.clone() * signed_constant(values[2] - values[0])
        + x * y * signed_constant(values[3] - values[2] - values[1] + values[0])
}

fn stage_constant<E: ExtensionField>(
    bits: &[WitIn; LOCAL_INDEX_BITS],
    stage: (usize, usize, usize),
    value: impl Fn(usize) -> i64,
) -> Expression<E> {
    let (base, stride, len) = stage;
    let mut values = [0_i64; 4];
    for (local, slot) in values.iter_mut().enumerate() {
        *slot = value(base + stride * local.min(len - 1));
    }
    multilinear_constant::<E>(bits, values)
}

fn selected_sum<E: ExtensionField, const CHIP: usize>(
    config: &LlamaTinyCoreConfig,
    predicate: impl Fn(usize) -> bool,
) -> Expression<E> {
    selected_fixed_sum::<E, CHIP>(config, |ordinal| i64::from(predicate(ordinal)))
}

fn selected_fixed_sum<E: ExtensionField, const CHIP: usize>(
    config: &LlamaTinyCoreConfig,
    value: impl Fn(usize) -> i64,
) -> Expression<E> {
    CHIP_STAGES[CHIP].iter().copied().enumerate().fold(
        E::BaseField::ZERO.expr(),
        |sum, (index, stage)| {
            sum + config.stage_selectors[index].expr()
                * stage_constant::<E>(&config.local_index_bits, stage, &value)
        },
    )
}

fn signed_constant<E: ExtensionField>(value: i64) -> Expression<E> {
    if value < 0 {
        -E::BaseField::from_u64(value.unsigned_abs()).expr()
    } else {
        E::BaseField::from_u64(value as u64).expr()
    }
}

fn require_stage_equal<E: ExtensionField>(
    cb: &mut CircuitBuilder<E>,
    stage: usize,
    name: &str,
    selector: Expression<E>,
    left: Expression<E>,
    right: Expression<E>,
) -> Result<(), ZKVMError> {
    Ok(cb.require_zero(
        || format!("llama_tiny_stage_{stage}_{name}"),
        selector * (left - right),
    )?)
}

fn claim_role_and_row(ordinal: usize, port: usize) -> (u32, usize) {
    match ordinal {
        16..=17 => (tensor::TENSOR_HINT_ROLE_Q, (ordinal - 16) * 2 + port),
        18..=19 => (tensor::TENSOR_HINT_ROLE_K, (ordinal - 18) * 2 + port),
        20..=23 => (tensor::TENSOR_HINT_ROLE_V, ordinal - 20),
        24..=27 => (tensor::TENSOR_HINT_ROLE_QK, ordinal - 24),
        64..=67 => (tensor::TENSOR_HINT_ROLE_PV, ordinal - 64),
        68..=71 => (tensor::TENSOR_HINT_ROLE_O, ordinal - 68),
        92..=95 => (tensor::TENSOR_HINT_ROLE_GATE, ordinal - 92),
        96..=99 => (tensor::TENSOR_HINT_ROLE_UP, ordinal - 96),
        108..=111 => (tensor::TENSOR_HINT_ROLE_DOWN, ordinal - 108),
        _ => unreachable!("claim-free ordinal"),
    }
}

fn constrain_operation_stages<E: ExtensionField, const CHIP: usize>(
    cb: &mut CircuitBuilder<E>,
    config: &LlamaTinyCoreConfig,
) -> Result<(), ZKVMError> {
    let reads = [
        (
            config.tensor_read_enabled,
            config.tensor_read_index,
            config.tensor_read_value,
            config.tensor_read_id_lo,
            config.tensor_read_id_hi,
            config.tensor_read_version,
        ),
        (
            config.tensor_read2_enabled,
            config.tensor_read2_index,
            config.tensor_read2_value,
            config.tensor_read2_id_lo,
            config.tensor_read2_id_hi,
            config.tensor_read2_version,
        ),
        (
            config.tensor_read3_enabled,
            config.tensor_read3_index,
            config.tensor_read3_value,
            config.tensor_read3_id_lo,
            config.tensor_read3_id_hi,
            config.tensor_read3_version,
        ),
    ];
    let writes = [
        (
            config.tensor_write_enabled,
            config.tensor_write_index,
            config.tensor_write_value,
        ),
        (
            config.tensor_write2_enabled,
            config.tensor_write2_index,
            config.tensor_write2_value,
        ),
        (
            config.tensor_write3_enabled,
            config.tensor_write3_index,
            config.tensor_write3_value,
        ),
    ];
    let rv = [reads[0].2, reads[1].2, reads[2].2];
    let wv = [writes[0].2, writes[1].2, writes[2].2];
    let zero = E::BaseField::ZERO.expr();
    let one = E::BaseField::ONE.expr();
    let x = config.local_index_bits[0].expr();
    let y = config.local_index_bits[1].expr();
    let operand = |lane: usize, index: usize| config.lanes[lane].operands[index].expr();
    let result = |lane: usize| config.lanes[lane].result.expr();

    for (stage_index, &stage) in CHIP_STAGES[CHIP].iter().enumerate() {
        let (base, _, _) = stage;
        let selector = config.stage_selectors[stage_index].expr();
        let fixed = |value: &dyn Fn(usize) -> i64| {
            stage_constant::<E>(&config.local_index_bits, stage, value)
        };
        let bind =
            |cb: &mut CircuitBuilder<E>, name: &str, left: Expression<E>, right: Expression<E>| {
                require_stage_equal(cb, stage_index, name, selector.clone(), left, right)
            };

        for port in 0..3 {
            bind(
                cb,
                &format!("read_{port}_index"),
                reads[port].1.expr(),
                fixed(&|ordinal| {
                    if semantic_read_enabled(ordinal, port) {
                        semantic_read_index(ordinal, port) as i64
                    } else {
                        0
                    }
                }),
            )?;
            bind(
                cb,
                &format!("write_{port}_index"),
                writes[port].1.expr(),
                fixed(&|ordinal| {
                    if semantic_write_enabled(ordinal, port) {
                        semantic_write_index(ordinal, port) as i64
                    } else {
                        0
                    }
                }),
            )?;
        }
        bind(
            cb,
            "state_value",
            config.value.expr(),
            fixed(&|ordinal| match ordinal {
                0 => 8_697,
                111 => 152,
                _ => 0,
            }),
        )?;
        if !matches!(base, 24..=30) {
            for (limb, column) in config.limbs.iter().enumerate() {
                bind(
                    cb,
                    &format!("zero_state_limb_{limb}"),
                    column.expr(),
                    zero.clone(),
                )?;
            }
        }
        for input in 0..5 {
            let used = match CHIP {
                CHIP_RMS_LOOKUP | CHIP_SWIGLU_LOOKUP => input == 0,
                CHIP_SOFTMAX_LOW_DIGIT => input < 3,
                CHIP_SOFTMAX_EXP3 => input == 3,
                CHIP_SOFTMAX_EXP4 => input == 4,
                _ => false,
            };
            if !used {
                bind(
                    cb,
                    &format!("zero_lookup_input_{input}"),
                    config.lookup_inputs[input].expr(),
                    zero.clone(),
                )?;
            }
        }
        if !matches!(
            CHIP,
            CHIP_RMS_LOOKUP | CHIP_SOFTMAX_EXP3 | CHIP_SOFTMAX_EXP4 | CHIP_SWIGLU_LOOKUP
        ) {
            bind(
                cb,
                "zero_lookup_output",
                config.lookup_output.expr(),
                zero.clone(),
            )?;
        }

        for port in 0..2 {
            if semantic_claim_enabled(base, port) {
                let claim = config.claims[port];
                let read_port = if base <= 19 { port } else { 0 };
                bind(
                    cb,
                    "claim_cycle",
                    claim.cycle.expr(),
                    config.call_cycle.expr(),
                )?;
                bind(
                    cb,
                    "claim_output_id_lo",
                    claim.output_id_lo.expr(),
                    reads[read_port].3.expr(),
                )?;
                bind(
                    cb,
                    "claim_output_id_hi",
                    claim.output_id_hi.expr(),
                    reads[read_port].4.expr(),
                )?;
                bind(
                    cb,
                    "claim_output_version",
                    claim.output_version.expr(),
                    reads[read_port].5.expr(),
                )?;
                bind(
                    cb,
                    "claim_role",
                    claim.role.expr(),
                    fixed(&|ordinal| i64::from(claim_role_and_row(ordinal, port).0)),
                )?;
                bind(
                    cb,
                    "claim_row",
                    claim.row.expr(),
                    fixed(&|ordinal| claim_role_and_row(ordinal, port).1 as i64),
                )?;
                bind(cb, "claim_value", claim.value.expr(), rv[read_port].expr())?;
            }
        }

        match base {
            0 => {
                bind(cb, "fanout0", wv[0].expr(), rv[0].expr())?;
                bind(cb, "fanout1", wv[1].expr(), rv[0].expr())?;
                bind(cb, "square_a", operand(0, 0), rv[0].expr())?;
                bind(cb, "square_b", operand(0, 1), rv[0].expr())?;
                bind(cb, "square_c", operand(0, 2), zero.clone())?;
                bind(cb, "square_d", operand(0, 3), zero.clone())?;
                let input0 = i64::from(tensor::llama_tiny::INPUT[0][0]);
                let input1 = i64::from(tensor::llama_tiny::INPUT[1][0]);
                let first = signed_constant(input0) + y.clone() * signed_constant(input1 - input0);
                bind(
                    cb,
                    "energy_first_a",
                    operand(1, 0),
                    x.clone() * first.clone(),
                )?;
                bind(cb, "energy_first_b", operand(1, 1), x.clone() * first)?;
                bind(
                    cb,
                    "energy_second_a",
                    operand(1, 2),
                    x.clone() * rv[0].expr(),
                )?;
                bind(
                    cb,
                    "energy_second_b",
                    operand(1, 3),
                    x.clone() * rv[0].expr(),
                )?;
                bind(cb, "energy_write", wv[2].expr(), x.clone() * result(1))?;
            }
            4 | 80 => {
                bind(
                    cb,
                    "lookup_input",
                    config.lookup_inputs[0].expr(),
                    rv[0].expr(),
                )?;
                bind(
                    cb,
                    "lookup_write",
                    wv[0].expr(),
                    config.lookup_output.expr(),
                )?;
            }
            6 | 82 => {
                bind(cb, "fanout0", wv[0].expr(), rv[0].expr())?;
                bind(cb, "fanout1", wv[1].expr(), rv[0].expr())?;
            }
            8 | 84 => {
                let weight = fixed(&|ordinal| {
                    let col = ordinal % 2;
                    i64::from(if ordinal <= 11 {
                        tensor::llama_tiny::INPUT_NORM_WEIGHT[col]
                    } else {
                        tensor::llama_tiny::POST_NORM_WEIGHT[col]
                    })
                });
                bind(cb, "norm_inv", operand(0, 0), rv[1].expr())?;
                bind(cb, "norm_weight", operand(0, 1), weight)?;
                bind(cb, "norm_zero_c", operand(0, 2), zero.clone())?;
                bind(cb, "norm_zero_d", operand(0, 3), zero.clone())?;
                bind(cb, "norm_value", operand(1, 0), result(0))?;
                bind(cb, "norm_input", operand(1, 1), rv[0].expr())?;
                bind(cb, "norm_zero2_c", operand(1, 2), zero.clone())?;
                bind(cb, "norm_zero2_d", operand(1, 3), zero.clone())?;
                bind(cb, "norm_write", wv[0].expr(), result(1))?;
            }
            12 => {
                for value in &wv {
                    bind(cb, "matrix_fanout", value.expr(), rv[0].expr())?;
                }
            }
            16 => {
                let cos0 =
                    fixed(&|ordinal| i64::from(tensor::llama_tiny::ROPE_COS[ordinal % 2][0]));
                let cos1 =
                    fixed(&|ordinal| i64::from(tensor::llama_tiny::ROPE_COS[ordinal % 2][1]));
                let sin0 =
                    fixed(&|ordinal| i64::from(tensor::llama_tiny::ROPE_SIN[ordinal % 2][0]));
                let sin1 =
                    fixed(&|ordinal| i64::from(tensor::llama_tiny::ROPE_SIN[ordinal % 2][1]));
                bind(cb, "rope0_a", operand(0, 0), rv[0].expr())?;
                bind(cb, "rope0_b", operand(0, 1), cos0)?;
                bind(cb, "rope0_c", operand(0, 2), -rv[1].expr())?;
                bind(cb, "rope0_d", operand(0, 3), sin0)?;
                bind(cb, "rope1_a", operand(1, 0), rv[1].expr())?;
                bind(cb, "rope1_b", operand(1, 1), cos1)?;
                bind(cb, "rope1_c", operand(1, 2), rv[0].expr())?;
                bind(cb, "rope1_d", operand(1, 3), sin1)?;
                bind(cb, "rope_write0", wv[0].expr(), result(0))?;
                bind(cb, "rope_write1", wv[1].expr(), result(1))?;
            }
            20 | 64 | 68 | 92 | 96 => {
                bind(cb, "rescale_a", operand(0, 0), rv[0].expr())?;
                bind(cb, "rescale_b", operand(0, 1), one.clone())?;
                bind(cb, "rescale_c", operand(0, 2), zero.clone())?;
                bind(cb, "rescale_d", operand(0, 3), zero.clone())?;
                bind(cb, "rescale_write", wv[0].expr(), result(0))?;
            }
            24 => {
                let shift0 =
                    E::BaseField::from_u64(tensor::llama_tiny::ATTENTION_SHIFTS[0] as u64).expr();
                let shift1 =
                    E::BaseField::from_u64(tensor::llama_tiny::ATTENTION_SHIFTS[1] as u64).expr();
                let shift = shift0.clone() + y.clone() * (shift1 - shift0);
                let mut magnitude = zero.clone();
                let mut coefficient = E::BaseField::ONE.expr();
                for limb in &config.limbs {
                    magnitude = magnitude + limb.expr() * coefficient.clone();
                    coefficient = coefficient * E::BaseField::from_u64(1 << 16).expr();
                }
                bind(cb, "score_minus_shift", shift - rv[0].expr(), magnitude)?;
            }
            28 | 29 | 30 => {
                bind(cb, "digit0", wv[0].expr(), config.limbs[0].expr())?;
                if base < 30 {
                    bind(cb, "digit1", wv[1].expr(), config.limbs[1].expr())?;
                    for limb in 0..3 {
                        bind(
                            cb,
                            &format!("advance_{limb}"),
                            config.next_limbs[limb].expr(),
                            config.limbs[limb + 2].expr(),
                        )?;
                    }
                    for limb in 3..5 {
                        bind(
                            cb,
                            &format!("advance_{limb}"),
                            config.next_limbs[limb].expr(),
                            zero.clone(),
                        )?;
                    }
                }
            }
            40 => {
                for port in 0..3 {
                    bind(
                        cb,
                        "low_digit_lookup",
                        config.lookup_inputs[port].expr(),
                        rv[port].expr(),
                    )?;
                }
            }
            44 => {
                bind(
                    cb,
                    "exp3_input",
                    config.lookup_inputs[3].expr(),
                    rv[0].expr(),
                )?;
                bind(cb, "exp3_output", wv[0].expr(), config.lookup_output.expr())?;
            }
            48 => {
                bind(
                    cb,
                    "exp4_input",
                    config.lookup_inputs[4].expr(),
                    rv[0].expr(),
                )?;
                bind(cb, "exp4_output", wv[0].expr(), config.lookup_output.expr())?;
            }
            52 => {
                bind(
                    cb,
                    "five_digit_low",
                    operand(0, 0),
                    E::BaseField::from_u64(1024_u64.pow(3)).expr(),
                )?;
                bind(cb, "five_digit_exp3", operand(0, 1), rv[0].expr())?;
                bind(cb, "five_digit_zero0", operand(0, 2), zero.clone())?;
                bind(cb, "five_digit_zero1", operand(0, 3), zero.clone())?;
                bind(cb, "five_digit_partial", operand(1, 0), result(0))?;
                bind(cb, "five_digit_exp4", operand(1, 1), rv[1].expr())?;
                bind(cb, "five_digit_zero2", operand(1, 2), zero.clone())?;
                bind(cb, "five_digit_zero3", operand(1, 3), zero.clone())?;
                bind(cb, "five_digit_product", wv[0].expr(), result(1))?;
            }
            56 => {
                bind(cb, "mask_keep", wv[0].expr(), rv[0].expr())?;
                bind(cb, "mask_causal", wv[1].expr(), x.clone() * rv[1].expr())?;
                bind(cb, "mask_sum_a", operand(0, 0), wv[0].expr())?;
                bind(cb, "mask_sum_b", operand(0, 1), one.clone())?;
                bind(cb, "mask_sum_c", operand(0, 2), wv[1].expr())?;
                bind(cb, "mask_sum_d", operand(0, 3), one.clone())?;
                bind(cb, "mask_sum", wv[2].expr(), result(0))?;
            }
            58 => {
                for lane in 0..2 {
                    bind(cb, "normalize_numerator", operand(lane, 0), rv[lane].expr())?;
                    bind(
                        cb,
                        "normalize_scale",
                        operand(lane, 1),
                        E::BaseField::from_u64(1 << tensor::llama_tiny::Q20_SHIFT).expr(),
                    )?;
                    bind(cb, "normalize_quotient", operand(lane, 2), -wv[lane].expr())?;
                    bind(cb, "normalize_denominator", operand(lane, 3), rv[2].expr())?;
                    bind(cb, "normalize_result", result(lane), zero.clone())?;
                    bind(
                        cb,
                        "normalize_lane_quotient",
                        config.lanes[lane].quotient.expr(),
                        wv[lane].expr(),
                    )?;
                }
                bind(
                    cb,
                    "normalization_sum",
                    wv[0].expr() + wv[1].expr(),
                    E::BaseField::from_u64(1 << tensor::llama_tiny::Q20_SHIFT).expr(),
                )?;
            }
            60 => bind(cb, "probability_fanout", wv[0].expr(), rv[0].expr())?,
            72 => {
                bind(cb, "residual_a", operand(0, 0), rv[0].expr())?;
                bind(cb, "residual_b", operand(0, 1), one.clone())?;
                bind(cb, "residual_c", operand(0, 2), rv[1].expr())?;
                bind(cb, "residual_d", operand(0, 3), one.clone())?;
                bind(cb, "residual_write", wv[0].expr(), result(0))?;
            }
            76 => {
                bind(cb, "post_fanout0", wv[0].expr(), rv[0].expr())?;
                bind(cb, "post_fanout1", wv[1].expr(), rv[0].expr())?;
                bind(cb, "post_square_a", operand(0, 0), rv[0].expr())?;
                bind(cb, "post_square_b", operand(0, 1), rv[0].expr())?;
                bind(cb, "post_square_c", operand(0, 2), zero.clone())?;
                bind(cb, "post_square_d", operand(0, 3), zero.clone())?;
                let first = signed_constant(199) + y.clone() * signed_constant(111 - 199);
                bind(
                    cb,
                    "post_energy_first_a",
                    operand(1, 0),
                    x.clone() * first.clone(),
                )?;
                bind(cb, "post_energy_first_b", operand(1, 1), x.clone() * first)?;
                bind(
                    cb,
                    "post_energy_second_a",
                    operand(1, 2),
                    x.clone() * rv[0].expr(),
                )?;
                bind(
                    cb,
                    "post_energy_second_b",
                    operand(1, 3),
                    x.clone() * rv[0].expr(),
                )?;
                bind(cb, "post_energy_write", wv[2].expr(), x.clone() * result(1))?;
            }
            88 => {
                bind(cb, "ffn_fanout0", wv[0].expr(), rv[0].expr())?;
                bind(cb, "ffn_fanout1", wv[1].expr(), rv[0].expr())?;
            }
            100 => {
                let gate = fixed(&|ordinal| {
                    i64::from([[19_i32, -14_i32], [16_i32, 7_i32]][ordinal / 2 - 50][ordinal % 2])
                });
                bind(cb, "swiglu_source", rv[0].expr(), gate.clone())?;
                bind(cb, "swiglu_key", config.lookup_inputs[0].expr(), gate)?;
                bind(
                    cb,
                    "swiglu_output",
                    wv[0].expr(),
                    config.lookup_output.expr(),
                )?;
            }
            104 => {
                bind(cb, "hadamard_a", operand(0, 0), rv[0].expr())?;
                bind(cb, "hadamard_b", operand(0, 1), rv[1].expr())?;
                bind(cb, "hadamard_zero_c", operand(0, 2), zero.clone())?;
                bind(cb, "hadamard_zero_d", operand(0, 3), zero.clone())?;
                bind(cb, "hadamard_write", wv[0].expr(), result(0))?;
            }
            108 => {
                bind(cb, "down_a", operand(0, 0), rv[0].expr())?;
                bind(cb, "down_b", operand(0, 1), one.clone())?;
                bind(cb, "down_zero_c", operand(0, 2), zero.clone())?;
                bind(cb, "down_zero_d", operand(0, 3), zero.clone())?;
                bind(cb, "residual_a", operand(1, 0), result(0))?;
                bind(cb, "residual_b", operand(1, 1), one.clone())?;
                bind(cb, "residual_c", operand(1, 2), rv[1].expr())?;
                bind(cb, "residual_d", operand(1, 3), one.clone())?;
                bind(cb, "residual_write", wv[0].expr(), result(1))?;
            }
            _ => unreachable!("unrecognized operation stage {base}"),
        }
    }
    Ok(())
}

fn constrain_semantic_sources<E: ExtensionField, const CHIP: usize>(
    cb: &mut CircuitBuilder<E>,
    config: &LlamaTinyCoreConfig,
) -> Result<(), ZKVMError> {
    let reads = [
        (
            config.tensor_read_enabled,
            config.tensor_read_id_lo,
            config.tensor_read_id_hi,
            config.tensor_read_version,
            config.tensor_read_index,
            config.tensor_read_value,
        ),
        (
            config.tensor_read2_enabled,
            config.tensor_read2_id_lo,
            config.tensor_read2_id_hi,
            config.tensor_read2_version,
            config.tensor_read2_index,
            config.tensor_read2_value,
        ),
        (
            config.tensor_read3_enabled,
            config.tensor_read3_id_lo,
            config.tensor_read3_id_hi,
            config.tensor_read3_version,
            config.tensor_read3_index,
            config.tensor_read3_value,
        ),
    ];
    let writes = [
        (
            config.tensor_write_enabled,
            config.tensor_write_id_lo,
            config.tensor_write_id_hi,
            config.tensor_write_version,
            config.tensor_write_index,
            config.tensor_write_value,
        ),
        (
            config.tensor_write2_enabled,
            config.tensor_write2_id_lo,
            config.tensor_write2_id_hi,
            config.tensor_write2_version,
            config.tensor_write2_index,
            config.tensor_write2_value,
        ),
        (
            config.tensor_write3_enabled,
            config.tensor_write3_id_lo,
            config.tensor_write3_id_hi,
            config.tensor_write3_version,
            config.tensor_write3_index,
            config.tensor_write3_value,
        ),
    ];
    for port in 0..3 {
        cb.require_equal(
            || format!("llama_tiny_read_{port}_schedule"),
            reads[port].0.expr(),
            selected_sum::<E, CHIP>(config, |ordinal| semantic_read_enabled(ordinal, port)),
        )?;
        cb.require_equal(
            || format!("llama_tiny_write_{port}_schedule"),
            writes[port].0.expr(),
            selected_sum::<E, CHIP>(config, |ordinal| semantic_write_enabled(ordinal, port)),
        )?;
    }
    for port in 0..2 {
        cb.require_equal(
            || format!("llama_tiny_claim_{port}_schedule"),
            config.claims[port].enabled.expr(),
            selected_sum::<E, CHIP>(config, |ordinal| semantic_claim_enabled(ordinal, port)),
        )?;
        cb.require_equal(
            || format!("llama_tiny_lane_{port}_schedule"),
            config.lanes[port].enabled.expr(),
            selected_sum::<E, CHIP>(config, |ordinal| semantic_lane_enabled(ordinal, port)),
        )?;
        cb.require_equal(
            || format!("llama_tiny_lane_{port}_rescale_schedule"),
            config.lanes[port].rescale.expr(),
            selected_sum::<E, CHIP>(config, |ordinal| {
                semantic_lane_shift(ordinal, port).is_some()
            }),
        )?;
        cb.require_equal(
            || format!("llama_tiny_lane_{port}_q20_schedule"),
            config.lanes[port].q20.expr(),
            selected_sum::<E, CHIP>(config, |ordinal| {
                semantic_lane_shift(ordinal, port) == Some(tensor::llama_tiny::Q20_SHIFT)
            }),
        )?;
        cb.require_equal(
            || format!("llama_tiny_lane_{port}_normalization_schedule"),
            config.lanes[port].normalize.expr(),
            selected_sum::<E, CHIP>(config, |ordinal| matches!(ordinal, 58..=59)),
        )?;
    }

    constrain_operation_stages::<E, CHIP>(cb, config)?;
    Ok(())
}

impl<E: ExtensionField, const CHIP: usize> Instruction<E> for LlamaTinyCoreInstruction<E, CHIP> {
    type InstructionConfig = LlamaTinyCoreConfig;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[]
    }
    fn name() -> String {
        CHIP_NAMES[CHIP].into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let active = cb.create_witin(|| "llama_tiny_active");
        cb.require_equal(
            || "llama_tiny_active_row",
            active.expr(),
            E::BaseField::ONE.expr(),
        )?;
        let lookup_inputs =
            std::array::from_fn(|i| cb.create_witin(|| format!("llama_tiny_lookup_input_{i}")));
        let mut new = |name: &'static str| cb.create_witin(|| name);
        let import_cycle = new("llama_tiny_import_cycle");
        let call_cycle = new("llama_tiny_call_cycle");
        let next_call_cycle = new("llama_tiny_next_call_cycle");
        let input_id_lo = new("llama_tiny_input_id_lo");
        let input_id_hi = new("llama_tiny_input_id_hi");
        let input_version = new("llama_tiny_input_version");
        let next_input_id_lo = new("llama_tiny_next_input_id_lo");
        let next_input_id_hi = new("llama_tiny_next_input_id_hi");
        let next_input_version = new("llama_tiny_next_input_version");
        let output_id_lo = new("llama_tiny_output_id_lo");
        let output_id_hi = new("llama_tiny_output_id_hi");
        let output_version = new("llama_tiny_output_version");
        let next_output_id_lo = new("llama_tiny_next_output_id_lo");
        let next_output_id_hi = new("llama_tiny_next_output_id_hi");
        let next_output_version = new("llama_tiny_next_output_version");
        let family = new("llama_tiny_family");
        let next_family = new("llama_tiny_next_family");
        let stage = new("llama_tiny_stage");
        let next_stage = new("llama_tiny_next_stage");
        let op = new("llama_tiny_op");
        let next_op = new("llama_tiny_next_op");
        drop(new);
        let ordinal_bits =
            std::array::from_fn(|bit| cb.create_witin(|| format!("llama_tiny_ordinal_bit_{bit}")));
        let next_ordinal_bits = std::array::from_fn(|bit| {
            cb.create_witin(|| format!("llama_tiny_next_ordinal_bit_{bit}"))
        });
        let local_index_bits = std::array::from_fn(|bit| {
            cb.create_witin(|| format!("llama_tiny_local_index_bit_{bit}"))
        });
        let stage_selectors = std::array::from_fn(|stage| {
            cb.create_witin(|| format!("llama_tiny_local_stage_{stage}"))
        });
        let mut new = |name: &'static str| cb.create_witin(|| name);
        let accumulator = new("llama_tiny_accumulator");
        let next_accumulator = new("llama_tiny_next_accumulator");
        let value = new("llama_tiny_value");
        let next_value = new("llama_tiny_next_value");
        drop(new);
        let limbs = std::array::from_fn(|i| cb.create_witin(|| format!("llama_tiny_limb_{i}")));
        let next_limbs =
            std::array::from_fn(|i| cb.create_witin(|| format!("llama_tiny_next_limb_{i}")));
        let lanes = std::array::from_fn(|lane| ArithmeticLaneConfig {
            enabled: cb.create_witin(|| format!("llama_tiny_lane_{lane}_enabled")),
            rescale: cb.create_witin(|| format!("llama_tiny_lane_{lane}_rescale")),
            q20: cb.create_witin(|| format!("llama_tiny_lane_{lane}_q20")),
            normalize: cb.create_witin(|| format!("llama_tiny_lane_{lane}_normalize")),
            operands: std::array::from_fn(|operand| {
                cb.create_witin(|| format!("llama_tiny_lane_{lane}_operand_{operand}"))
            }),
            result: cb.create_witin(|| format!("llama_tiny_lane_{lane}_result")),
            quotient: cb.create_witin(|| format!("llama_tiny_lane_{lane}_quotient")),
            remainder: cb.create_witin(|| format!("llama_tiny_lane_{lane}_remainder")),
        });
        let remainder_bits = std::array::from_fn(|lane| {
            std::array::from_fn(|bit| {
                cb.create_witin(|| format!("llama_tiny_lane_{lane}_remainder_bit_{bit}"))
            })
        });
        let mut new = |name: &'static str| cb.create_witin(|| name);
        let tensor_read_enabled = new("llama_tiny_tensor_read_enabled");
        let tensor_read_id_lo = new("llama_tiny_tensor_read_id_lo");
        let tensor_read_id_hi = new("llama_tiny_tensor_read_id_hi");
        let tensor_read_version = new("llama_tiny_tensor_read_version");
        let tensor_read_index = new("llama_tiny_tensor_read_index");
        let tensor_read_value = new("llama_tiny_tensor_read_value");
        let tensor_read2_enabled = new("llama_tiny_tensor_read2_enabled");
        let tensor_read2_id_lo = new("llama_tiny_tensor_read2_id_lo");
        let tensor_read2_id_hi = new("llama_tiny_tensor_read2_id_hi");
        let tensor_read2_version = new("llama_tiny_tensor_read2_version");
        let tensor_read2_index = new("llama_tiny_tensor_read2_index");
        let tensor_read2_value = new("llama_tiny_tensor_read2_value");
        let tensor_read3_enabled = new("llama_tiny_tensor_read3_enabled");
        let tensor_read3_id_lo = new("llama_tiny_tensor_read3_id_lo");
        let tensor_read3_id_hi = new("llama_tiny_tensor_read3_id_hi");
        let tensor_read3_version = new("llama_tiny_tensor_read3_version");
        let tensor_read3_index = new("llama_tiny_tensor_read3_index");
        let tensor_read3_value = new("llama_tiny_tensor_read3_value");
        let tensor_write_enabled = new("llama_tiny_tensor_write_enabled");
        let tensor_write_id_lo = new("llama_tiny_tensor_write_id_lo");
        let tensor_write_id_hi = new("llama_tiny_tensor_write_id_hi");
        let tensor_write_version = new("llama_tiny_tensor_write_version");
        let tensor_write_index = new("llama_tiny_tensor_write_index");
        let tensor_write_value = new("llama_tiny_tensor_write_value");
        let tensor_write2_enabled = new("llama_tiny_tensor_write2_enabled");
        let tensor_write2_id_lo = new("llama_tiny_tensor_write2_id_lo");
        let tensor_write2_id_hi = new("llama_tiny_tensor_write2_id_hi");
        let tensor_write2_version = new("llama_tiny_tensor_write2_version");
        let tensor_write2_index = new("llama_tiny_tensor_write2_index");
        let tensor_write2_value = new("llama_tiny_tensor_write2_value");
        let tensor_write3_enabled = new("llama_tiny_tensor_write3_enabled");
        let tensor_write3_id_lo = new("llama_tiny_tensor_write3_id_lo");
        let tensor_write3_id_hi = new("llama_tiny_tensor_write3_id_hi");
        let tensor_write3_version = new("llama_tiny_tensor_write3_version");
        let tensor_write3_index = new("llama_tiny_tensor_write3_index");
        let tensor_write3_value = new("llama_tiny_tensor_write3_value");
        let lookup_output = new("llama_tiny_lookup_output");
        drop(new);
        let claims = std::array::from_fn(|port| ResidentClaimPortConfig {
            enabled: cb.create_witin(|| format!("llama_tiny_claim_{port}_enabled")),
            cycle: cb.create_witin(|| format!("llama_tiny_claim_{port}_cycle")),
            input_id_lo: cb.create_witin(|| format!("llama_tiny_claim_{port}_input_id_lo")),
            input_id_hi: cb.create_witin(|| format!("llama_tiny_claim_{port}_input_id_hi")),
            input_version: cb.create_witin(|| format!("llama_tiny_claim_{port}_input_version")),
            output_id_lo: cb.create_witin(|| format!("llama_tiny_claim_{port}_output_id_lo")),
            output_id_hi: cb.create_witin(|| format!("llama_tiny_claim_{port}_output_id_hi")),
            output_version: cb.create_witin(|| format!("llama_tiny_claim_{port}_output_version")),
            role: cb.create_witin(|| format!("llama_tiny_claim_{port}_role")),
            row: cb.create_witin(|| format!("llama_tiny_claim_{port}_row")),
            value: cb.create_witin(|| format!("llama_tiny_claim_{port}_value")),
        });

        for (name, selector) in [
            ("tensor_read", tensor_read_enabled),
            ("tensor_read2", tensor_read2_enabled),
            ("tensor_read3", tensor_read3_enabled),
            ("tensor_write", tensor_write_enabled),
            ("tensor_write2", tensor_write2_enabled),
            ("tensor_write3", tensor_write3_enabled),
            ("claim", claims[0].enabled),
            ("claim2", claims[1].enabled),
        ] {
            cb.assert_bit(|| format!("llama_tiny_{name}_selector"), selector.expr())?;
        }
        for (lane_index, lane) in lanes.iter().enumerate() {
            cb.assert_bit(
                || format!("llama_tiny_lane_{lane_index}_enabled_bit"),
                lane.enabled.expr(),
            )?;
            cb.assert_bit(
                || format!("llama_tiny_lane_{lane_index}_rescale_bit"),
                lane.rescale.expr(),
            )?;
            cb.assert_bit(
                || format!("llama_tiny_lane_{lane_index}_q20_bit"),
                lane.q20.expr(),
            )?;
            cb.assert_bit(
                || format!("llama_tiny_lane_{lane_index}_normalize_bit"),
                lane.normalize.expr(),
            )?;
            cb.require_zero(
                || format!("llama_tiny_lane_{lane_index}_q20_needs_rescale"),
                lane.q20.expr() * (E::BaseField::ONE.expr() - lane.rescale.expr()),
            )?;
            cb.require_zero(
                || format!("llama_tiny_lane_{lane_index}_rescale_needs_enabled"),
                lane.rescale.expr() * (E::BaseField::ONE.expr() - lane.enabled.expr()),
            )?;
            cb.require_zero(
                || format!("llama_tiny_lane_{lane_index}_normalize_shape"),
                lane.normalize.expr()
                    * (E::BaseField::ONE.expr() - lane.enabled.expr()
                        + lane.rescale.expr()
                        + lane.q20.expr()),
            )?;
            let raw = lane.operands[0].expr() * lane.operands[1].expr()
                + lane.operands[2].expr() * lane.operands[3].expr();
            let scale = E::BaseField::ONE.expr()
                + lane.rescale.expr()
                    * (E::BaseField::from_u64(1 << 16).expr() - E::BaseField::ONE.expr())
                + lane.q20.expr()
                    * (E::BaseField::from_u64(1 << 20).expr()
                        - E::BaseField::from_u64(1 << 16).expr());
            let half = lane.rescale.expr() * E::BaseField::from_u64(1 << 15).expr()
                + lane.q20.expr()
                    * (E::BaseField::from_u64(1 << 19).expr()
                        - E::BaseField::from_u64(1 << 15).expr());
            cb.require_zero(
                || format!("llama_tiny_lane_{lane_index}_division"),
                (lane.enabled.expr() - lane.normalize.expr())
                    * (raw.clone() + half - lane.quotient.expr() * scale - lane.remainder.expr()),
            )?;
            cb.require_zero(
                || format!("llama_tiny_lane_{lane_index}_raw_result"),
                (lane.enabled.expr() - lane.rescale.expr()) * (lane.result.expr() - raw),
            )?;
            cb.require_zero(
                || format!("llama_tiny_lane_{lane_index}_rescaled_result"),
                lane.rescale.expr() * (lane.result.expr() - lane.quotient.expr()),
            )?;
            let mut recomposed = E::BaseField::ZERO.expr();
            for (bit_index, bit) in remainder_bits[lane_index].iter().enumerate() {
                cb.assert_bit(
                    || format!("llama_tiny_lane_{lane_index}_remainder_bit_{bit_index}"),
                    bit.expr(),
                )?;
                recomposed = recomposed + bit.expr() * (1u64 << bit_index);
                if bit_index >= 16 {
                    cb.require_zero(
                        || format!("llama_tiny_lane_{lane_index}_q16_top_bit_{bit_index}"),
                        lane.rescale.expr()
                            * (E::BaseField::ONE.expr() - lane.q20.expr())
                            * bit.expr(),
                    )?;
                }
            }
            cb.require_zero(
                || format!("llama_tiny_lane_{lane_index}_remainder_bits"),
                lane.enabled.expr() * (lane.remainder.expr() - recomposed),
            )?;
            cb.require_zero(
                || format!("llama_tiny_lane_{lane_index}_raw_remainder"),
                lane.enabled.expr()
                    * (E::BaseField::ONE.expr() - lane.rescale.expr())
                    * lane.remainder.expr(),
            )?;
        }
        let ordinal = binary_expression::<E>(&ordinal_bits);
        let next_ordinal = binary_expression::<E>(&next_ordinal_bits);
        let local_index = binary_expression::<E>(&local_index_bits);
        for (bit, column) in ordinal_bits.iter().enumerate() {
            cb.assert_bit(|| format!("llama_tiny_ordinal_bit_{bit}"), column.expr())?;
        }
        for (bit, column) in next_ordinal_bits.iter().enumerate() {
            cb.assert_bit(
                || format!("llama_tiny_next_ordinal_bit_{bit}"),
                column.expr(),
            )?;
        }
        for (bit, column) in local_index_bits.iter().enumerate() {
            cb.assert_bit(
                || format!("llama_tiny_local_index_bit_{bit}"),
                column.expr(),
            )?;
        }
        let mut stage_sum = E::BaseField::ZERO.expr();
        let mut selected_base = E::BaseField::ZERO.expr();
        let mut expected_family = E::BaseField::ZERO.expr();
        let mut selected_stride = E::BaseField::ZERO.expr();
        for (index, selector) in stage_selectors.iter().enumerate() {
            cb.assert_bit(
                || format!("llama_tiny_local_stage_{index}_bit"),
                selector.expr(),
            )?;
            if let Some(&(base, stride, len)) = CHIP_STAGES[CHIP].get(index) {
                stage_sum = stage_sum + selector.expr();
                selected_base = selected_base + selector.expr() * base as u64;
                selected_stride = selected_stride + selector.expr() * stride as u64;
                expected_family = expected_family + selector.expr() * semantic_family(base) as u64;
                match len {
                    2 => {
                        for bit in 1..LOCAL_INDEX_BITS {
                            cb.require_zero(
                                || format!("llama_tiny_stage_{index}_local_bit_{bit}"),
                                selector.expr() * local_index_bits[bit].expr(),
                            )?;
                        }
                    }
                    4 => {
                        for bit in 2..LOCAL_INDEX_BITS {
                            cb.require_zero(
                                || format!("llama_tiny_stage_{index}_local_bit_{bit}"),
                                selector.expr() * local_index_bits[bit].expr(),
                            )?;
                        }
                    }
                    _ => unreachable!("all operation stages have two or four rows"),
                }
            } else {
                cb.require_zero(
                    || format!("llama_tiny_unused_local_stage_{index}"),
                    selector.expr(),
                )?;
            }
        }
        cb.require_equal(
            || "llama_tiny_unique_local_stage",
            stage_sum,
            E::BaseField::ONE.expr(),
        )?;
        cb.require_equal(
            || "llama_tiny_stage_local_ordinal",
            ordinal.clone(),
            selected_base + selected_stride * local_index,
        )?;
        cb.require_equal(|| "llama_tiny_family", family.expr(), expected_family)?;
        cb.require_equal(|| "llama_tiny_stage", stage.expr(), family.expr())?;
        cb.require_equal(
            || "llama_tiny_operation_ordinal",
            op.expr(),
            ordinal.clone(),
        )?;
        cb.require_equal(
            || "llama_tiny_state_value",
            accumulator.expr(),
            value.expr(),
        )?;
        cb.require_equal(
            || "llama_tiny_next_state_value",
            next_accumulator.expr(),
            next_value.expr(),
        )?;
        cb.require_equal(
            || "llama_tiny_ordinal_step",
            next_ordinal.clone(),
            ordinal.clone() + 1,
        )?;

        let state = llama_tiny_layer_state_record(
            import_cycle.expr(),
            call_cycle.expr(),
            input_id_lo.expr(),
            input_id_hi.expr(),
            input_version.expr(),
            output_id_lo.expr(),
            output_id_hi.expr(),
            output_version.expr(),
            ordinal.clone(),
            family.expr(),
            stage.expr(),
            op.expr(),
            binary_expression::<E>(&ordinal_bits[1..]),
            ordinal_bits[0].expr(),
            accumulator.expr(),
            value.expr(),
            std::array::from_fn(|index| limbs[index].expr()),
        );
        cb.read_rlc_record(
            || "llama_tiny_private_state_read",
            conditional_type(active.expr()),
            state.clone(),
            conditional_rlc(cb, active.expr(), &state),
        )?;
        let next_state = llama_tiny_layer_state_record(
            import_cycle.expr(),
            next_call_cycle.expr(),
            next_input_id_lo.expr(),
            next_input_id_hi.expr(),
            next_input_version.expr(),
            next_output_id_lo.expr(),
            next_output_id_hi.expr(),
            next_output_version.expr(),
            next_ordinal.clone(),
            next_family.expr(),
            next_stage.expr(),
            next_op.expr(),
            binary_expression::<E>(&next_ordinal_bits[1..]),
            next_ordinal_bits[0].expr(),
            next_accumulator.expr(),
            next_value.expr(),
            std::array::from_fn(|index| next_limbs[index].expr()),
        );
        cb.write_rlc_record(
            || "llama_tiny_private_state_write",
            conditional_type(active.expr()),
            next_state.clone(),
            conditional_rlc(cb, active.expr(), &next_state),
        )?;

        let local_index = binary_expression::<E>(&local_index_bits);
        let limb_write_selector = if CHIP == CHIP_SOFTMAX_ARITHMETIC {
            stage_selectors[0].expr()
        } else {
            E::BaseField::ZERO.expr()
        };
        let limb_write_score = limb_write_selector.clone() * local_index.clone();
        let limb_write = llama_tiny_softmax_limb_record(
            import_cycle.expr(),
            limb_write_score,
            std::array::from_fn(|index| limbs[index].expr()),
        );
        cb.write_rlc_record(
            || "llama_tiny_softmax_limb_write",
            conditional_type(limb_write_selector.clone()),
            limb_write.clone(),
            conditional_rlc(cb, limb_write_selector, &limb_write),
        )?;
        let limb_read_selector = if CHIP == CHIP_SOFTMAX_ARITHMETIC {
            stage_selectors[1].expr()
        } else {
            E::BaseField::ZERO.expr()
        };
        let limb_read_score = limb_read_selector.clone() * local_index;
        let limb_read = llama_tiny_softmax_limb_record(
            import_cycle.expr(),
            limb_read_score,
            std::array::from_fn(|index| limbs[index].expr()),
        );
        cb.read_rlc_record(
            || "llama_tiny_softmax_limb_read",
            conditional_type(limb_read_selector.clone()),
            limb_read.clone(),
            conditional_rlc(cb, limb_read_selector, &limb_read),
        )?;

        let read = tensor_space_record(
            import_cycle.expr(),
            tensor_read_id_lo.expr(),
            tensor_read_id_hi.expr(),
            tensor_read_version.expr(),
            tensor_read_index.expr(),
            tensor_read_value.expr(),
        );
        cb.read_rlc_record(
            || "llama_tiny_tensor_read",
            conditional_type(tensor_read_enabled.expr()),
            read.clone(),
            conditional_rlc(cb, tensor_read_enabled.expr(), &read),
        )?;
        let read2 = tensor_space_record(
            import_cycle.expr(),
            tensor_read2_id_lo.expr(),
            tensor_read2_id_hi.expr(),
            tensor_read2_version.expr(),
            tensor_read2_index.expr(),
            tensor_read2_value.expr(),
        );
        cb.read_rlc_record(
            || "llama_tiny_tensor_read2",
            conditional_type(tensor_read2_enabled.expr()),
            read2.clone(),
            conditional_rlc(cb, tensor_read2_enabled.expr(), &read2),
        )?;
        let read3 = tensor_space_record(
            import_cycle.expr(),
            tensor_read3_id_lo.expr(),
            tensor_read3_id_hi.expr(),
            tensor_read3_version.expr(),
            tensor_read3_index.expr(),
            tensor_read3_value.expr(),
        );
        cb.read_rlc_record(
            || "llama_tiny_tensor_read3",
            conditional_type(tensor_read3_enabled.expr()),
            read3.clone(),
            conditional_rlc(cb, tensor_read3_enabled.expr(), &read3),
        )?;
        let write = tensor_space_record(
            import_cycle.expr(),
            tensor_write_id_lo.expr(),
            tensor_write_id_hi.expr(),
            tensor_write_version.expr(),
            tensor_write_index.expr(),
            tensor_write_value.expr(),
        );
        cb.write_rlc_record(
            || "llama_tiny_tensor_write",
            conditional_type(tensor_write_enabled.expr()),
            write.clone(),
            conditional_rlc(cb, tensor_write_enabled.expr(), &write),
        )?;
        let write2 = tensor_space_record(
            import_cycle.expr(),
            tensor_write2_id_lo.expr(),
            tensor_write2_id_hi.expr(),
            tensor_write2_version.expr(),
            tensor_write2_index.expr(),
            tensor_write2_value.expr(),
        );
        cb.write_rlc_record(
            || "llama_tiny_tensor_write2",
            conditional_type(tensor_write2_enabled.expr()),
            write2.clone(),
            conditional_rlc(cb, tensor_write2_enabled.expr(), &write2),
        )?;
        let write3 = tensor_space_record(
            import_cycle.expr(),
            tensor_write3_id_lo.expr(),
            tensor_write3_id_hi.expr(),
            tensor_write3_version.expr(),
            tensor_write3_index.expr(),
            tensor_write3_value.expr(),
        );
        cb.write_rlc_record(
            || "llama_tiny_tensor_write3",
            conditional_type(tensor_write3_enabled.expr()),
            write3.clone(),
            conditional_rlc(cb, tensor_write3_enabled.expr(), &write3),
        )?;
        for (port, claim) in claims.iter().enumerate() {
            let record = tensor_resident_claim_record(
                claim.cycle.expr(),
                import_cycle.expr(),
                claim.input_id_lo.expr(),
                claim.input_id_hi.expr(),
                claim.input_version.expr(),
                claim.output_id_lo.expr(),
                claim.output_id_hi.expr(),
                claim.output_version.expr(),
                E::BaseField::from_u32(tensor::TENSOR_PROFILE_LLAMA_TINY).expr(),
                E::BaseField::ZERO.expr(),
                claim.role.expr(),
                claim.row.expr(),
                claim.value.expr(),
            );
            cb.write_rlc_record(
                || format!("llama_tiny_matrix_claim_{port}"),
                conditional_type(claim.enabled.expr()),
                record.clone(),
                conditional_rlc(cb, claim.enabled.expr(), &record),
            )?;
        }

        match CHIP {
            CHIP_RMS_LOOKUP => cb.lk_record(
                || "llama_tiny_rms_lookup",
                LookupTable::LlamaRmsInv,
                vec![lookup_inputs[0].expr(), lookup_output.expr()],
            )?,
            CHIP_SOFTMAX_LOW_DIGIT => {
                for digit in &lookup_inputs[..3] {
                    cb.lk_record(
                        || "llama_tiny_low_digit",
                        LookupTable::Dynamic,
                        vec![digit.expr(), E::BaseField::from_u32(16).expr()],
                    )?;
                }
            }
            CHIP_SOFTMAX_EXP3 => cb.lk_record(
                || "llama_tiny_exp3_lookup",
                LookupTable::LlamaSoftmaxExp3,
                vec![lookup_inputs[3].expr(), lookup_output.expr()],
            )?,
            CHIP_SOFTMAX_EXP4 => cb.lk_record(
                || "llama_tiny_exp4_lookup",
                LookupTable::LlamaSoftmaxExp4,
                vec![lookup_inputs[4].expr(), lookup_output.expr()],
            )?,
            CHIP_SWIGLU_LOOKUP => cb.lk_record(
                || "llama_tiny_swiglu_lookup",
                LookupTable::LlamaSwiGlu,
                vec![lookup_inputs[0].expr(), lookup_output.expr()],
            )?,
            _ => {}
        }
        let config = LlamaTinyCoreConfig {
            active,
            import_cycle,
            call_cycle,
            next_call_cycle,
            input_id_lo,
            input_id_hi,
            input_version,
            next_input_id_lo,
            next_input_id_hi,
            next_input_version,
            output_id_lo,
            output_id_hi,
            output_version,
            next_output_id_lo,
            next_output_id_hi,
            next_output_version,
            ordinal_bits,
            next_ordinal_bits,
            local_index_bits,
            stage_selectors,
            family,
            next_family,
            stage,
            next_stage,
            op,
            next_op,
            accumulator,
            next_accumulator,
            value,
            next_value,
            limbs,
            next_limbs,
            lanes,
            remainder_bits,
            tensor_read_enabled,
            tensor_read_id_lo,
            tensor_read_id_hi,
            tensor_read_version,
            tensor_read_index,
            tensor_read_value,
            tensor_read2_enabled,
            tensor_read2_id_lo,
            tensor_read2_id_hi,
            tensor_read2_version,
            tensor_read2_index,
            tensor_read2_value,
            tensor_read3_enabled,
            tensor_read3_id_lo,
            tensor_read3_id_hi,
            tensor_read3_version,
            tensor_read3_index,
            tensor_read3_value,
            tensor_write_enabled,
            tensor_write_id_lo,
            tensor_write_id_hi,
            tensor_write_version,
            tensor_write_index,
            tensor_write_value,
            tensor_write2_enabled,
            tensor_write2_id_lo,
            tensor_write2_id_hi,
            tensor_write2_version,
            tensor_write2_index,
            tensor_write2_value,
            tensor_write3_enabled,
            tensor_write3_id_lo,
            tensor_write3_id_hi,
            tensor_write3_version,
            tensor_write3_index,
            tensor_write3_value,
            claims,
            lookup_inputs,
            lookup_output,
        };
        constrain_semantic_sources::<E, CHIP>(cb, &config)?;
        Ok(config)
    }

    fn assign_instance(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: &mut [E::BaseField],
        _: &mut LkMultiplicity,
        _: &StepRecord,
    ) -> Result<(), ZKVMError> {
        Err(invalid(
            "llama-tiny Core is assigned from complete layer sections",
        ))
    }

    fn assign_instances(
        _: &Self::InstructionConfig,
        _: &mut ShardContext,
        _: usize,
        _: usize,
        _: &[StepRecord],
        _: &[StepIndex],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        Err(invalid(
            "rv32im must share the collected llama-tiny layer section",
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TensorCell {
    id: u64,
    version: u32,
    index: u32,
    value: i64,
}

#[derive(Clone, Copy, Debug)]
struct ClaimCell {
    resident: tensor::TensorResidentMatMulWitness,
    logical_row: u32,
    value: i32,
}

#[derive(Clone, Copy, Debug, Default)]
struct ArithmeticLane {
    enabled: bool,
    rescale: bool,
    q20: bool,
    normalize: bool,
    operands: [i64; 4],
    result: i64,
    quotient: i64,
    remainder: u32,
}

impl ArithmeticLane {
    fn exact(a: i64, b: i64, c: i64, d: i64) -> Self {
        Self {
            enabled: true,
            operands: [a, b, c, d],
            result: a * b + c * d,
            quotient: a * b + c * d,
            ..Self::default()
        }
    }

    fn centered(a: i64, b: i64, c: i64, d: i64, shift: u32) -> Self {
        let raw = a * b + c * d;
        let scale = 1_i64 << shift;
        let adjusted = raw + scale / 2;
        Self {
            enabled: true,
            rescale: true,
            q20: shift == tensor::llama_tiny::Q20_SHIFT,
            normalize: false,
            operands: [a, b, c, d],
            result: adjusted.div_euclid(scale),
            quotient: adjusted.div_euclid(scale),
            remainder: adjusted.rem_euclid(scale) as u32,
        }
    }

    fn normalization(numerator: i64, denominator: i64, quotient: i64) -> Self {
        debug_assert_eq!(
            i128::from(numerator) * (1_i128 << tensor::llama_tiny::Q20_SHIFT),
            i128::from(quotient) * i128::from(denominator),
        );
        Self {
            enabled: true,
            normalize: true,
            operands: [
                numerator,
                1_i64 << tensor::llama_tiny::Q20_SHIFT,
                -quotient,
                denominator,
            ],
            result: 0,
            quotient,
            remainder: 0,
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug)]
struct LlamaTinySemanticRow {
    ordinal: usize,
    family: usize,
    stage: usize,
    op: usize,
    coordinate_row: usize,
    coordinate_col: usize,
    value: i64,
    limbs: [u16; 5],
    reads: [Option<TensorCell>; 3],
    writes: [Option<TensorCell>; 3],
    claims: [Option<ClaimCell>; 2],
    lanes: [ArithmeticLane; 2],
    lookup_inputs: [u64; 5],
    lookup_output: i64,
}

impl LlamaTinySemanticRow {
    fn new(ordinal: usize) -> Self {
        Self {
            ordinal,
            family: semantic_family(ordinal),
            stage: semantic_family(ordinal),
            op: ordinal,
            coordinate_row: ordinal / 2,
            coordinate_col: ordinal % 2,
            value: 0,
            limbs: [0; 5],
            reads: [None; 3],
            writes: [None; 3],
            claims: [None; 2],
            lanes: [ArithmeticLane::default(); 2],
            lookup_inputs: [0; 5],
            lookup_output: 0,
        }
    }
}

fn layer_identity(section: &LlamaTinyLayerSection) -> LlamaTinyLayerIdentity {
    LlamaTinyLayerIdentity {
        import_cycle: section.import_cycle,
        attention_cycle: section.attention_cycle,
        ffn_cycle: section.ffn_cycle,
        input_tensor_id: section.input_tensor_id,
        input_version: section.input_version,
        attention_tensor_id: section.attention_tensor_id,
        attention_version: section.attention_version,
        output_tensor_id: section.output_tensor_id,
        output_version: section.output_version,
    }
}

fn semantic_cell<V: Into<i64>>(
    identity: &LlamaTinyLayerIdentity,
    domain: u32,
    index: usize,
    value: V,
) -> TensorCell {
    TensorCell {
        id: internal_tensor_id(identity, domain),
        version: 1,
        index: index as u32,
        value: value.into(),
    }
}

fn resident_input(
    resident: tensor::TensorResidentMatMulWitness,
    index: usize,
    value: i32,
) -> TensorCell {
    TensorCell {
        id: resident.input_tensor_id,
        version: resident.input_version,
        index: index as u32,
        value: i64::from(value),
    }
}

fn resident_output(resident: tensor::TensorResidentMatMulWitness, index: usize) -> TensorCell {
    TensorCell {
        id: resident.output_tensor_id,
        version: resident.output_version,
        index: index as u32,
        value: i64::from(resident.output[index]),
    }
}

fn resident_rhs(
    resident: tensor::TensorResidentMatMulWitness,
    index: usize,
    value: i32,
) -> TensorCell {
    TensorCell {
        id: resident.rhs_tensor_id.expect("RHS tensor id"),
        version: resident.rhs_tensor_version.expect("RHS tensor version"),
        index: index as u32,
        value: i64::from(value),
    }
}

fn semantic_schedule(section: &LlamaTinyLayerSection) -> Vec<LlamaTinySemanticRow> {
    let identity = layer_identity(section);
    let trace = &section.trace;
    let mut rows = (0..LLAMA_TINY_TOTAL_ROWS)
        .map(LlamaTinySemanticRow::new)
        .collect::<Vec<_>>();

    for cell in 0..4 {
        let token = cell / 2;
        let col = cell % 2;
        let input = tensor::llama_tiny::INPUT[token][col];
        let row = &mut rows[cell];
        row.reads[0] = Some(TensorCell {
            id: section.input_tensor_id,
            version: section.input_version,
            index: cell as u32,
            value: i64::from(input),
        });
        row.writes[0] = Some(semantic_cell(&identity, 1, cell, input));
        row.writes[1] = Some(semantic_cell(&identity, 2, cell, input));
        row.lanes[0] = ArithmeticLane::exact(i64::from(input), i64::from(input), 0, 0);
        if col == 1 {
            row.writes[2] = Some(semantic_cell(
                &identity,
                3,
                token,
                trace.input_energy[token],
            ));
            row.lanes[1] = ArithmeticLane::exact(
                i64::from(tensor::llama_tiny::INPUT[token][0]),
                i64::from(tensor::llama_tiny::INPUT[token][0]),
                i64::from(input),
                i64::from(input),
            );
        }
    }
    for token in 0..2 {
        let row = &mut rows[4 + token];
        row.reads[0] = Some(semantic_cell(
            &identity,
            3,
            token,
            trace.input_energy[token],
        ));
        row.writes[0] = Some(semantic_cell(
            &identity,
            4,
            token,
            tensor::llama_tiny::INPUT_INV_RMS[token],
        ));
        row.lookup_inputs[0] = trace.input_energy[token] as u64;
        row.lookup_output = i64::from(tensor::llama_tiny::INPUT_INV_RMS[token]);
    }
    for token in 0..2 {
        let inv = tensor::llama_tiny::INPUT_INV_RMS[token];
        let row = &mut rows[6 + token];
        row.reads[0] = Some(semantic_cell(&identity, 4, token, inv));
        row.writes[0] = Some(semantic_cell(&identity, 5, token * 2, inv));
        row.writes[1] = Some(semantic_cell(&identity, 5, token * 2 + 1, inv));
    }
    for cell in 0..4 {
        let token = cell / 2;
        let col = cell % 2;
        let inv = tensor::llama_tiny::INPUT_INV_RMS[token];
        let input = tensor::llama_tiny::INPUT[token][col];
        let weighted = ArithmeticLane::centered(
            i64::from(inv),
            i64::from(tensor::llama_tiny::INPUT_NORM_WEIGHT[col]),
            0,
            0,
            tensor::llama_tiny::Q16_SHIFT,
        );
        let row = &mut rows[8 + cell];
        row.reads[0] = Some(semantic_cell(&identity, 1, cell, input));
        row.reads[1] = Some(semantic_cell(&identity, 5, cell, inv));
        row.lanes[0] = weighted;
        row.lanes[1] = ArithmeticLane::centered(
            weighted.result,
            i64::from(input),
            0,
            0,
            tensor::llama_tiny::Q16_SHIFT,
        );
        row.writes[0] = Some(semantic_cell(
            &identity,
            6,
            cell,
            trace.input_norm[token][col],
        ));
    }
    for cell in 0..4 {
        let value = trace.input_norm[cell / 2][cell % 2];
        let row = &mut rows[12 + cell];
        row.reads[0] = Some(semantic_cell(&identity, 6, cell, value));
        for (port, matrix) in section.matrices[..3].iter().enumerate() {
            row.writes[port] = Some(resident_input(matrix.resident.unwrap(), cell, value));
        }
    }
    for token in 0..2 {
        let row = &mut rows[16 + token];
        let resident = section.matrices[0].resident.unwrap();
        for dim in 0..2 {
            let cell = token * 2 + dim;
            row.reads[dim] = Some(resident_output(resident, cell));
            row.claims[dim] = Some(ClaimCell {
                resident,
                logical_row: cell as u32,
                value: resident.output[cell],
            });
            row.writes[dim] = Some(resident_input(
                section.matrices[3].resident.unwrap(),
                cell,
                trace.q_rope[token][dim],
            ));
        }
        row.lanes[0] = ArithmeticLane::centered(
            i64::from(trace.q_projection[token][0]),
            i64::from(tensor::llama_tiny::ROPE_COS[token][0]),
            -i64::from(trace.q_projection[token][1]),
            i64::from(tensor::llama_tiny::ROPE_SIN[token][0]),
            tensor::llama_tiny::Q16_SHIFT,
        );
        row.lanes[1] = ArithmeticLane::centered(
            i64::from(trace.q_projection[token][1]),
            i64::from(tensor::llama_tiny::ROPE_COS[token][1]),
            i64::from(trace.q_projection[token][0]),
            i64::from(tensor::llama_tiny::ROPE_SIN[token][1]),
            tensor::llama_tiny::Q16_SHIFT,
        );
    }
    for token in 0..2 {
        let row = &mut rows[18 + token];
        let resident = section.matrices[1].resident.unwrap();
        for dim in 0..2 {
            let cell = token * 2 + dim;
            row.reads[dim] = Some(resident_output(resident, cell));
            row.claims[dim] = Some(ClaimCell {
                resident,
                logical_row: cell as u32,
                value: resident.output[cell],
            });
            row.writes[dim] = Some(resident_rhs(
                section.matrices[3].resident.unwrap(),
                dim * 2 + token,
                trace.k_rope[token][dim],
            ));
        }
        row.lanes[0] = ArithmeticLane::centered(
            i64::from(trace.k_projection[token][0]),
            i64::from(tensor::llama_tiny::ROPE_COS[token][0]),
            -i64::from(trace.k_projection[token][1]),
            i64::from(tensor::llama_tiny::ROPE_SIN[token][0]),
            tensor::llama_tiny::Q16_SHIFT,
        );
        row.lanes[1] = ArithmeticLane::centered(
            i64::from(trace.k_projection[token][1]),
            i64::from(tensor::llama_tiny::ROPE_COS[token][1]),
            i64::from(trace.k_projection[token][0]),
            i64::from(tensor::llama_tiny::ROPE_SIN[token][1]),
            tensor::llama_tiny::Q16_SHIFT,
        );
    }
    for cell in 0..4 {
        let resident = section.matrices[2].resident.unwrap();
        let value = trace.v[cell / 2][cell % 2];
        let row = &mut rows[20 + cell];
        row.reads[0] = Some(resident_output(resident, cell));
        row.claims[0] = Some(ClaimCell {
            resident,
            logical_row: cell as u32,
            value: resident.output[cell],
        });
        row.lanes[0] = ArithmeticLane::centered(
            i64::from(resident.output[cell]),
            1,
            0,
            0,
            tensor::llama_tiny::Q16_SHIFT,
        );
        row.writes[0] = Some(resident_rhs(
            section.matrices[4].resident.unwrap(),
            cell,
            value,
        ));
    }
    for score in 0..4 {
        let resident = section.matrices[3].resident.unwrap();
        let row = &mut rows[24 + score];
        row.reads[0] = Some(resident_output(resident, score));
        row.claims[0] = Some(ClaimCell {
            resident,
            logical_row: score as u32,
            value: resident.output[score],
        });
        row.limbs = tensor::llama_tiny::SOFTMAX_DIGITS[score / 2][score % 2];
        // The shifted magnitude can exceed i64::MAX.  It is represented only
        // by the five base-2^16 limbs and the AIR sign/decomposition equation.
        row.value = 0;
    }
    for score in 0..4 {
        for step in 0..3 {
            let ordinal = 28 + score * 3 + step;
            let digits = tensor::llama_tiny::SOFTMAX_DIGITS[score / 2][score % 2];
            rows[ordinal].limbs = match step {
                0 => digits,
                1 => [digits[2], digits[3], digits[4], 0, 0],
                2 => [digits[4], 0, 0, 0, 0],
                _ => unreachable!(),
            };
            let first = step * 2;
            for port in 0..2 {
                let digit = first + port;
                if digit < 5 {
                    rows[ordinal].writes[port] = Some(semantic_cell(
                        &identity,
                        10 + digit as u32,
                        score,
                        i32::from(tensor::llama_tiny::SOFTMAX_DIGITS[score / 2][score % 2][digit]),
                    ));
                }
            }
        }
    }
    for score in 0..4 {
        let digits = tensor::llama_tiny::SOFTMAX_DIGITS[score / 2][score % 2];
        for digit in 0..3 {
            rows[40 + score].reads[digit] = Some(semantic_cell(
                &identity,
                10 + digit as u32,
                score,
                i32::from(digits[digit]),
            ));
            rows[40 + score].lookup_inputs[digit] = u64::from(digits[digit]);
        }
        rows[44 + score].reads[0] = Some(semantic_cell(&identity, 13, score, i32::from(digits[3])));
        rows[44 + score].lookup_inputs[3] = u64::from(digits[3]);
        rows[44 + score].lookup_output = SoftmaxExp3Rom::output(digits[3]) as i64;
        rows[44 + score].writes[0] = Some(semantic_cell(
            &identity,
            15,
            score,
            rows[44 + score].lookup_output as i32,
        ));
        rows[48 + score].reads[0] = Some(semantic_cell(&identity, 14, score, i32::from(digits[4])));
        rows[48 + score].lookup_inputs[4] = u64::from(digits[4]);
        rows[48 + score].lookup_output = SoftmaxExp4Rom::output(digits[4]) as i64;
        rows[48 + score].writes[0] = Some(semantic_cell(
            &identity,
            16,
            score,
            rows[48 + score].lookup_output as i32,
        ));
        rows[52 + score].reads[0] = rows[44 + score].writes[0];
        rows[52 + score].reads[1] = rows[48 + score].writes[0];
        let low_product = 1024_i64.pow(3);
        rows[52 + score].lanes[0] =
            ArithmeticLane::exact(low_product, rows[44 + score].lookup_output, 0, 0);
        rows[52 + score].lanes[1] = ArithmeticLane::exact(
            rows[52 + score].lanes[0].result,
            rows[48 + score].lookup_output,
            0,
            0,
        );
        let product = rows[52 + score].lanes[1].result;
        rows[52 + score].writes[0] = Some(semantic_cell(&identity, 17, score, product));
    }
    for query in 0..2 {
        let first = rows[52 + query * 2].writes[0].unwrap();
        let second = rows[52 + query * 2 + 1].writes[0].unwrap();
        let masked = [first.value, if query == 0 { 0 } else { second.value }];
        let sum = masked[0] + masked[1];
        let masked_writes = {
            let row = &mut rows[56 + query];
            row.reads[0] = Some(first);
            row.reads[1] = Some(second);
            row.writes[0] = Some(semantic_cell(&identity, 18, query * 2, masked[0]));
            row.writes[1] = Some(semantic_cell(&identity, 18, query * 2 + 1, masked[1]));
            row.writes[2] = Some(semantic_cell(&identity, 19, query, sum));
            row.lanes[0] = ArithmeticLane::exact(i64::from(masked[0]), 1, i64::from(masked[1]), 1);
            row.writes
        };
        let norm = &mut rows[58 + query];
        norm.reads = masked_writes;
        for key in 0..2 {
            norm.writes[key] = Some(semantic_cell(
                &identity,
                20,
                query * 2 + key,
                trace.probabilities[query][key],
            ));
            norm.lanes[key] = ArithmeticLane::normalization(
                i64::from(masked[key]),
                i64::from(sum),
                i64::from(trace.probabilities[query][key]),
            );
        }
    }
    for cell in 0..4 {
        rows[60 + cell].reads[0] = Some(semantic_cell(
            &identity,
            20,
            cell,
            trace.probabilities[cell / 2][cell % 2],
        ));
        rows[60 + cell].writes[0] = Some(resident_input(
            section.matrices[4].resident.unwrap(),
            cell,
            trace.probabilities[cell / 2][cell % 2],
        ));
    }
    for cell in 0..4 {
        let resident = section.matrices[4].resident.unwrap();
        let value = trace.attention[cell / 2][cell % 2];
        rows[64 + cell].reads[0] = Some(resident_output(resident, cell));
        rows[64 + cell].claims[0] = Some(ClaimCell {
            resident,
            logical_row: cell as u32,
            value: resident.output[cell],
        });
        rows[64 + cell].lanes[0] = ArithmeticLane::centered(
            i64::from(resident.output[cell]),
            1,
            0,
            0,
            tensor::llama_tiny::Q20_SHIFT,
        );
        rows[64 + cell].writes[0] = Some(resident_input(
            section.matrices[5].resident.unwrap(),
            cell,
            value,
        ));
    }
    for cell in 0..4 {
        let resident = section.matrices[5].resident.unwrap();
        rows[68 + cell].reads[0] = Some(resident_output(resident, cell));
        rows[68 + cell].claims[0] = Some(ClaimCell {
            resident,
            logical_row: cell as u32,
            value: resident.output[cell],
        });
        rows[68 + cell].lanes[0] = ArithmeticLane::centered(
            i64::from(resident.output[cell]),
            1,
            0,
            0,
            tensor::llama_tiny::Q16_SHIFT,
        );
        rows[68 + cell].writes[0] = Some(semantic_cell(
            &identity,
            21,
            cell,
            trace.attention_projection[cell / 2][cell % 2],
        ));
        rows[72 + cell].reads[0] = Some(semantic_cell(
            &identity,
            2,
            cell,
            tensor::llama_tiny::INPUT[cell / 2][cell % 2],
        ));
        rows[72 + cell].reads[1] = rows[68 + cell].writes[0];
        rows[72 + cell].lanes[0] = ArithmeticLane::exact(
            i64::from(tensor::llama_tiny::INPUT[cell / 2][cell % 2]),
            1,
            i64::from(trace.attention_projection[cell / 2][cell % 2]),
            1,
        );
        rows[72 + cell].writes[0] = Some(TensorCell {
            id: section.attention_tensor_id,
            version: section.attention_version,
            index: cell as u32,
            value: i64::from(trace.attention_residual[cell / 2][cell % 2]),
        });
    }
    for cell in 0..4 {
        let token = cell / 2;
        let col = cell % 2;
        let value = trace.attention_residual[token][col];
        rows[76 + cell].reads[0] = Some(TensorCell {
            id: section.attention_tensor_id,
            version: section.attention_version,
            index: cell as u32,
            value: i64::from(value),
        });
        rows[76 + cell].writes[0] = Some(semantic_cell(&identity, 22, cell, value));
        rows[76 + cell].writes[1] = Some(semantic_cell(&identity, 23, cell, value));
        rows[76 + cell].lanes[0] = ArithmeticLane::exact(i64::from(value), i64::from(value), 0, 0);
        if col == 1 {
            rows[76 + cell].writes[2] = Some(semantic_cell(
                &identity,
                24,
                token,
                trace.post_energy[token],
            ));
            rows[76 + cell].lanes[1] = ArithmeticLane::exact(
                i64::from(trace.attention_residual[token][0]),
                i64::from(trace.attention_residual[token][0]),
                i64::from(value),
                i64::from(value),
            );
        }
    }
    for token in 0..2 {
        rows[80 + token].reads[0] = Some(semantic_cell(
            &identity,
            24,
            token,
            trace.post_energy[token],
        ));
        rows[80 + token].writes[0] = Some(semantic_cell(
            &identity,
            25,
            token,
            tensor::llama_tiny::POST_INV_RMS[token],
        ));
        rows[80 + token].lookup_inputs[0] = trace.post_energy[token] as u64;
        rows[80 + token].lookup_output = i64::from(tensor::llama_tiny::POST_INV_RMS[token]);
        rows[82 + token].reads[0] = rows[80 + token].writes[0];
        for dim in 0..2 {
            rows[82 + token].writes[dim] = Some(semantic_cell(
                &identity,
                26,
                token * 2 + dim,
                tensor::llama_tiny::POST_INV_RMS[token],
            ));
        }
    }
    for cell in 0..4 {
        let token = cell / 2;
        let col = cell % 2;
        let inv = tensor::llama_tiny::POST_INV_RMS[token];
        let value = trace.attention_residual[token][col];
        let weighted = ArithmeticLane::centered(
            i64::from(inv),
            i64::from(tensor::llama_tiny::POST_NORM_WEIGHT[col]),
            0,
            0,
            tensor::llama_tiny::Q16_SHIFT,
        );
        rows[84 + cell].reads[0] = Some(semantic_cell(&identity, 22, cell, value));
        rows[84 + cell].reads[1] = Some(semantic_cell(&identity, 26, cell, inv));
        rows[84 + cell].lanes[0] = weighted;
        rows[84 + cell].lanes[1] = ArithmeticLane::centered(
            weighted.result,
            i64::from(value),
            0,
            0,
            tensor::llama_tiny::Q16_SHIFT,
        );
        rows[84 + cell].writes[0] = Some(semantic_cell(
            &identity,
            27,
            cell,
            trace.post_norm[token][col],
        ));
        rows[88 + cell].reads[0] = rows[84 + cell].writes[0];
        rows[88 + cell].writes[0] = Some(resident_input(
            section.matrices[6].resident.unwrap(),
            cell,
            trace.post_norm[token][col],
        ));
        rows[88 + cell].writes[1] = Some(resident_input(
            section.matrices[7].resident.unwrap(),
            cell,
            trace.post_norm[token][col],
        ));
    }
    for cell in 0..4 {
        for (base, matrix_index, shift, domain, output) in [
            (
                92,
                6,
                tensor::llama_tiny::Q20_SHIFT,
                28,
                trace.gate[cell / 2][cell % 2],
            ),
            (
                96,
                7,
                tensor::llama_tiny::Q16_SHIFT,
                29,
                trace.up[cell / 2][cell % 2],
            ),
        ] {
            let resident = section.matrices[matrix_index].resident.unwrap();
            rows[base + cell].reads[0] = Some(resident_output(resident, cell));
            rows[base + cell].claims[0] = Some(ClaimCell {
                resident,
                logical_row: cell as u32,
                value: resident.output[cell],
            });
            rows[base + cell].lanes[0] =
                ArithmeticLane::centered(i64::from(resident.output[cell]), 1, 0, 0, shift);
            rows[base + cell].writes[0] = Some(semantic_cell(&identity, domain, cell, output));
        }
        rows[100 + cell].reads[0] = Some(semantic_cell(
            &identity,
            28,
            cell,
            trace.gate[cell / 2][cell % 2],
        ));
        rows[100 + cell].lookup_inputs[0] = u64::from(trace.gate[cell / 2][cell % 2] as i16 as u16);
        rows[100 + cell].lookup_output = i64::from(trace.swiglu[cell / 2][cell % 2]);
        rows[100 + cell].writes[0] = Some(semantic_cell(
            &identity,
            30,
            cell,
            trace.swiglu[cell / 2][cell % 2],
        ));
        rows[104 + cell].reads[0] = rows[100 + cell].writes[0];
        rows[104 + cell].reads[1] = Some(semantic_cell(
            &identity,
            29,
            cell,
            trace.up[cell / 2][cell % 2],
        ));
        rows[104 + cell].lanes[0] = ArithmeticLane::centered(
            i64::from(trace.swiglu[cell / 2][cell % 2]),
            i64::from(trace.up[cell / 2][cell % 2]),
            0,
            0,
            tensor::llama_tiny::Q16_SHIFT,
        );
        rows[104 + cell].writes[0] = Some(resident_input(
            section.matrices[8].resident.unwrap(),
            cell,
            trace.down_input[cell / 2][cell % 2],
        ));
        let down = section.matrices[8].resident.unwrap();
        rows[108 + cell].reads[0] = Some(resident_output(down, cell));
        rows[108 + cell].reads[1] = Some(semantic_cell(
            &identity,
            23,
            cell,
            trace.attention_residual[cell / 2][cell % 2],
        ));
        rows[108 + cell].claims[0] = Some(ClaimCell {
            resident: down,
            logical_row: cell as u32,
            value: down.output[cell],
        });
        rows[108 + cell].lanes[0] = ArithmeticLane::centered(
            i64::from(down.output[cell]),
            1,
            0,
            0,
            tensor::llama_tiny::Q16_SHIFT,
        );
        rows[108 + cell].lanes[1] = ArithmeticLane::exact(
            rows[108 + cell].lanes[0].result,
            1,
            i64::from(trace.attention_residual[cell / 2][cell % 2]),
            1,
        );
        rows[108 + cell].writes[0] = Some(TensorCell {
            id: section.output_tensor_id,
            version: section.output_version,
            index: cell as u32,
            value: i64::from(trace.output[cell / 2][cell % 2]),
        });
    }
    rows[0].value = i64::from(trace.input_norm[0][0]);
    rows[111].value = i64::from(trace.swiglu[0][0]);
    rows
}

fn set_signed<F: PrimeCharacteristicRing>(row: &mut [F], column: WitIn, value: i64) {
    row[column.id as usize] = if value < 0 {
        -F::from_u64(value.unsigned_abs())
    } else {
        F::from_u64(value as u64)
    };
}

fn set_id<F: PrimeCharacteristicRing>(row: &mut [F], lo: WitIn, hi: WitIn, id: u64) {
    row[lo.id as usize] = F::from_u64(u64::from(id as u32));
    row[hi.id as usize] = F::from_u64(id >> 32);
}

fn semantic_family(ordinal: usize) -> usize {
    match ordinal {
        0..=3 | 6..=39 | 52..=75 => STATE_ATTENTION_LINEAR,
        4..=5 => STATE_ATTENTION_RMS,
        40..=43 => STATE_ATTENTION_LOW_DIGIT,
        44..=47 => STATE_ATTENTION_EXP3,
        48..=51 => STATE_ATTENTION_EXP4,
        76..=79 | 82..=99 | 104..=111 => STATE_FFN_LINEAR,
        80..=81 => STATE_FFN_RMS,
        100..=103 => STATE_FFN_SWIGLU,
        _ => panic!("llama-tiny semantic ordinal out of range: {ordinal}"),
    }
}

fn semantic_chip(ordinal: usize) -> usize {
    CHIP_ORDINALS
        .iter()
        .position(|ordinals| ordinals.contains(&ordinal))
        .unwrap_or_else(|| panic!("llama-tiny semantic ordinal has no chip: {ordinal}"))
}

impl<E: ExtensionField, const CHIP: usize> LlamaTinyCoreInstruction<E, CHIP> {
    pub fn assign_layer_sections(
        config: &LlamaTinyCoreConfig,
        num_witin: usize,
        num_structural_witin: usize,
        sections: &[LlamaTinyLayerSection],
    ) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
        let active_rows = CHIP_ROWS[CHIP];
        let rows = sections.len() * active_rows;
        let mut witness = RowMajorMatrix::new(rows, num_witin, InstancePaddingStrategy::Default);
        let mut structural =
            RowMajorMatrix::new(rows, num_structural_witin, InstancePaddingStrategy::Default);
        let mut lkm = LkMultiplicity::default();
        let schedules = sections.iter().map(semantic_schedule).collect::<Vec<_>>();
        for (physical, (row, structural_row)) in
            witness.iter_mut().zip(structural.iter_mut()).enumerate()
        {
            let section_index = physical / active_rows;
            let section = &sections[section_index];
            let schedule = &schedules[section_index];
            let semantic = &schedule[CHIP_ORDINALS[CHIP][physical % active_rows]];
            let ordinal = semantic.ordinal;
            if num_structural_witin > 0 {
                *structural_row.last_mut().unwrap() = E::BaseField::ONE;
            }
            set_val!(row, config.active, 1);
            set_val!(row, config.import_cycle, section.import_cycle);
            let attention = ordinal < LLAMA_TINY_ATTENTION_ROWS;
            let next_attention = ordinal + 1 < LLAMA_TINY_ATTENTION_ROWS;
            set_val!(
                row,
                config.call_cycle,
                if attention {
                    section.attention_cycle
                } else {
                    section.ffn_cycle
                }
            );
            set_val!(
                row,
                config.next_call_cycle,
                if next_attention {
                    section.attention_cycle
                } else {
                    section.ffn_cycle
                }
            );
            let current_input = if attention {
                (section.input_tensor_id, section.input_version)
            } else {
                (section.attention_tensor_id, section.attention_version)
            };
            let current_output = if attention {
                (section.attention_tensor_id, section.attention_version)
            } else {
                (section.output_tensor_id, section.output_version)
            };
            let next_input = if next_attention {
                (section.input_tensor_id, section.input_version)
            } else {
                (section.attention_tensor_id, section.attention_version)
            };
            let next_output = if next_attention {
                (section.attention_tensor_id, section.attention_version)
            } else {
                (section.output_tensor_id, section.output_version)
            };
            set_id(row, config.input_id_lo, config.input_id_hi, current_input.0);
            set_val!(row, config.input_version, u64::from(current_input.1));
            set_id(
                row,
                config.output_id_lo,
                config.output_id_hi,
                current_output.0,
            );
            set_val!(row, config.output_version, u64::from(current_output.1));
            set_id(
                row,
                config.next_input_id_lo,
                config.next_input_id_hi,
                next_input.0,
            );
            set_val!(row, config.next_input_version, u64::from(next_input.1));
            set_id(
                row,
                config.next_output_id_lo,
                config.next_output_id_hi,
                next_output.0,
            );
            set_val!(row, config.next_output_version, u64::from(next_output.1));
            set_val!(row, config.family, semantic.family as u64);
            set_val!(row, config.stage, semantic.stage as u64);
            set_val!(row, config.op, semantic.op as u64);
            for (bit, column) in config.ordinal_bits.iter().enumerate() {
                set_val!(row, *column, ((ordinal >> bit) & 1) as u64);
            }
            let (local_stage, local_base, local_stride) = CHIP_STAGES[CHIP]
                .iter()
                .enumerate()
                .find_map(|(stage, &(base, stride, len))| {
                    (0..len)
                        .find(|local| base + stride * local == ordinal)
                        .map(|_| (stage, base, stride))
                })
                .expect("chip ordinal belongs to a local stage");
            for (stage, selector) in config.stage_selectors.iter().enumerate() {
                set_val!(row, *selector, u64::from(stage == local_stage));
            }
            for (bit, column) in config.local_index_bits.iter().enumerate() {
                let local_index = (ordinal - local_base) / local_stride;
                set_val!(row, *column, ((local_index >> bit) & 1) as u64);
            }
            set_signed(row, config.accumulator, semantic.value);
            set_signed(row, config.value, semantic.value);
            for (column, limb) in config.limbs.iter().zip(semantic.limbs) {
                set_val!(row, *column, u64::from(limb));
            }

            let (next_family, next_stage, next_op, next_value, next_limbs) =
                if let Some(next) = schedule.get(ordinal + 1) {
                    (next.family, next.stage, next.op, next.value, next.limbs)
                } else {
                    (
                        STATE_FFN_SWIGLU,
                        STATE_FFN_SWIGLU,
                        LLAMA_TINY_TOTAL_ROWS,
                        i64::from(section.trace.swiglu[0][0]),
                        [0; 5],
                    )
                };
            for (bit, column) in config.next_ordinal_bits.iter().enumerate() {
                set_val!(row, *column, (((ordinal + 1) >> bit) & 1) as u64);
            }
            set_val!(row, config.next_family, next_family as u64);
            set_val!(row, config.next_stage, next_stage as u64);
            set_val!(row, config.next_op, next_op as u64);
            set_signed(row, config.next_accumulator, next_value);
            set_signed(row, config.next_value, next_value);
            for (column, limb) in config.next_limbs.iter().zip(next_limbs) {
                set_val!(row, *column, u64::from(limb));
            }

            for (lane_index, (lane, lane_config)) in
                semantic.lanes.iter().zip(config.lanes.iter()).enumerate()
            {
                set_val!(row, lane_config.enabled, u64::from(lane.enabled));
                set_val!(row, lane_config.rescale, u64::from(lane.rescale));
                set_val!(row, lane_config.q20, u64::from(lane.q20));
                set_val!(row, lane_config.normalize, u64::from(lane.normalize));
                for (column, operand) in lane_config.operands.iter().zip(lane.operands) {
                    set_signed(row, *column, operand);
                }
                set_signed(row, lane_config.result, lane.result);
                set_signed(row, lane_config.quotient, lane.quotient);
                set_val!(row, lane_config.remainder, u64::from(lane.remainder));
                for (bit, column) in config.remainder_bits[lane_index].iter().enumerate() {
                    set_val!(row, *column, u64::from((lane.remainder >> bit) & 1));
                }
            }

            let assign_cell = |row: &mut [E::BaseField], cell: TensorCell, columns: [WitIn; 6]| {
                set_val!(row, columns[0], 1);
                set_id(row, columns[1], columns[2], cell.id);
                set_val!(row, columns[3], u64::from(cell.version));
                set_val!(row, columns[4], u64::from(cell.index));
                set_signed(row, columns[5], i64::from(cell.value));
            };
            let read_columns = [
                [
                    config.tensor_read_enabled,
                    config.tensor_read_id_lo,
                    config.tensor_read_id_hi,
                    config.tensor_read_version,
                    config.tensor_read_index,
                    config.tensor_read_value,
                ],
                [
                    config.tensor_read2_enabled,
                    config.tensor_read2_id_lo,
                    config.tensor_read2_id_hi,
                    config.tensor_read2_version,
                    config.tensor_read2_index,
                    config.tensor_read2_value,
                ],
                [
                    config.tensor_read3_enabled,
                    config.tensor_read3_id_lo,
                    config.tensor_read3_id_hi,
                    config.tensor_read3_version,
                    config.tensor_read3_index,
                    config.tensor_read3_value,
                ],
            ];
            let write_columns = [
                [
                    config.tensor_write_enabled,
                    config.tensor_write_id_lo,
                    config.tensor_write_id_hi,
                    config.tensor_write_version,
                    config.tensor_write_index,
                    config.tensor_write_value,
                ],
                [
                    config.tensor_write2_enabled,
                    config.tensor_write2_id_lo,
                    config.tensor_write2_id_hi,
                    config.tensor_write2_version,
                    config.tensor_write2_index,
                    config.tensor_write2_value,
                ],
                [
                    config.tensor_write3_enabled,
                    config.tensor_write3_id_lo,
                    config.tensor_write3_id_hi,
                    config.tensor_write3_version,
                    config.tensor_write3_index,
                    config.tensor_write3_value,
                ],
            ];
            for (cell, columns) in semantic.reads.iter().zip(read_columns) {
                if let Some(cell) = cell {
                    assign_cell(row, *cell, columns);
                }
            }
            for (cell, columns) in semantic.writes.iter().zip(write_columns) {
                if let Some(cell) = cell {
                    assign_cell(row, *cell, columns);
                }
            }
            for (claim_index, claim) in semantic.claims.iter().enumerate() {
                if let Some(claim) = claim {
                    let port = config.claims[claim_index];
                    set_val!(row, port.enabled, 1);
                    set_val!(
                        row,
                        port.cycle,
                        if claim.resident.hint.role <= tensor::TENSOR_HINT_ROLE_O {
                            section.attention_cycle
                        } else {
                            section.ffn_cycle
                        }
                    );
                    set_id(
                        row,
                        port.input_id_lo,
                        port.input_id_hi,
                        claim.resident.input_tensor_id,
                    );
                    set_val!(
                        row,
                        port.input_version,
                        u64::from(claim.resident.input_version)
                    );
                    set_id(
                        row,
                        port.output_id_lo,
                        port.output_id_hi,
                        claim.resident.output_tensor_id,
                    );
                    set_val!(
                        row,
                        port.output_version,
                        u64::from(claim.resident.output_version)
                    );
                    set_val!(row, port.role, u64::from(claim.resident.hint.role));
                    set_val!(row, port.row, u64::from(claim.logical_row));
                    set_signed(row, port.value, i64::from(claim.value));
                }
            }
            for (index, (column, input)) in config
                .lookup_inputs
                .iter()
                .zip(semantic.lookup_inputs)
                .enumerate()
            {
                if CHIP == CHIP_SWIGLU_LOOKUP && index == 0 {
                    set_signed(row, *column, i64::from(input as u16 as i16));
                } else {
                    set_val!(row, *column, input);
                }
            }
            set_signed(row, config.lookup_output, semantic.lookup_output);
            match CHIP {
                CHIP_RMS_LOOKUP => {
                    lkm.increment(LookupTable::LlamaRmsInv, semantic.lookup_inputs[0]);
                }
                CHIP_SOFTMAX_LOW_DIGIT => {
                    for input in &semantic.lookup_inputs[..3] {
                        lkm.assert_dynamic_range(*input, 16);
                    }
                }
                CHIP_SOFTMAX_EXP3 => {
                    lkm.increment(LookupTable::LlamaSoftmaxExp3, semantic.lookup_inputs[3]);
                }
                CHIP_SOFTMAX_EXP4 => {
                    lkm.increment(LookupTable::LlamaSoftmaxExp4, semantic.lookup_inputs[4]);
                }
                CHIP_SWIGLU_LOOKUP => {
                    lkm.increment(LookupTable::LlamaSwiGlu, semantic.lookup_inputs[0]);
                }
                _ => {}
            }
        }
        witness.padding_by_strategy();
        structural.padding_by_strategy();
        Ok(([witness, structural], lkm.into_finalize_result()))
    }
}
pub fn audit_layer_graph(sections: &[LlamaTinyLayerSection]) -> Result<(), ZKVMError> {
    type TensorKey = (u64, u32, u32, i64);
    type ClaimKey = (u32, u32, i32);
    type HintKey = (u32, u32, u32, u32, u32, i32);
    type PrivateKey = (usize, usize, usize, usize, usize, usize, i64, [u16; 5]);

    for section in sections {
        if section.matrices.len() != 9 || section.hints.len() != 7 {
            return Err(invalid("llama-tiny matrix/HintRef cardinality drift"));
        }
        let matrix_roles = section
            .matrices
            .iter()
            .map(|matrix| matrix.resident.unwrap().hint.role)
            .collect::<Vec<_>>();
        if matrix_roles != MATRIX_ROLES {
            return Err(invalid("llama-tiny matrix role order drift"));
        }
        if !section
            .hints
            .iter()
            .zip(WEIGHT_ROLES)
            .all(|((hint, _), role)| hint.role == role)
        {
            return Err(invalid("llama-tiny HintRef role order drift"));
        }

        let schedule = semantic_schedule(section);
        if schedule.len() != LLAMA_TINY_TOTAL_ROWS {
            return Err(invalid(format!(
                "llama-tiny semantic schedule length actual={} expected={LLAMA_TINY_TOTAL_ROWS}",
                schedule.len()
            )));
        }
        for (ordinal, row) in schedule.iter().enumerate() {
            if row.ordinal != ordinal
                || row.family != semantic_family(ordinal)
                || row.stage != row.family
                || row.op != ordinal
            {
                return Err(invalid(format!(
                    "llama-tiny semantic identity drift ordinal={ordinal} row_ordinal={} family={} expected_family={} stage={} op={}",
                    row.ordinal,
                    row.family,
                    semantic_family(ordinal),
                    row.stage,
                    row.op,
                )));
            }
            for port in 0..3 {
                let read_actual = row.reads[port].is_some();
                let read_expected = semantic_read_enabled(ordinal, port);
                let read_index_actual = row.reads[port].map(|cell| cell.index as usize);
                let read_index_expected = semantic_read_index(ordinal, port);
                if read_actual != read_expected
                    || read_index_actual.is_some_and(|index| index != read_index_expected)
                {
                    return Err(invalid(format!(
                        "llama-tiny semantic read drift ordinal={ordinal} port={port} actual_enabled={read_actual} expected_enabled={read_expected} actual_index={read_index_actual:?} expected_index={read_index_expected}"
                    )));
                }
                let write_actual = row.writes[port].is_some();
                let write_expected = semantic_write_enabled(ordinal, port);
                let write_index_actual = row.writes[port].map(|cell| cell.index as usize);
                let write_index_expected = semantic_write_index(ordinal, port);
                if write_actual != write_expected
                    || write_index_actual.is_some_and(|index| index != write_index_expected)
                {
                    return Err(invalid(format!(
                        "llama-tiny semantic write drift ordinal={ordinal} port={port} actual_enabled={write_actual} expected_enabled={write_expected} actual_index={write_index_actual:?} expected_index={write_index_expected}"
                    )));
                }
            }
            for port in 0..2 {
                let claim_actual = row.claims[port].is_some();
                let claim_expected = semantic_claim_enabled(ordinal, port);
                if claim_actual != claim_expected {
                    return Err(invalid(format!(
                        "llama-tiny semantic claim drift ordinal={ordinal} port={port} actual_enabled={claim_actual} expected_enabled={claim_expected}"
                    )));
                }
                let lane = row.lanes[port];
                let expected_enabled = semantic_lane_enabled(ordinal, port);
                let expected_shift = semantic_lane_shift(ordinal, port);
                let expected_normalize = matches!(ordinal, 58..=59);
                if lane.enabled != expected_enabled
                    || lane.rescale != expected_shift.is_some()
                    || lane.q20 != (expected_shift == Some(tensor::llama_tiny::Q20_SHIFT))
                    || lane.normalize != expected_normalize
                {
                    return Err(invalid(format!(
                        "llama-tiny semantic lane drift ordinal={ordinal} port={port} actual=[enabled={},rescale={},q20={},normalize={}] expected=[enabled={expected_enabled},rescale={},q20={},normalize={expected_normalize}]",
                        lane.enabled,
                        lane.rescale,
                        lane.q20,
                        lane.normalize,
                        expected_shift.is_some(),
                        expected_shift == Some(tensor::llama_tiny::Q20_SHIFT),
                    )));
                }
            }
        }
        for chip in 0..CHIP_ROWS.len() {
            let owned = schedule
                .iter()
                .filter(|row| semantic_chip(row.ordinal) == chip)
                .map(|row| row.ordinal)
                .collect::<Vec<_>>();
            if owned != CHIP_ORDINALS[chip] || owned.len() != CHIP_ROWS[chip] {
                return Err(invalid(
                    "llama-tiny operation-chip ordinal projection drift",
                ));
            }
        }
        for score in 0..4 {
            let initial = schedule[24 + score].limbs;
            let first = 28 + score * 3;
            let magnitude = initial
                .iter()
                .enumerate()
                .map(|(index, limb)| u128::from(*limb) << (16 * index))
                .sum::<u128>();
            if magnitude != section.trace.shifted_magnitudes[score / 2][score % 2]
                || schedule[first].limbs != initial
                || schedule[first + 1].limbs != [initial[2], initial[3], initial[4], 0, 0]
                || schedule[first + 2].limbs != [initial[4], 0, 0, 0, 0]
            {
                return Err(invalid(
                    "llama-tiny softmax limb initialization/advancement drift",
                ));
            }
        }

        let mut tensor_ledger = BTreeMap::<TensorKey, [usize; 2]>::new();
        let mut tensor_ordinals = BTreeMap::<TensorKey, [Option<usize>; 2]>::new();
        let mut claims = BTreeMap::<ClaimKey, [usize; 2]>::new();
        let mut hints = BTreeMap::<HintKey, [usize; 2]>::new();
        let mut dynamic = BTreeMap::<u64, usize>::new();
        let mut rms = BTreeMap::<u64, usize>::new();
        let mut exp3 = BTreeMap::<u64, usize>::new();
        let mut exp4 = BTreeMap::<u64, usize>::new();
        let mut swiglu = BTreeMap::<u64, usize>::new();
        let mut private = BTreeMap::<PrivateKey, [usize; 2]>::new();

        let mut traffic = |cell: TensorCell, side: usize, ordinal: Option<usize>| {
            let key = (cell.id, cell.version, cell.index, cell.value);
            tensor_ledger.entry(key).or_default()[side] += 1;
            tensor_ordinals.entry(key).or_default()[side] = ordinal;
        };
        for (hint, values) in &section.hints {
            for (index, value) in values.iter().flatten().copied().enumerate() {
                hints
                    .entry((
                        hint.profile,
                        hint.layer,
                        hint.role,
                        hint.tile_index,
                        index as u32,
                        value,
                    ))
                    .or_default()[0] += 1;
            }
        }
        for (index, value) in tensor::llama_tiny::INPUT
            .iter()
            .flatten()
            .copied()
            .enumerate()
        {
            traffic(
                TensorCell {
                    id: section.input_tensor_id,
                    version: section.input_version,
                    index: index as u32,
                    value: i64::from(value),
                },
                0,
                None,
            );
        }
        for row in &schedule {
            for cell in row.reads.iter().flatten() {
                traffic(*cell, 1, Some(row.ordinal));
            }
            for cell in row.writes.iter().flatten() {
                traffic(*cell, 0, Some(row.ordinal));
            }
            for claim in row.claims.iter().flatten() {
                claims
                    .entry((claim.resident.hint.role, claim.logical_row, claim.value))
                    .or_default()[0] += 1;
            }
            let current = (
                row.ordinal,
                row.family,
                row.stage,
                row.op,
                row.coordinate_row,
                row.coordinate_col,
                row.value,
                row.limbs,
            );
            private.entry(current).or_default()[1] += 1;
            let (family, stage, op, coordinate_row, coordinate_col, value, limbs) =
                if let Some(next) = schedule.get(row.ordinal + 1) {
                    (
                        next.family,
                        next.stage,
                        next.op,
                        next.coordinate_row,
                        next.coordinate_col,
                        next.value,
                        next.limbs,
                    )
                } else {
                    (
                        STATE_FFN_SWIGLU,
                        STATE_FFN_SWIGLU,
                        LLAMA_TINY_TOTAL_ROWS,
                        LLAMA_TINY_TOTAL_ROWS / 2,
                        0,
                        i64::from(section.trace.swiglu[0][0]),
                        [0; 5],
                    )
                };
            private
                .entry((
                    row.ordinal + 1,
                    family,
                    stage,
                    op,
                    coordinate_row,
                    coordinate_col,
                    value,
                    limbs,
                ))
                .or_default()[0] += 1;

            match row.family {
                STATE_ATTENTION_RMS | STATE_FFN_RMS => {
                    *rms.entry(row.lookup_inputs[0]).or_default() += 1;
                }
                STATE_ATTENTION_LOW_DIGIT => {
                    for key in &row.lookup_inputs[..3] {
                        *dynamic.entry(65_536 + *key).or_default() += 1;
                    }
                }
                STATE_ATTENTION_EXP3 => {
                    *exp3.entry(row.lookup_inputs[3]).or_default() += 1;
                }
                STATE_ATTENTION_EXP4 => {
                    *exp4.entry(row.lookup_inputs[4]).or_default() += 1;
                }
                STATE_FFN_SWIGLU => {
                    *swiglu.entry(row.lookup_inputs[0]).or_default() += 1;
                }
                _ => {}
            }
        }
        private
            .entry((
                0,
                STATE_ATTENTION_LINEAR,
                STATE_ATTENTION_LINEAR,
                0,
                0,
                0,
                i64::from(section.trace.input_norm[0][0]),
                [0; 5],
            ))
            .or_default()[0] += 1;
        private
            .entry((
                LLAMA_TINY_TOTAL_ROWS,
                STATE_FFN_SWIGLU,
                STATE_FFN_SWIGLU,
                LLAMA_TINY_TOTAL_ROWS,
                LLAMA_TINY_TOTAL_ROWS / 2,
                0,
                i64::from(section.trace.swiglu[0][0]),
                [0; 5],
            ))
            .or_default()[1] += 1;

        for matrix in &section.matrices {
            let resident = matrix.resident.unwrap();
            if !matches!(
                resident.hint.role,
                tensor::TENSOR_HINT_ROLE_QK | tensor::TENSOR_HINT_ROLE_PV
            ) {
                for (index, value) in matrix.w.iter().flatten().copied().enumerate() {
                    hints
                        .entry((
                            resident.hint.profile,
                            resident.hint.layer,
                            resident.hint.role,
                            resident.hint.tile_index,
                            index as u32,
                            value,
                        ))
                        .or_default()[1] += 1;
                }
            }
            for (index, value) in resident.input.into_iter().enumerate() {
                traffic(resident_input(resident, index, value), 1, None);
            }
            for index in 0..4 {
                traffic(resident_output(resident, index), 0, None);
                claims
                    .entry((resident.hint.role, index as u32, resident.output[index]))
                    .or_default()[1] += 1;
            }
            if let (Some(rhs_id), Some(rhs_version)) =
                (resident.rhs_tensor_id, resident.rhs_tensor_version)
            {
                let expected = match resident.hint.role {
                    tensor::TENSOR_HINT_ROLE_QK => [
                        section.trace.k_rope[0][0],
                        section.trace.k_rope[1][0],
                        section.trace.k_rope[0][1],
                        section.trace.k_rope[1][1],
                    ],
                    tensor::TENSOR_HINT_ROLE_PV => flatten(section.trace.v),
                    _ => return Err(invalid("unexpected llama-tiny RHS role")),
                };
                for (index, value) in expected.into_iter().enumerate() {
                    traffic(
                        TensorCell {
                            id: rhs_id,
                            version: rhs_version,
                            index: index as u32,
                            value: i64::from(value),
                        },
                        1,
                        None,
                    );
                }
                if resident.hint.role == tensor::TENSOR_HINT_ROLE_QK
                    && resident.matrix.w
                        != [
                            [section.trace.k_rope[0][0], section.trace.k_rope[1][0]],
                            [section.trace.k_rope[0][1], section.trace.k_rope[1][1]],
                        ]
                {
                    return Err(invalid("llama-tiny QK RHS transpose drift"));
                }
                if resident.hint.role == tensor::TENSOR_HINT_ROLE_PV
                    && resident.matrix.w != section.trace.v
                {
                    return Err(invalid("llama-tiny PV RHS order drift"));
                }
            }
        }
        for (index, value) in section.trace.output.iter().flatten().copied().enumerate() {
            traffic(
                TensorCell {
                    id: section.output_tensor_id,
                    version: section.output_version,
                    index: index as u32,
                    value: i64::from(value),
                },
                1,
                None,
            );
        }

        if tensor_ledger.values().any(|count| *count != [1, 1]) {
            return Err(invalid("llama-tiny emitted Tensor ledger drift"));
        }
        if tensor_ordinals.values().any(
            |ordinals| matches!(ordinals, [Some(producer), Some(consumer)] if producer >= consumer),
        ) {
            return Err(invalid("llama-tiny Tensor producer is not before consumer"));
        }
        if claims.len() != 36 || claims.values().any(|count| *count != [1, 1]) {
            return Err(invalid("llama-tiny emitted claim ledger drift"));
        }
        if hints.len() != 28 || hints.values().any(|count| *count != [1, 1]) {
            return Err(invalid("llama-tiny exact emitted HintRef W/R ledger drift"));
        }
        if dynamic
            != BTreeMap::from([
                (65_536, 8),
                (116_192, 1),
                (66_923, 1),
                (66_493, 1),
                (69_262, 1),
            ])
            || rms != BTreeMap::from([(20_480, 2), (41_905, 1), (36_970, 1)])
            || exp3 != BTreeMap::from([(0, 2), (64_254, 2)])
            || exp4 != BTreeMap::from([(0, 4)])
            || swiglu != BTreeMap::from([(19, 1), (65_522, 1), (16, 1), (7, 1)])
        {
            return Err(invalid("llama-tiny emitted lookup multiplicity drift"));
        }
        if private.len() != LLAMA_TINY_TOTAL_ROWS + 1
            || private.values().any(|count| *count != [1, 1])
        {
            return Err(invalid("llama-tiny complete private tuple ledger drift"));
        }
    }
    Ok(())
}
