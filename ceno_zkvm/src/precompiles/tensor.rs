//! Structural boundary record for split tensor ecalls.
//!
//! Both sides construct this exact record. Private weight words deliberately
//! appear only in the core input record and never in the syscall journal.

use ff_ext::{ExtensionField, FieldInto};
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::{Field, PrimeCharacteristicRing};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    structs::{CustomRWTag, RAMType},
    witness::{LkMultiplicity, set_val},
};

use ceno_emul::tensor::{
    GATE2_LINEAR_COMMITMENT_V1, TensorWitnessProvider, decode_i32_le, gate2_linear_commitment_v1,
    matmul_rescaled_i32,
};

pub const TENSOR_STATE_PHASE_INPUT: u64 = 0;
pub const TENSOR_STATE_PHASE_OUTPUT: u64 = 1;
pub const TENSOR_GATE2_WEIGHTS: usize = 6;
pub const TENSOR_GATE2_OUTPUTS: usize = 4;
pub const TENSOR_GATE2_SHIFT: u32 = 16;
pub const RMS_INV_LOOKUP_V1: u32 = 1;
pub const RMS_INV_TABLE_REDUCED_V1: u32 = 0x524d_5301;
pub const SWIGLU_LOOKUP_V1: u32 = 2;
pub const SWIGLU_TABLE_REDUCED_V1: u32 = 0x5357_4701;
pub const ROPE_LOOKUP_Q16_REDUCED_V1: u32 = 3;
pub const ROPE_TABLE_REDUCED_V1: u32 = 0x524f_5001;
pub const RESIDUAL_LOOKUP_PACKED_REDUCED_V1: u32 = 4;
pub const RESIDUAL_TABLE_REDUCED_V1: u32 = 0x5245_5301;
pub const RMS_STATE_VERSION_V1: u32 = 1;
pub const RMS_STATE_PHASE_INPUT: u64 = 0;
pub const RMS_STATE_PHASE_OUTPUT: u64 = 1;
pub const RMS_REDUCED_ENTRIES: [(i32, i32); 10] = [
    (-10, -10),
    (-7, -7),
    (-4, -4),
    (-2, -2),
    (0, 0),
    (1, 1),
    (2, 2),
    (3, 3),
    (5, 5),
    (7, 7),
];
pub const RESIDUAL_REDUCED_ENTRIES: [(i32, i32); 12] = [
    (561, 2),
    (462, -4),
    (626, 5),
    (397, -7),
    (592, 2),
    (400, -4),
    (688, 5),
    (304, -7),
    (628, 7),
    (394, -10),
    (752, 7),
    (208, -10),
];
const LIMB_BASE: u64 = 1 << 16;

/// A compile-time fixed nonlinear table selected by constrained one-hot bits.
/// This intentionally does not accept witness-provided table rows.
#[derive(Debug)]
pub struct TensorFixedLookupConfig<E: ExtensionField> {
    pub profile: WitIn,
    pub table_id: WitIn,
    pub input: TensorSignedWord<E>,
    pub output: TensorSignedWord<E>,
    selectors: Vec<WitIn>,
    entries: Vec<(u32, u32, i32, i32)>,
}

impl<E: ExtensionField> TensorFixedLookupConfig<E> {
    pub fn construct_rms_inverse_v1(
        cb: &mut CircuitBuilder<E>,
        entries: &[(i32, i32)],
    ) -> Result<Self, ZKVMError> {
        Self::construct(
            cb,
            "rms_inverse_v1",
            RMS_INV_LOOKUP_V1,
            RMS_INV_TABLE_REDUCED_V1,
            18,
            18,
            entries,
        )
    }

    pub fn construct_swiglu_v1(
        cb: &mut CircuitBuilder<E>,
        entries: &[(i32, i32)],
    ) -> Result<Self, ZKVMError> {
        Self::construct(
            cb,
            "swiglu_v1",
            SWIGLU_LOOKUP_V1,
            SWIGLU_TABLE_REDUCED_V1,
            18,
            18,
            entries,
        )
    }

    pub fn construct(
        cb: &mut CircuitBuilder<E>,
        name: &str,
        profile_value: u32,
        table_id_value: u32,
        input_bits: usize,
        output_bits: usize,
        entries: &[(i32, i32)],
    ) -> Result<Self, ZKVMError> {
        let entries = entries
            .iter()
            .map(|&(input, output)| (profile_value, table_id_value, input, output))
            .collect_vec();
        Self::construct_registered(cb, name, input_bits, output_bits, &entries)
    }

    pub fn construct_registered(
        cb: &mut CircuitBuilder<E>,
        name: &str,
        input_bits: usize,
        output_bits: usize,
        entries: &[(u32, u32, i32, i32)],
    ) -> Result<Self, ZKVMError> {
        assert!(!entries.is_empty(), "fixed lookup table must be nonempty");
        let profile = cb.create_witin(|| format!("{name}_profile"));
        let table_id = cb.create_witin(|| format!("{name}_table_id"));
        let input = TensorSignedWord::construct(cb, &format!("{name}_input"), input_bits)?;
        let output = TensorSignedWord::construct(cb, &format!("{name}_output"), output_bits)?;
        let selectors = (0..entries.len())
            .map(|index| {
                let selector = cb.create_witin(|| format!("{name}_selector_{index}"));
                cb.assert_bit(|| format!("{name}_selector_{index}_bit"), selector.expr())?;
                Ok(selector)
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;
        cb.require_equal(
            || format!("{name}_one_hot"),
            selectors
                .iter()
                .fold(E::BaseField::ZERO.expr(), |sum, selector| {
                    sum + selector.expr()
                }),
            E::BaseField::ONE.expr(),
        )?;
        cb.require_equal(
            || format!("{name}_profile_selected"),
            profile.expr(),
            selectors.iter().zip(entries).fold(
                E::BaseField::ZERO.expr(),
                |sum, (selector, (profile, _, _, _))| {
                    sum + selector.expr() * E::BaseField::from_u32(*profile).expr()
                },
            ),
        )?;
        cb.require_equal(
            || format!("{name}_table_selected"),
            table_id.expr(),
            selectors.iter().zip(entries).fold(
                E::BaseField::ZERO.expr(),
                |sum, (selector, (_, table, _, _))| {
                    sum + selector.expr() * E::BaseField::from_u32(*table).expr()
                },
            ),
        )?;
        cb.require_equal(
            || format!("{name}_input_selected"),
            input.expr(),
            selectors.iter().zip(entries).fold(
                E::BaseField::ZERO.expr(),
                |sum, (selector, (_, _, value, _))| {
                    sum + selector.expr() * E::BaseField::from_i64(i64::from(*value)).expr()
                },
            ),
        )?;
        cb.require_equal(
            || format!("{name}_output_selected"),
            output.expr(),
            selectors.iter().zip(entries).fold(
                E::BaseField::ZERO.expr(),
                |sum, (selector, (_, _, _, value))| {
                    sum + selector.expr() * E::BaseField::from_i64(i64::from(*value)).expr()
                },
            ),
        )?;
        Ok(Self {
            profile,
            table_id,
            input,
            output,
            selectors,
            entries: entries.to_vec(),
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        profile: u32,
        table_id: u32,
        input: i32,
    ) -> Result<i32, String> {
        let selected = self
            .entries
            .iter()
            .position(|&(candidate_profile, candidate_table, candidate, _)| {
                candidate_profile == profile && candidate_table == table_id && candidate == input
            })
            .ok_or_else(|| "fixed tensor lookup miss".to_string())?;
        let output = self.entries[selected].3;
        set_val!(instance, self.profile, profile as u64);
        set_val!(instance, self.table_id, table_id as u64);
        self.input.assign(instance, lkm, input);
        self.output.assign(instance, lkm, output);
        for (index, selector) in self.selectors.iter().enumerate() {
            set_val!(instance, *selector, u64::from(index == selected));
        }
        Ok(output)
    }
}

pub struct TensorRmsStateRecord<E: ExtensionField> {
    pub cycle: Expression<E>,
    pub call_id: Expression<E>,
    pub phase: u64,
    pub profile: Expression<E>,
    pub table_id: Expression<E>,
    pub input: Expression<E>,
    pub output: Expression<E>,
}

/// Versioned, ordered boundary record shared by the reduced RMS ecall/core.
pub fn tensor_rms_state_record<E: ExtensionField>(
    record: TensorRmsStateRecord<E>,
) -> Vec<Expression<E>> {
    vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(RMS_STATE_VERSION_V1).expr(),
        record.cycle,
        record.call_id,
        E::BaseField::from_u64(record.phase).expr(),
        record.profile,
        record.table_id,
        record.input,
        record.output,
    ]
}

pub const ATTENTION_STATE_VERSION_V1: u32 = 1;
pub const ATTENTION_STATE_PHASE_INPUT: u64 = 0;
pub const ATTENTION_STATE_PHASE_OUTPUT: u64 = 1;
pub const BLOCK_STATE_VERSION_V1: u32 = 1;
pub const BLOCK_STATE_PHASE_INPUT: u64 = 0;
pub const BLOCK_STATE_PHASE_OUTPUT: u64 = 1;

/// Ordered boundary for the atomic reduced causal-attention chip. Values are
/// raw RV32 words (represented by their two u16 limbs in the caller), so the
/// boundary remains injective even for negative i32 values.
pub struct TensorAttentionStateRecord<E: ExtensionField> {
    pub cycle: Expression<E>,
    pub call_id: Expression<E>,
    pub phase: u64,
    pub descriptor: Vec<Expression<E>>,
    pub qkv_output: Vec<Expression<E>>,
}

pub fn tensor_attention_state_record<E: ExtensionField>(
    record: TensorAttentionStateRecord<E>,
) -> Vec<Expression<E>> {
    let mut row = vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(ATTENTION_STATE_VERSION_V1).expr(),
        record.cycle,
        record.call_id,
        E::BaseField::from_u64(record.phase).expr(),
    ];
    row.extend(record.descriptor);
    row.extend(record.qkv_output);
    row
}

/// Ordered, injective split boundary for a registered fused tensor block.
/// Every guest-visible descriptor/input/root/output word is represented by its
/// two u16 limbs. Private tile bytes remain core-local.
pub fn tensor_block_state_record<E: ExtensionField>(
    cycle: Expression<E>,
    call_id: Expression<E>,
    phase: u64,
    opcode: u32,
    words: impl IntoIterator<Item = Expression<E>>,
) -> Vec<Expression<E>> {
    let mut row = vec![
        CustomRWTag::TensorState.expr::<E>(),
        E::BaseField::from_u32(BLOCK_STATE_VERSION_V1).expr(),
        cycle,
        call_id,
        E::BaseField::from_u64(phase).expr(),
        E::BaseField::from_u32(opcode).expr(),
    ];
    row.extend(words);
    row
}

#[derive(Debug)]
pub struct TensorRmsLookupCoreConfig<E: ExtensionField> {
    pub cycle: WitIn,
    pub call_id: WitIn,
    pub lookup: TensorFixedLookupConfig<E>,
}

impl<E: ExtensionField> TensorRmsLookupCoreConfig<E> {
    pub fn construct(cb: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        let cycle = cb.create_witin(|| "tensor_rms_cycle");
        let call_id = cb.create_witin(|| "tensor_rms_call_id");
        let entries = RMS_REDUCED_ENTRIES
            .iter()
            .map(|&(input, output)| (RMS_INV_LOOKUP_V1, RMS_INV_TABLE_REDUCED_V1, input, output))
            .chain(
                RMS_REDUCED_ENTRIES.iter().map(|&(input, output)| {
                    (SWIGLU_LOOKUP_V1, SWIGLU_TABLE_REDUCED_V1, input, output)
                }),
            )
            .chain(RMS_REDUCED_ENTRIES.iter().map(|&(input, output)| {
                (
                    ROPE_LOOKUP_Q16_REDUCED_V1,
                    ROPE_TABLE_REDUCED_V1,
                    input,
                    output,
                )
            }))
            .chain(RESIDUAL_REDUCED_ENTRIES.iter().map(|&(input, output)| {
                (
                    RESIDUAL_LOOKUP_PACKED_REDUCED_V1,
                    RESIDUAL_TABLE_REDUCED_V1,
                    input,
                    output,
                )
            }))
            .collect_vec();
        let lookup = TensorFixedLookupConfig::construct_registered(
            cb,
            "tensor_scalar_lookup_v1",
            18,
            18,
            &entries,
        )?;
        let record = |phase| {
            tensor_rms_state_record(TensorRmsStateRecord {
                cycle: cycle.expr(),
                call_id: call_id.expr(),
                phase,
                profile: lookup.profile.expr(),
                table_id: lookup.table_id.expr(),
                input: lookup.input.expr(),
                output: lookup.output.expr(),
            })
        };
        cb.read_record(
            || "tensor_rms_state_in",
            crate::structs::RAMType::Custom,
            record(RMS_STATE_PHASE_INPUT),
        )?;
        cb.write_record(
            || "tensor_rms_state_out",
            crate::structs::RAMType::Custom,
            record(RMS_STATE_PHASE_OUTPUT),
        )?;
        Ok(Self {
            cycle,
            call_id,
            lookup,
        })
    }
}

/// Canonical remainder encoded as `r + 2^(shift-1)` in unsigned limbs.  This
/// represents exactly `[-2^(shift-1), 2^(shift-1))`, including Q20 remainders,
/// without asking Ceno's 18-bit range table for an unsupported 20-bit lookup.
#[derive(Debug)]
pub struct TensorBiasedRemainder<E: ExtensionField> {
    limbs: [WitIn; 2],
    shift: u32,
    marker: std::marker::PhantomData<E>,
}

impl<E: ExtensionField> TensorBiasedRemainder<E> {
    fn construct(cb: &mut CircuitBuilder<E>, name: &str, shift: u32) -> Result<Self, ZKVMError> {
        assert!((1..=31).contains(&shift));
        let limbs = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_biased_{i}")));
        cb.assert_const_range(
            || format!("{name}_biased_lo"),
            limbs[0].expr(),
            shift.min(16) as usize,
        )?;
        if shift <= 16 {
            cb.require_zero(|| format!("{name}_biased_hi_zero"), limbs[1].expr())?;
        } else {
            cb.assert_const_range(
                || format!("{name}_biased_hi"),
                limbs[1].expr(),
                (shift - 16) as usize,
            )?;
        }
        Ok(Self {
            limbs,
            shift,
            marker: std::marker::PhantomData,
        })
    }

    fn expr(&self) -> Expression<E> {
        self.limbs[0].expr() + self.limbs[1].expr() * LIMB_BASE
            - E::BaseField::from_u64(1u64 << (self.shift - 1)).expr()
    }

    fn assign(&self, instance: &mut [E::BaseField], lkm: &mut LkMultiplicity, remainder: i64) {
        let half = 1i64 << (self.shift - 1);
        assert!((-half..half).contains(&remainder));
        let biased = (remainder + half) as u64;
        let lo = biased & 0xffff;
        let hi = biased >> 16;
        set_val!(instance, self.limbs[0], lo);
        set_val!(instance, self.limbs[1], hi);
        lkm.assert_const_range(lo, self.shift.min(16) as usize);
        if self.shift > 16 {
            lkm.assert_const_range(hi, (self.shift - 16) as usize);
        }
    }
}

/// One bounded signed product followed by the authoritative zkLLM rescale.
#[derive(Debug)]
pub struct TensorMulRescaleConfig<E: ExtensionField> {
    pub left: TensorSignedWord<E>,
    pub right: TensorSignedWord<E>,
    pub output: TensorSignedWord<E>,
    remainder: TensorBiasedRemainder<E>,
    shift: u32,
}

impl<E: ExtensionField> TensorMulRescaleConfig<E> {
    pub fn construct(
        cb: &mut CircuitBuilder<E>,
        name: &str,
        shift: u32,
        operand_bits: usize,
        output_bits: usize,
    ) -> Result<Self, ZKVMError> {
        Self::construct_bounded(cb, name, shift, operand_bits, operand_bits, output_bits)
    }

    /// Construct a rescale with independently bounded operands.  If the
    /// magnitudes use `l` and `r` bits, their product is strictly below
    /// `2^(l+r)`.  Keeping that sum at most 30 makes equality in BabyBear an
    /// integer equality rather than a field equality modulo the prime.
    pub fn construct_bounded(
        cb: &mut CircuitBuilder<E>,
        name: &str,
        shift: u32,
        left_bits: usize,
        right_bits: usize,
        output_bits: usize,
    ) -> Result<Self, ZKVMError> {
        // The direct field equation is sound only while the integer product is
        // strictly below BabyBear. Full-width migration uses limbs/carries.
        assert!(
            left_bits + right_bits <= 30,
            "direct product may wrap BabyBear"
        );
        let left = TensorSignedWord::construct(cb, &format!("{name}_left"), left_bits)?;
        let right = TensorSignedWord::construct(cb, &format!("{name}_right"), right_bits)?;
        let output = TensorSignedWord::construct(cb, &format!("{name}_output"), output_bits)?;
        let remainder = TensorBiasedRemainder::construct(cb, &format!("{name}_remainder"), shift)?;
        cb.require_equal(
            || format!("{name}_rescale"),
            left.expr() * right.expr(),
            output.expr() * (1u64 << shift) + remainder.expr(),
        )?;
        Ok(Self {
            left,
            right,
            output,
            remainder,
            shift,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        left: i32,
        right: i32,
    ) -> Result<i32, String> {
        let product = i64::from(left)
            .checked_mul(i64::from(right))
            .ok_or("product overflow")?;
        let (output, remainder) =
            ceno_emul::tensor::zkllm_rescale(product, self.shift).map_err(|e| e.to_string())?;
        let output = i32::try_from(output).map_err(|_| "rescaled output exceeds i32")?;
        self.left.assign(instance, lkm, left);
        self.right.assign(instance, lkm, right);
        self.output.assign(instance, lkm, output);
        self.remainder.assign(instance, lkm, remainder);
        Ok(output)
    }
}

#[derive(Debug)]
pub struct TensorResidualConfig<E: ExtensionField> {
    pub left: TensorSignedWord<E>,
    pub right: TensorSignedWord<E>,
    pub output: TensorSignedWord<E>,
}

impl<E: ExtensionField> TensorResidualConfig<E> {
    pub fn construct(
        cb: &mut CircuitBuilder<E>,
        name: &str,
        operand_bits: usize,
        output_bits: usize,
    ) -> Result<Self, ZKVMError> {
        let left = TensorSignedWord::construct(cb, &format!("{name}_left"), operand_bits)?;
        let right = TensorSignedWord::construct(cb, &format!("{name}_right"), operand_bits)?;
        let output = TensorSignedWord::construct(cb, &format!("{name}_output"), output_bits)?;
        cb.require_equal(
            || format!("{name}_add"),
            left.expr() + right.expr(),
            output.expr(),
        )?;
        Ok(Self {
            left,
            right,
            output,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        left: i32,
        right: i32,
    ) -> Result<i32, String> {
        let output = left.checked_add(right).ok_or("residual overflow")?;
        self.left.assign(instance, lkm, left);
        self.right.assign(instance, lkm, right);
        self.output.assign(instance, lkm, output);
        Ok(output)
    }
}

/// One RoPE coordinate: `out = rescale(x*cos + rotate_half(x)*sin)`.
#[derive(Debug)]
pub struct TensorRopeConfig<E: ExtensionField> {
    pub value: TensorSignedWord<E>,
    pub rotated: TensorSignedWord<E>,
    pub cosine: TensorSignedWord<E>,
    pub sine: TensorSignedWord<E>,
    pub output: TensorSignedWord<E>,
    remainder: TensorBiasedRemainder<E>,
}

impl<E: ExtensionField> TensorRopeConfig<E> {
    pub fn construct(cb: &mut CircuitBuilder<E>, name: &str) -> Result<Self, ZKVMError> {
        // Reduced Gate-3 values are 9-bit and Q16 table entries are 17-bit;
        // the sum stays below 2^27 and cannot wrap BabyBear.
        let value = TensorSignedWord::construct(cb, &format!("{name}_value"), 9)?;
        let rotated = TensorSignedWord::construct(cb, &format!("{name}_rotated"), 9)?;
        let cosine = TensorSignedWord::construct(cb, &format!("{name}_cos"), 17)?;
        let sine = TensorSignedWord::construct(cb, &format!("{name}_sin"), 17)?;
        let output = TensorSignedWord::construct(cb, &format!("{name}_output"), 10)?;
        let remainder = TensorBiasedRemainder::construct(cb, &format!("{name}_remainder"), 16)?;
        cb.require_equal(
            || format!("{name}_rope"),
            value.expr() * cosine.expr() + rotated.expr() * sine.expr(),
            output.expr() * (1u64 << 16) + remainder.expr(),
        )?;
        Ok(Self {
            value,
            rotated,
            cosine,
            sine,
            output,
            remainder,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        value: i32,
        rotated: i32,
        cosine: i32,
        sine: i32,
    ) -> Result<i32, String> {
        let accum = i64::from(value) * i64::from(cosine) + i64::from(rotated) * i64::from(sine);
        let (output, remainder) =
            ceno_emul::tensor::zkllm_rescale(accum, 16).map_err(|e| e.to_string())?;
        let output = i32::try_from(output).map_err(|_| "RoPE output exceeds i32")?;
        self.value.assign(instance, lkm, value);
        self.rotated.assign(instance, lkm, rotated);
        self.cosine.assign(instance, lkm, cosine);
        self.sine.assign(instance, lkm, sine);
        self.output.assign(instance, lkm, output);
        self.remainder.assign(instance, lkm, remainder);
        Ok(output)
    }
}

#[derive(Debug)]
pub struct TensorSignedWord<E: ExtensionField> {
    pub sign: WitIn,
    pub magnitude: [WitIn; 2],
    pub zero: WitIn,
    pub inverse: WitIn,
    magnitude_bits: usize,
    value: WitIn,
    marker: std::marker::PhantomData<E>,
}

impl<E: ExtensionField> TensorSignedWord<E> {
    pub(crate) fn construct(
        cb: &mut CircuitBuilder<E>,
        name: &str,
        magnitude_bits: usize,
    ) -> Result<Self, ZKVMError> {
        // Two canonical u16 limbs are required for the full i32 domain,
        // including `i32::MIN` whose signed magnitude is exactly 2^31.
        assert!((1..=32).contains(&magnitude_bits));
        let sign = cb.create_witin(|| format!("{name}_sign"));
        let magnitude = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_mag_{i}")));
        let zero = cb.create_witin(|| format!("{name}_zero"));
        let inverse = cb.create_witin(|| format!("{name}_inverse"));
        let value = cb.create_witin(|| format!("{name}_value"));
        cb.assert_bit(|| format!("{name}_sign_bit"), sign.expr())?;
        cb.assert_bit(|| format!("{name}_zero_bit"), zero.expr())?;
        cb.assert_const_range(
            || format!("{name}_mag_lo"),
            magnitude[0].expr(),
            magnitude_bits.min(16),
        )?;
        if magnitude_bits <= 16 {
            cb.require_zero(|| format!("{name}_mag_hi_zero"), magnitude[1].expr())?;
        } else {
            cb.assert_const_range(
                || format!("{name}_mag_hi"),
                magnitude[1].expr(),
                magnitude_bits - 16,
            )?;
        }
        let magnitude_expr = magnitude[0].expr() + magnitude[1].expr() * LIMB_BASE;
        cb.require_zero(
            || format!("{name}_zero_product"),
            magnitude_expr.clone() * zero.expr(),
        )?;
        cb.require_zero(
            || format!("{name}_inverse_or_zero"),
            magnitude_expr.clone() * inverse.expr() - (E::BaseField::ONE.expr() - zero.expr()),
        )?;
        cb.require_zero(
            || format!("{name}_canonical_zero_sign"),
            sign.expr() * zero.expr(),
        )?;
        cb.require_equal(
            || format!("{name}_signed_value"),
            value.expr(),
            (E::BaseField::ONE.expr() - sign.expr() * 2) * magnitude_expr,
        )?;
        Ok(Self {
            sign,
            magnitude,
            zero,
            inverse,
            magnitude_bits,
            value,
            marker: std::marker::PhantomData,
        })
    }

    pub fn expr(&self) -> Expression<E> {
        self.value.expr()
    }

    pub fn assign(&self, instance: &mut [E::BaseField], lkm: &mut LkMultiplicity, value: i32) {
        let sign = u64::from(value < 0);
        let magnitude = i64::from(value).unsigned_abs();
        let lo = magnitude & 0xffff;
        let hi = magnitude >> 16;
        let zero = u64::from(magnitude == 0);
        set_val!(instance, self.sign, sign);
        set_val!(instance, self.magnitude[0], lo);
        set_val!(instance, self.magnitude[1], hi);
        set_val!(instance, self.zero, zero);
        let inverse = E::BaseField::from_u64(magnitude)
            .try_inverse()
            .unwrap_or(E::BaseField::ZERO);
        set_val!(instance, self.inverse, inverse);
        set_val!(
            instance,
            self.value,
            E::BaseField::from_i64(i64::from(value))
        );
        lkm.assert_const_range(lo, self.magnitude_bits.min(16));
        if self.magnitude_bits > 16 {
            lkm.assert_const_range(hi, self.magnitude_bits - 16);
        }
    }
}

#[derive(Debug)]
pub struct TensorSignedRemainder<E: ExtensionField> {
    pub sign: WitIn,
    pub magnitude: WitIn,
    value: Expression<E>,
}

/// One production-safe signed i32 multiplication. Magnitudes are four
/// constrained base-256 limbs and the full product is eight limbs with
/// explicit carries. This avoids interpreting a 64-bit product as one
/// BabyBear element. Dot products reduce these rows in sign-separated limbs.
#[derive(Debug)]
pub struct TensorI32ByteLimbProduct<E: ExtensionField> {
    pub left_sign: WitIn,
    pub right_sign: WitIn,
    pub product_sign: WitIn,
    pub left: [WitIn; 4],
    pub right: [WitIn; 4],
    pub product: [WitIn; 8],
    pub carries: [WitIn; 7],
    marker: std::marker::PhantomData<E>,
}

impl<E: ExtensionField> TensorI32ByteLimbProduct<E> {
    pub fn construct(cb: &mut CircuitBuilder<E>, name: &str) -> Result<Self, ZKVMError> {
        let left_sign = cb.create_witin(|| format!("{name}_left_sign"));
        let right_sign = cb.create_witin(|| format!("{name}_right_sign"));
        let product_sign = cb.create_witin(|| format!("{name}_product_sign"));
        for (label, bit) in [
            ("left", left_sign),
            ("right", right_sign),
            ("product", product_sign),
        ] {
            cb.assert_bit(|| format!("{name}_{label}_sign_bit"), bit.expr())?;
        }
        cb.require_equal(
            || format!("{name}_sign_xor"),
            product_sign.expr(),
            left_sign.expr() + right_sign.expr() - left_sign.expr() * right_sign.expr() * 2,
        )?;
        let left = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_left_{i}")));
        let right = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_right_{i}")));
        let product = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_product_{i}")));
        let carries = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_carry_{i}")));
        for (i, limb) in left.iter().chain(&right).chain(&product).enumerate() {
            cb.assert_const_range(|| format!("{name}_byte_{i}"), limb.expr(), 8)?;
        }
        // abs(i32::MIN)=2^31 is admitted, but no larger unsigned magnitude is.
        cb.assert_const_range(|| format!("{name}_left_top"), left[3].expr(), 8)?;
        cb.assert_const_range(|| format!("{name}_right_top"), right[3].expr(), 8)?;
        for (i, carry) in carries.iter().enumerate() {
            cb.assert_const_range(|| format!("{name}_carry18_{i}"), carry.expr(), 18)?;
        }
        for diagonal in 0usize..8 {
            let convolution = (0usize..4)
                .filter_map(|i| {
                    let j = diagonal.checked_sub(i)?;
                    (j < 4).then(|| left[i].expr() * right[j].expr())
                })
                .fold(E::BaseField::ZERO.expr(), |sum, term| sum + term);
            let carry_in = if diagonal == 0 {
                E::BaseField::ZERO.expr()
            } else {
                carries[diagonal - 1].expr()
            };
            let carry_out = if diagonal == 7 {
                E::BaseField::ZERO.expr()
            } else {
                carries[diagonal].expr() * 256
            };
            cb.require_equal(
                || format!("{name}_convolution_{diagonal}"),
                convolution + carry_in,
                product[diagonal].expr() + carry_out,
            )?;
        }
        Ok(Self {
            left_sign,
            right_sign,
            product_sign,
            left,
            right,
            product,
            carries,
            marker: std::marker::PhantomData,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        left: i32,
        right: i32,
    ) {
        let left_mag = u64::from(left.unsigned_abs());
        let right_mag = u64::from(right.unsigned_abs());
        set_val!(instance, self.left_sign, u64::from(left < 0));
        set_val!(instance, self.right_sign, u64::from(right < 0));
        set_val!(
            instance,
            self.product_sign,
            u64::from((left < 0) ^ (right < 0))
        );
        for (i, limb) in self.left.iter().enumerate() {
            let v = (left_mag >> (8 * i)) & 255;
            set_val!(instance, *limb, v);
            lkm.assert_const_range(v, 8);
        }
        for (i, limb) in self.right.iter().enumerate() {
            let v = (right_mag >> (8 * i)) & 255;
            set_val!(instance, *limb, v);
            lkm.assert_const_range(v, 8);
        }
        // These two checks intentionally mirror the separate top-byte range
        // constraints in `construct`.  They are redundant algebraically, but
        // remain distinct dynamic lookup relations in the AIR.
        lkm.assert_const_range((left_mag >> 24) & 255, 8);
        lkm.assert_const_range((right_mag >> 24) & 255, 8);
        let product = u128::from(left.unsigned_abs()) * u128::from(right.unsigned_abs());
        for (i, limb) in self.product.iter().enumerate() {
            let v = ((product >> (8 * i)) & 255) as u64;
            set_val!(instance, *limb, v);
            lkm.assert_const_range(v, 8);
        }
        let left_bytes = std::array::from_fn::<_, 4, _>(|i| (left_mag >> (8 * i)) & 255);
        let right_bytes = std::array::from_fn::<_, 4, _>(|i| (right_mag >> (8 * i)) & 255);
        let mut carry = 0u64;
        for diagonal in 0usize..7 {
            let bucket = (0usize..4)
                .filter_map(|i| {
                    diagonal
                        .checked_sub(i)
                        .filter(|&j| j < 4)
                        .map(|j| left_bytes[i] * right_bytes[j])
                })
                .sum::<u64>()
                + carry;
            carry = bucket >> 8;
            set_val!(instance, self.carries[diagonal], carry);
            lkm.assert_const_range(carry, 18);
        }
    }
}

/// A sign-separated dot-product tile. Each multiplication is constrained by
/// `TensorI32ByteLimbProduct`; byte columns are then accumulated into distinct
/// positive/negative base-256 buckets. For K<=1024 every diagonal sum is below
/// 2^19, hence below BabyBear, and cancellation is deferred until the buckets
/// have been range-constrained.
#[derive(Debug)]
pub struct TensorSignedDotBucketConfig<E: ExtensionField> {
    pub products: Vec<TensorI32ByteLimbProduct<E>>,
    pub positive: [WitIn; 10],
    pub negative: [WitIn; 10],
    pub positive_carries: [WitIn; 9],
    pub negative_carries: [WitIn; 9],
}

#[derive(Debug)]
pub struct TensorSignedI64Nibbles {
    pub sign: WitIn,
    pub magnitude: [WitIn; 16],
}

/// Limb-safe `accumulator = quotient * 2^shift + remainder` for signed i64
/// values. Base 16 aligns both supported shifts and keeps each addition digit
/// tiny. The common 17-digit normalized result prevents independent carry
/// choices on the two sides of the signed equation.
#[derive(Debug)]
pub struct TensorSignedLimbRescaleConfig<E: ExtensionField> {
    pub accumulator: TensorSignedI64Nibbles,
    pub quotient: TensorSignedI64Nibbles,
    pub remainder: TensorSignedI64Nibbles,
    pub result: [WitIn; 17],
    pub left_carries: [WitIn; 16],
    pub right_carries: [WitIn; 16],
    pub remainder_top_high: WitIn,
    pub remainder_top_low: WitIn,
    shift: u32,
    marker: std::marker::PhantomData<E>,
}

/// Checked base-256 addition used to fold independently constrained K-tile
/// buckets.  The final carry is constrained to zero, so a production bucket
/// cannot silently wrap at ten bytes.
#[derive(Debug)]
pub struct TensorBucketAddConfig<E: ExtensionField> {
    pub accumulator: [WitIn; 10],
    pub addend: [WitIn; 10],
    pub output: [WitIn; 10],
    pub carries: [WitIn; 10],
    marker: std::marker::PhantomData<E>,
}

/// Binds the difference of two unsigned ten-byte buckets to the signed-i64
/// accumulator consumed by `TensorSignedLimbRescaleConfig`.  Both sides are
/// normalized to one shared base-16 result, preventing independent carry
/// choices or in-field cancellation.
#[derive(Debug)]
pub struct TensorBucketDifferenceConfig<E: ExtensionField> {
    pub positive_nibbles: [[WitIn; 2]; 10],
    pub negative_nibbles: [[WitIn; 2]; 10],
    pub result: [WitIn; 21],
    pub positive_carries: [WitIn; 20],
    pub negative_carries: [WitIn; 20],
    marker: std::marker::PhantomData<E>,
}

impl<E: ExtensionField> TensorBucketAddConfig<E> {
    pub fn construct(cb: &mut CircuitBuilder<E>, name: &str) -> Result<Self, ZKVMError> {
        let accumulator = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_acc_{i}")));
        let addend = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_add_{i}")));
        let output = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_out_{i}")));
        let carries = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_carry_{i}")));
        for (kind, limbs) in [("acc", &accumulator), ("add", &addend), ("out", &output)] {
            for (i, limb) in limbs.iter().enumerate() {
                cb.assert_const_range(|| format!("{name}_{kind}_byte_{i}"), limb.expr(), 8)?;
            }
        }
        for (i, carry) in carries.iter().enumerate() {
            cb.assert_bit(|| format!("{name}_carry_bit_{i}"), carry.expr())?;
            let carry_in = if i == 0 {
                E::BaseField::ZERO.expr()
            } else {
                carries[i - 1].expr()
            };
            let carry_out = if i == 9 {
                E::BaseField::ZERO.expr()
            } else {
                carry.expr() * 256
            };
            cb.require_equal(
                || format!("{name}_add_column_{i}"),
                accumulator[i].expr() + addend[i].expr() + carry_in,
                output[i].expr() + carry_out,
            )?;
        }
        // The otherwise-unused last carry is the explicit terminal-overflow witness.
        cb.require_zero(|| format!("{name}_terminal_carry"), carries[9].expr())?;
        Ok(Self {
            accumulator,
            addend,
            output,
            carries,
            marker: std::marker::PhantomData,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        accumulator: &[u8],
        addend: &[u8],
    ) -> Result<[u8; 10], String> {
        if accumulator.len() < 10 || addend.len() < 10 {
            return Err("bucket add requires ten bytes".into());
        }
        let mut output = [0u8; 10];
        let mut carry = 0u16;
        for i in 0..10 {
            let column = u16::from(accumulator[i]) + u16::from(addend[i]) + carry;
            output[i] = column as u8;
            carry = column >> 8;
            for (column, value) in [
                (self.accumulator[i], accumulator[i]),
                (self.addend[i], addend[i]),
                (self.output[i], output[i]),
            ] {
                set_val!(instance, column, u64::from(value));
                lkm.assert_const_range(u64::from(value), 8);
            }
            // Column nine is a dedicated zero terminal witness.
            let witnessed = if i == 9 { 0 } else { carry as u64 };
            set_val!(instance, self.carries[i], witnessed);
        }
        if carry != 0 {
            return Err("bucket add overflow".into());
        }
        Ok(output)
    }
}

impl<E: ExtensionField> TensorBucketDifferenceConfig<E> {
    pub fn construct(
        cb: &mut CircuitBuilder<E>,
        name: &str,
        positive: &[WitIn; 10],
        negative: &[WitIn; 10],
        accumulator: &TensorSignedI64Nibbles,
    ) -> Result<Self, ZKVMError> {
        let positive_nibbles = std::array::from_fn(|i| {
            std::array::from_fn(|j| cb.create_witin(|| format!("{name}_positive_{i}_{j}")))
        });
        let negative_nibbles = std::array::from_fn(|i| {
            std::array::from_fn(|j| cb.create_witin(|| format!("{name}_negative_{i}_{j}")))
        });
        for i in 0..10 {
            for j in 0..2 {
                cb.assert_const_range(
                    || format!("{name}_positive_nibble_{i}_{j}"),
                    positive_nibbles[i][j].expr(),
                    4,
                )?;
                cb.assert_const_range(
                    || format!("{name}_negative_nibble_{i}_{j}"),
                    negative_nibbles[i][j].expr(),
                    4,
                )?;
            }
            cb.require_equal(
                || format!("{name}_positive_split_{i}"),
                positive[i].expr(),
                positive_nibbles[i][0].expr() + positive_nibbles[i][1].expr() * 16,
            )?;
            cb.require_equal(
                || format!("{name}_negative_split_{i}"),
                negative[i].expr(),
                negative_nibbles[i][0].expr() + negative_nibbles[i][1].expr() * 16,
            )?;
        }
        let result = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_result_{i}")));
        let positive_carries =
            std::array::from_fn(|i| cb.create_witin(|| format!("{name}_positive_carry_{i}")));
        let negative_carries =
            std::array::from_fn(|i| cb.create_witin(|| format!("{name}_negative_carry_{i}")));
        for i in 0..21 {
            cb.assert_const_range(|| format!("{name}_result_nibble_{i}"), result[i].expr(), 4)?;
            let bucket = |limbs: &[[WitIn; 2]; 10]| {
                if i < 20 {
                    limbs[i / 2][i % 2].expr()
                } else {
                    E::BaseField::ZERO.expr()
                }
            };
            let acc_pos = if i < 16 {
                (E::BaseField::ONE.expr() - accumulator.sign.expr())
                    * accumulator.magnitude[i].expr()
            } else {
                E::BaseField::ZERO.expr()
            };
            let acc_neg = if i < 16 {
                accumulator.sign.expr() * accumulator.magnitude[i].expr()
            } else {
                E::BaseField::ZERO.expr()
            };
            for (side, terms, carries) in [
                (
                    "positive",
                    bucket(&positive_nibbles) + acc_neg,
                    &positive_carries,
                ),
                (
                    "negative",
                    bucket(&negative_nibbles) + acc_pos,
                    &negative_carries,
                ),
            ] {
                let carry_in = if i == 0 {
                    E::BaseField::ZERO.expr()
                } else {
                    carries[i - 1].expr()
                };
                let carry_out = if i == 20 {
                    E::BaseField::ZERO.expr()
                } else {
                    carries[i].expr() * 16
                };
                cb.require_equal(
                    || format!("{name}_{side}_normalize_{i}"),
                    terms + carry_in,
                    result[i].expr() + carry_out,
                )?;
            }
            if i < 20 {
                cb.assert_bit(
                    || format!("{name}_positive_carry_bit_{i}"),
                    positive_carries[i].expr(),
                )?;
                cb.assert_bit(
                    || format!("{name}_negative_carry_bit_{i}"),
                    negative_carries[i].expr(),
                )?;
            }
        }
        Ok(Self {
            positive_nibbles,
            negative_nibbles,
            result,
            positive_carries,
            negative_carries,
            marker: std::marker::PhantomData,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        positive: u128,
        negative: u128,
        accumulator: i64,
    ) -> Result<(), String> {
        if i128::try_from(positive).map_err(|_| "positive bucket overflow")?
            - i128::try_from(negative).map_err(|_| "negative bucket overflow")?
            != i128::from(accumulator)
        {
            return Err("bucket difference mismatch".into());
        }
        let acc_mag = u128::from(accumulator.unsigned_abs());
        let lhs = positive + if accumulator < 0 { acc_mag } else { 0 };
        let rhs = negative + if accumulator >= 0 { acc_mag } else { 0 };
        if lhs != rhs {
            return Err("bucket normalization mismatch".into());
        }
        for i in 0..10 {
            for j in 0..2 {
                let shift = 8 * i + 4 * j;
                for (column, value) in [
                    (self.positive_nibbles[i][j], (positive >> shift) & 15),
                    (self.negative_nibbles[i][j], (negative >> shift) & 15),
                ] {
                    set_val!(instance, column, value as u64);
                    lkm.assert_const_range(value as u64, 4);
                }
            }
        }
        for i in 0..21 {
            let digit = ((lhs >> (4 * i)) & 15) as u64;
            set_val!(instance, self.result[i], digit);
            lkm.assert_const_range(digit, 4);
        }
        for (bucket, add, carries) in [
            (
                positive,
                if accumulator < 0 { acc_mag } else { 0 },
                &self.positive_carries,
            ),
            (
                negative,
                if accumulator >= 0 { acc_mag } else { 0 },
                &self.negative_carries,
            ),
        ] {
            let mut carry = 0u128;
            for i in 0..20 {
                carry = (((bucket >> (4 * i)) & 15) + ((add >> (4 * i)) & 15) + carry) >> 4;
                set_val!(instance, carries[i], carry as u64);
                lkm.assert_const_range(carry as u64, 1);
            }
        }
        Ok(())
    }
}

impl TensorSignedI64Nibbles {
    fn construct<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        name: &str,
    ) -> Result<Self, ZKVMError> {
        let sign = cb.create_witin(|| format!("{name}_sign"));
        cb.assert_bit(|| format!("{name}_sign_bit"), sign.expr())?;
        let magnitude = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_nibble_{i}")));
        for (i, digit) in magnitude.iter().enumerate() {
            cb.assert_const_range(|| format!("{name}_nibble4_{i}"), digit.expr(), 4)?;
        }
        Ok(Self { sign, magnitude })
    }

    fn assign<E: ExtensionField>(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        value: i64,
    ) {
        let magnitude = value.unsigned_abs();
        set_val!(instance, self.sign, u64::from(value < 0));
        for (i, digit) in self.magnitude.iter().enumerate() {
            let nibble = (magnitude >> (4 * i)) & 15;
            set_val!(instance, *digit, nibble);
            lkm.assert_const_range(nibble, 4);
        }
    }
}

impl<E: ExtensionField> TensorSignedLimbRescaleConfig<E> {
    pub fn construct(
        cb: &mut CircuitBuilder<E>,
        name: &str,
        shift: u32,
    ) -> Result<Self, ZKVMError> {
        if !matches!(shift, 16 | 20) {
            return Err(ZKVMError::InvalidWitness(
                "limb rescale shift must be 16 or 20".into(),
            ));
        }
        let accumulator = TensorSignedI64Nibbles::construct(cb, &format!("{name}_acc"))?;
        let quotient = TensorSignedI64Nibbles::construct(cb, &format!("{name}_q"))?;
        let remainder = TensorSignedI64Nibbles::construct(cb, &format!("{name}_r"))?;
        let result = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_sum_{i}")));
        let left_carries =
            std::array::from_fn(|i| cb.create_witin(|| format!("{name}_left_carry_{i}")));
        let right_carries =
            std::array::from_fn(|i| cb.create_witin(|| format!("{name}_right_carry_{i}")));
        for (i, digit) in result.iter().enumerate() {
            cb.assert_const_range(|| format!("{name}_sum4_{i}"), digit.expr(), 4)?;
        }
        for (side, carries) in [("left", &left_carries), ("right", &right_carries)] {
            for (i, carry) in carries.iter().enumerate() {
                cb.assert_const_range(|| format!("{name}_{side}_carry2_{i}"), carry.expr(), 2)?;
            }
        }
        // Canonical half-open remainder: positive magnitude < half; negative
        // magnitude <= half. The top remainder nibble is therefore 0..7, or
        // exactly 8 only for a negative remainder with all lower digits zero.
        let top = shift as usize / 4 - 1;
        let top_high = cb.create_witin(|| format!("{name}_r_top_high"));
        let top_low = cb.create_witin(|| format!("{name}_r_top_low"));
        cb.assert_bit(|| format!("{name}_r_top_high_bit"), top_high.expr())?;
        cb.assert_const_range(|| format!("{name}_r_top_low3"), top_low.expr(), 3)?;
        cb.require_equal(
            || format!("{name}_r_top_split"),
            remainder.magnitude[top].expr(),
            top_low.expr() + top_high.expr() * 8,
        )?;
        cb.require_zero(
            || format!("{name}_positive_r_below_half"),
            (E::BaseField::ONE.expr() - remainder.sign.expr()) * top_high.expr(),
        )?;
        cb.require_zero(
            || format!("{name}_negative_half_top_exact"),
            top_high.expr() * top_low.expr(),
        )?;
        for i in 0..top {
            cb.require_zero(
                || format!("{name}_negative_half_low_zero_{i}"),
                top_high.expr() * remainder.magnitude[i].expr(),
            )?;
        }
        for i in top + 1..16 {
            cb.require_zero(
                || format!("{name}_remainder_high_zero_{i}"),
                remainder.magnitude[i].expr(),
            )?;
        }
        let q_offset = (shift / 4) as usize;
        for digit in 0..17 {
            let acc_pos = if digit < 16 {
                (E::BaseField::ONE.expr() - accumulator.sign.expr())
                    * accumulator.magnitude[digit].expr()
            } else {
                E::BaseField::ZERO.expr()
            };
            let acc_neg = if digit < 16 {
                accumulator.sign.expr() * accumulator.magnitude[digit].expr()
            } else {
                E::BaseField::ZERO.expr()
            };
            let r_pos = if digit < 16 {
                (E::BaseField::ONE.expr() - remainder.sign.expr())
                    * remainder.magnitude[digit].expr()
            } else {
                E::BaseField::ZERO.expr()
            };
            let r_neg = if digit < 16 {
                remainder.sign.expr() * remainder.magnitude[digit].expr()
            } else {
                E::BaseField::ZERO.expr()
            };
            let q_digit = digit.checked_sub(q_offset).filter(|&i| i < 16);
            let q_pos = q_digit
                .map(|i| {
                    (E::BaseField::ONE.expr() - quotient.sign.expr()) * quotient.magnitude[i].expr()
                })
                .unwrap_or_else(|| E::BaseField::ZERO.expr());
            let q_neg = q_digit
                .map(|i| quotient.sign.expr() * quotient.magnitude[i].expr())
                .unwrap_or_else(|| E::BaseField::ZERO.expr());
            for (side, terms, carries) in [
                ("left", acc_pos + q_neg + r_neg, &left_carries),
                ("right", acc_neg + q_pos + r_pos, &right_carries),
            ] {
                let carry_in = if digit == 0 {
                    E::BaseField::ZERO.expr()
                } else {
                    carries[digit - 1].expr()
                };
                let carry_out = if digit == 16 {
                    E::BaseField::ZERO.expr()
                } else {
                    carries[digit].expr() * 16
                };
                cb.require_equal(
                    || format!("{name}_{side}_normalize_{digit}"),
                    terms + carry_in,
                    result[digit].expr() + carry_out,
                )?;
            }
        }
        Ok(Self {
            accumulator,
            quotient,
            remainder,
            result,
            left_carries,
            right_carries,
            remainder_top_high: top_high,
            remainder_top_low: top_low,
            shift,
            marker: std::marker::PhantomData,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        accumulator: i64,
    ) -> Result<(i64, i64), String> {
        let (q, r) =
            ceno_emul::tensor::zkllm_rescale(accumulator, self.shift).map_err(|e| e.to_string())?;
        self.accumulator.assign::<E>(instance, lkm, accumulator);
        self.quotient.assign::<E>(instance, lkm, q);
        self.remainder.assign::<E>(instance, lkm, r);
        let top = self.shift as usize / 4 - 1;
        let top_nibble = (r.unsigned_abs() >> (4 * top)) & 15;
        set_val!(instance, self.remainder_top_high, top_nibble >> 3);
        set_val!(instance, self.remainder_top_low, top_nibble & 7);
        lkm.assert_const_range(top_nibble >> 3, 1);
        lkm.assert_const_range(top_nibble & 7, 3);
        let shift = self.shift;
        let lhs = u128::from(accumulator.max(0) as u64)
            + (u128::from(q.unsigned_abs()) << shift) * u128::from(q < 0)
            + u128::from(r.unsigned_abs()) * u128::from(r < 0);
        let rhs = u128::from(accumulator.unsigned_abs()) * u128::from(accumulator < 0)
            + (u128::from(q.max(0) as u64) << shift)
            + u128::from(r.max(0) as u64);
        if lhs != rhs {
            return Err("limb rescale internal equality failed".into());
        }
        for i in 0..17 {
            let digit = ((lhs >> (4 * i)) & 15) as u64;
            set_val!(instance, self.result[i], digit);
            lkm.assert_const_range(digit, 4);
        }
        // Compute carries from the actual three signed-side terms.  Do not
        // first account for a normalized approximation: both passes target
        // the same witness columns, while the AIR has exactly one lookup per
        // carry column.
        for (left_side, carries) in [(true, &self.left_carries), (false, &self.right_carries)] {
            let mut carry = 0u64;
            for digit in 0..16 {
                let nib = |v: u64, offset: usize| {
                    if digit >= offset {
                        (v >> (4 * (digit - offset))) & 15
                    } else {
                        0
                    }
                };
                let terms = if left_side {
                    nib(accumulator.max(0) as u64, 0)
                        + if q < 0 {
                            nib(q.unsigned_abs(), (shift / 4) as usize)
                        } else {
                            0
                        }
                        + if r < 0 { nib(r.unsigned_abs(), 0) } else { 0 }
                } else {
                    (if accumulator < 0 {
                        nib(accumulator.unsigned_abs(), 0)
                    } else {
                        0
                    }) + nib(q.max(0) as u64, (shift / 4) as usize)
                        + nib(r.max(0) as u64, 0)
                };
                carry = (terms + carry) >> 4;
                set_val!(instance, carries[digit], carry);
                lkm.assert_const_range(carry, 2);
            }
        }
        Ok((q, r))
    }
}

impl<E: ExtensionField> TensorSignedDotBucketConfig<E> {
    pub fn construct(cb: &mut CircuitBuilder<E>, name: &str, k: usize) -> Result<Self, ZKVMError> {
        if !(1..=ceno_emul::tensor::production::PRODUCTION_K_TILE).contains(&k) {
            return Err(ZKVMError::InvalidWitness(
                "production dot K outside 1..=1024".into(),
            ));
        }
        let products = (0..k)
            .map(|i| TensorI32ByteLimbProduct::construct(cb, &format!("{name}_product_{i}")))
            .collect::<Result<Vec<_>, _>>()?;
        let positive = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_positive_{i}")));
        let negative = std::array::from_fn(|i| cb.create_witin(|| format!("{name}_negative_{i}")));
        let positive_carries =
            std::array::from_fn(|i| cb.create_witin(|| format!("{name}_positive_carry_{i}")));
        let negative_carries =
            std::array::from_fn(|i| cb.create_witin(|| format!("{name}_negative_carry_{i}")));
        for (side, limbs, carries) in [
            ("positive", &positive, &positive_carries),
            ("negative", &negative, &negative_carries),
        ] {
            for (i, limb) in limbs.iter().enumerate() {
                cb.assert_const_range(|| format!("{name}_{side}_byte_{i}"), limb.expr(), 8)?;
            }
            // A carry is at most K after division by 256; 11 bits admits 1024.
            for (i, carry) in carries.iter().enumerate() {
                cb.assert_const_range(|| format!("{name}_{side}_carry11_{i}"), carry.expr(), 11)?;
            }
        }
        for byte in 0..10 {
            for (side, wanted_sign, limbs, carries) in [
                ("positive", 0u64, &positive, &positive_carries),
                ("negative", 1u64, &negative, &negative_carries),
            ] {
                let terms = if byte < 8 {
                    products
                        .iter()
                        .fold(E::BaseField::ZERO.expr(), |sum, product| {
                            let selector = if wanted_sign == 0 {
                                E::BaseField::ONE.expr() - product.product_sign.expr()
                            } else {
                                product.product_sign.expr()
                            };
                            sum + selector * product.product[byte].expr()
                        })
                } else {
                    E::BaseField::ZERO.expr()
                };
                let carry_in = if byte == 0 {
                    E::BaseField::ZERO.expr()
                } else {
                    carries[byte - 1].expr()
                };
                let carry_out = if byte == 9 {
                    E::BaseField::ZERO.expr()
                } else {
                    carries[byte].expr() * 256
                };
                cb.require_equal(
                    || format!("{name}_{side}_accumulate_{byte}"),
                    terms + carry_in,
                    limbs[byte].expr() + carry_out,
                )?;
            }
        }
        Ok(Self {
            products,
            positive,
            negative,
            positive_carries,
            negative_carries,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        left: &[i32],
        right: &[i32],
    ) -> Result<(), String> {
        if left.len() != self.products.len() || right.len() != self.products.len() {
            return Err("production dot assignment shape mismatch".into());
        }
        for ((product, &a), &b) in self.products.iter().zip(left).zip(right) {
            product.assign(instance, lkm, a, b);
        }
        let trace = ceno_emul::tensor::production::signed_dot_byte_limb_tile(left, right)
            .map_err(|e| e.to_string())?;
        for (value, wanted_negative, limbs, carries) in [
            (
                trace.positive,
                false,
                &self.positive,
                &self.positive_carries,
            ),
            (trace.negative, true, &self.negative, &self.negative_carries),
        ] {
            for (i, limb) in limbs.iter().enumerate() {
                let byte = ((value >> (8 * i)) & 255) as u64;
                set_val!(instance, *limb, byte);
                lkm.assert_const_range(byte, 8);
            }
            let mut carry = 0u128;
            for byte in 0..9 {
                let terms: u128 = left
                    .iter()
                    .zip(right)
                    .filter_map(|(&a, &b)| {
                        let negative = (a < 0) ^ (b < 0);
                        (negative == wanted_negative).then(|| {
                            (u128::from(a.unsigned_abs()) * u128::from(b.unsigned_abs())
                                >> (8 * byte))
                                & 255
                        })
                    })
                    .sum();
                carry = (terms + carry) >> 8;
                set_val!(instance, carries[byte], carry as u64);
                lkm.assert_const_range(carry as u64, 11);
            }
        }
        Ok(())
    }
}

/// One production-safe MatMul output cell. Large K dimensions are partitioned
/// into bounded dot-product tiles, then both sign buckets are folded through a
/// checked base-256 chain before the single difference/rescale relation.
#[derive(Debug)]
pub struct TensorProductionMatMulCellConfig<E: ExtensionField> {
    pub buckets: Vec<TensorSignedDotBucketConfig<E>>,
    pub positive_folds: Vec<TensorBucketAddConfig<E>>,
    pub negative_folds: Vec<TensorBucketAddConfig<E>>,
    pub difference: TensorBucketDifferenceConfig<E>,
    pub rescale: TensorSignedLimbRescaleConfig<E>,
    k: usize,
}

impl<E: ExtensionField> TensorProductionMatMulCellConfig<E> {
    pub fn construct(
        cb: &mut CircuitBuilder<E>,
        name: &str,
        k: usize,
        shift: u32,
    ) -> Result<Self, ZKVMError> {
        if k == 0 {
            return Err(ZKVMError::InvalidWitness(
                "production MatMul K must be nonzero".into(),
            ));
        }
        let tile_size = ceno_emul::tensor::production::PRODUCTION_K_TILE;
        let tile_count = k.div_ceil(tile_size);
        let buckets = (0..tile_count)
            .map(|tile| {
                let tile_k = (k - tile * tile_size).min(tile_size);
                TensorSignedDotBucketConfig::construct(cb, &format!("{name}_bucket_{tile}"), tile_k)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let positive_folds = (0..tile_count)
            .map(|tile| {
                TensorBucketAddConfig::construct(cb, &format!("{name}_positive_fold_{tile}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let negative_folds = (0..tile_count)
            .map(|tile| {
                TensorBucketAddConfig::construct(cb, &format!("{name}_negative_fold_{tile}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (side, folds, buckets) in [
            ("positive", &positive_folds, &buckets),
            ("negative", &negative_folds, &buckets),
        ] {
            for (tile, (fold, bucket)) in folds.iter().zip(buckets).enumerate() {
                for byte in 0..10 {
                    let previous = if tile == 0 {
                        E::BaseField::ZERO.expr()
                    } else {
                        folds[tile - 1].output[byte].expr()
                    };
                    cb.require_equal(
                        || format!("{name}_{side}_fold_input_{tile}_{byte}"),
                        fold.accumulator[byte].expr(),
                        previous,
                    )?;
                    let bucket_byte = if side == "positive" {
                        bucket.positive[byte]
                    } else {
                        bucket.negative[byte]
                    };
                    cb.require_equal(
                        || format!("{name}_{side}_fold_bucket_{tile}_{byte}"),
                        fold.addend[byte].expr(),
                        bucket_byte.expr(),
                    )?;
                }
            }
        }
        let rescale =
            TensorSignedLimbRescaleConfig::construct(cb, &format!("{name}_rescale"), shift)?;
        let difference = TensorBucketDifferenceConfig::construct(
            cb,
            &format!("{name}_difference"),
            &positive_folds.last().expect("nonempty fold chain").output,
            &negative_folds.last().expect("nonempty fold chain").output,
            &rescale.accumulator,
        )?;
        Ok(Self {
            buckets,
            positive_folds,
            negative_folds,
            difference,
            rescale,
            k,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        left: &[i32],
        right: &[i32],
    ) -> Result<(i64, i64), String> {
        if left.len() != self.k || right.len() != self.k {
            return Err("production MatMul cell shape mismatch".into());
        }
        let trace = ceno_emul::tensor::production::signed_dot_byte_limb_rescaled(
            left,
            right,
            self.rescale.shift,
        )
        .map_err(|e| e.to_string())?;
        let mut positive = [0u8; 10];
        let mut negative = [0u8; 10];
        for (tile_index, (tile, ((bucket, positive_fold), negative_fold))) in trace
            .tiles
            .iter()
            .zip(
                self.buckets
                    .iter()
                    .zip(&self.positive_folds)
                    .zip(&self.negative_folds),
            )
            .enumerate()
        {
            let start = tile_index * ceno_emul::tensor::production::PRODUCTION_K_TILE;
            let end = (start + ceno_emul::tensor::production::PRODUCTION_K_TILE).min(self.k);
            bucket.assign(instance, lkm, &left[start..end], &right[start..end])?;
            positive = positive_fold.assign(instance, lkm, &positive, &tile.positive_base256)?;
            negative = negative_fold.assign(instance, lkm, &negative, &tile.negative_base256)?;
        }
        self.difference.assign(
            instance,
            lkm,
            trace.positive,
            trace.negative,
            trace.signed_sum,
        )?;
        self.rescale.assign(instance, lkm, trace.signed_sum)
    }
}

impl<E: ExtensionField> TensorSignedRemainder<E> {
    fn construct(cb: &mut CircuitBuilder<E>, name: &str) -> Result<Self, ZKVMError> {
        let sign = cb.create_witin(|| format!("{name}_sign"));
        let magnitude = cb.create_witin(|| format!("{name}_magnitude"));
        cb.assert_bit(|| format!("{name}_sign_bit"), sign.expr())?;
        // 2*magnitude-sign < 2^16 gives positive <=32767 and negative <=32768.
        cb.assert_const_range(
            || format!("{name}_canonical_range"),
            magnitude.expr() * 2 - sign.expr(),
            16,
        )?;
        let value = (E::BaseField::ONE.expr() - sign.expr() * 2) * magnitude.expr();
        Ok(Self {
            sign,
            magnitude,
            value,
        })
    }

    pub fn expr(&self) -> Expression<E> {
        self.value.clone()
    }

    pub fn assign(&self, instance: &mut [E::BaseField], lkm: &mut LkMultiplicity, value: i32) {
        let sign = u64::from(value < 0);
        let magnitude = i64::from(value).unsigned_abs();
        set_val!(instance, self.sign, sign);
        set_val!(instance, self.magnitude, magnitude);
        lkm.assert_const_range(2 * magnitude - sign, 16);
    }
}

/// Circuit columns and equations for the bounded Gate-2 arithmetic core.
/// Boundary bus reads/writes are added by `TensorMatMulCoreInstruction`; this
/// type owns the reusable arithmetic relation so construction can be tested in
/// isolation before syscall registration.
#[derive(Debug)]
pub struct TensorGate2AirConfig<E: ExtensionField> {
    pub inputs: [TensorSignedWord<E>; 6],
    pub weights: [TensorSignedWord<E>; 6],
    pub outputs: [TensorSignedWord<E>; 4],
    pub remainders: [TensorSignedRemainder<E>; 4],
    pub commitment: [WitIn; 8],
    /// Production-safe replacement for the former direct-field dot equations.
    pub production_cells: [TensorProductionMatMulCellConfig<E>; 4],
}

#[derive(Debug)]
pub struct TensorMatMulCoreConfig<E: ExtensionField> {
    pub cycle: WitIn,
    pub call_id: WitIn,
    pub profile: WitIn,
    pub signature_id: WitIn,
    pub tensor_id: WitIn,
    pub tile_id: WitIn,
    pub air: TensorGate2AirConfig<E>,
}

impl<E: ExtensionField> TensorMatMulCoreConfig<E> {
    /// Construct the pure arithmetic side of the split tensor syscall. It has
    /// no guest-memory columns: only the two ordered TensorState records.
    pub fn construct(cb: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        let cycle = cb.create_witin(|| "tensor_cycle");
        let call_id = cb.create_witin(|| "tensor_call_id");
        let profile = cb.create_witin(|| "tensor_profile");
        let signature_id = cb.create_witin(|| "tensor_signature_id");
        let tensor_id = cb.create_witin(|| "tensor_id");
        let tile_id = cb.create_witin(|| "tensor_tile_id");
        cb.require_equal(
            || "tensor_profile_is_gate2_v1",
            profile.expr(),
            E::BaseField::from_u32(GATE2_LINEAR_COMMITMENT_V1).expr(),
        )?;
        cb.require_equal(
            || "tensor_signature_is_2x3x2",
            signature_id.expr(),
            E::BaseField::from_u32(ceno_emul::TENSOR_SIGNATURE_2X3X2).expr(),
        )?;
        // Gate 2 uses the existing dynamic range table, whose supported
        // width is 18 bits. Keep this bounded fixture at u16; production IDs
        // will use explicit limbs rather than an unsupported 32-bit lookup.
        cb.assert_const_range(|| "tensor_id_gate2_u16", tensor_id.expr(), 16)?;
        cb.assert_const_range(|| "tensor_tile_id_gate2_u16", tile_id.expr(), 16)?;

        let air = TensorGate2AirConfig::construct(cb, tensor_id.expr(), tile_id.expr())?;
        let zeros4 = || std::array::from_fn(|_| E::BaseField::ZERO.expr());
        cb.read_record(
            || "tensor_state_in",
            crate::structs::RAMType::Custom,
            tensor_state_record(TensorStateRecord {
                cycle: cycle.expr(),
                call_id: call_id.expr(),
                phase: TENSOR_STATE_PHASE_INPUT,
                profile: profile.expr(),
                signature_id: signature_id.expr(),
                tensor_id: tensor_id.expr(),
                tile_id: tile_id.expr(),
                values: std::array::from_fn(|i| air.inputs[i].expr()),
                commitment: std::array::from_fn(|i| air.commitment[i].expr()),
                outputs: zeros4(),
                remainders: zeros4(),
            }),
        )?;
        cb.write_record(
            || "tensor_state_out",
            crate::structs::RAMType::Custom,
            tensor_state_record(TensorStateRecord {
                cycle: cycle.expr(),
                call_id: call_id.expr(),
                phase: TENSOR_STATE_PHASE_OUTPUT,
                profile: profile.expr(),
                signature_id: signature_id.expr(),
                tensor_id: tensor_id.expr(),
                tile_id: tile_id.expr(),
                values: std::array::from_fn(|i| air.inputs[i].expr()),
                commitment: std::array::from_fn(|i| air.commitment[i].expr()),
                outputs: std::array::from_fn(|i| air.outputs[i].expr()),
                // Remainders are core-local arithmetic witnesses. The syscall
                // boundary exposes only the guest-visible quotient words.
                remainders: zeros4(),
            }),
        )?;
        Ok(Self {
            cycle,
            call_id,
            profile,
            signature_id,
            tensor_id,
            tile_id,
            air,
        })
    }
}

impl<E: ExtensionField> TensorGate2AirConfig<E> {
    pub fn construct(
        cb: &mut CircuitBuilder<E>,
        tensor_id: Expression<E>,
        tile_id: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        let inputs: [_; 6] = (0..6)
            .map(|i| TensorSignedWord::construct(cb, &format!("tensor_input_{i}"), 9))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .expect("six input columns");
        let weights: [_; 6] = (0..6)
            .map(|i| TensorSignedWord::construct(cb, &format!("tensor_weight_{i}"), 17))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .expect("six weight columns");
        let outputs: [_; 4] = (0..4)
            .map(|i| TensorSignedWord::construct(cb, &format!("tensor_output_{i}"), 16))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .expect("four output columns");
        let remainders: [_; 4] = (0..4)
            .map(|i| TensorSignedRemainder::construct(cb, &format!("tensor_remainder_{i}")))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .expect("four remainder columns");
        let commitment =
            std::array::from_fn(|i| cb.create_witin(|| format!("tensor_commitment_{i}")));

        let domain = E::BaseField::from_u64(0x4741_5432).expr();
        for lane in 0..8 {
            let lane_one = (lane + 1) as u64;
            let expected = weights.iter().enumerate().fold(
                domain.clone()
                    + 17 * GATE2_LINEAR_COMMITMENT_V1 as u64
                    + tensor_id.clone() * 31
                    + tile_id.clone() * 43
                    + 59 * TENSOR_GATE2_WEIGHTS as u64
                    + 71 * lane_one,
                |acc, (index, weight)| {
                    acc + weight.expr() * (97 + lane_one * 19 + index as u64 * 23)
                },
            );
            cb.require_equal(
                || format!("tensor_commitment_lane_{lane}"),
                commitment[lane].expr(),
                expected,
            )?;
        }

        let production_cells: [_; 4] = (0..4)
            .map(|output_index| {
                TensorProductionMatMulCellConfig::construct(
                    cb,
                    &format!("tensor_production_cell_{output_index}"),
                    3,
                    TENSOR_GATE2_SHIFT,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .expect("four production cells");
        for row in 0..2 {
            for col in 0..2 {
                let output_index = row * 2 + col;
                let cell = &production_cells[output_index];
                for k in 0..3 {
                    for (side, product_word, boundary) in [
                        (
                            "input",
                            &cell.buckets[0].products[k].left,
                            &inputs[row * 3 + k],
                        ),
                        (
                            "weight",
                            &cell.buckets[0].products[k].right,
                            &weights[k * 2 + col],
                        ),
                    ] {
                        let magnitude = product_word
                            .iter()
                            .enumerate()
                            .fold(E::BaseField::ZERO.expr(), |sum, (i, byte)| {
                                sum + byte.expr() * (1u64 << (8 * i))
                            });
                        let sign = if side == "input" {
                            cell.buckets[0].products[k].left_sign.expr()
                        } else {
                            cell.buckets[0].products[k].right_sign.expr()
                        };
                        cb.require_equal(
                            || format!("tensor_cell_{output_index}_{side}_{k}_shared"),
                            (E::BaseField::ONE.expr() - sign * 2) * magnitude,
                            boundary.expr(),
                        )?;
                    }
                }
                let signed_nibbles = |word: &TensorSignedI64Nibbles| {
                    let magnitude = word
                        .magnitude
                        .iter()
                        .enumerate()
                        .fold(E::BaseField::ZERO.expr(), |sum, (i, nibble)| {
                            sum + nibble.expr() * (1u64 << (4 * i))
                        });
                    (E::BaseField::ONE.expr() - word.sign.expr() * 2) * magnitude
                };
                cb.require_equal(
                    || format!("tensor_production_output_{row}_{col}"),
                    signed_nibbles(&cell.rescale.quotient),
                    outputs[output_index].expr(),
                )?;
                cb.require_equal(
                    || format!("tensor_production_remainder_{row}_{col}"),
                    signed_nibbles(&cell.rescale.remainder),
                    remainders[output_index].expr(),
                )?;
            }
        }

        Ok(Self {
            inputs,
            weights,
            outputs,
            remainders,
            commitment,
            production_cells,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        input: &[i32; 6],
        witness: &TensorGate2CoreWitness,
    ) -> Result<(), String> {
        for (config, value) in self.inputs.iter().zip(input) {
            config.assign(instance, lkm, *value);
        }
        for (config, value) in self.weights.iter().zip(witness.weights) {
            config.assign(instance, lkm, value);
        }
        for (config, value) in self.outputs.iter().zip(witness.outputs) {
            config.assign(instance, lkm, value);
        }
        for (config, value) in self.remainders.iter().zip(witness.remainders) {
            config.assign(instance, lkm, value);
        }
        for (column, value) in self.commitment.iter().zip(witness.commitment) {
            set_val!(instance, *column, value as u64);
        }
        for row in 0..2 {
            for col in 0..2 {
                let output_index = row * 2 + col;
                let left = [input[row * 3], input[row * 3 + 1], input[row * 3 + 2]];
                let right = [
                    witness.weights[col],
                    witness.weights[2 + col],
                    witness.weights[4 + col],
                ];
                let actual =
                    self.production_cells[output_index].assign(instance, lkm, &left, &right)?;
                if actual
                    != (
                        i64::from(witness.outputs[output_index]),
                        i64::from(witness.remainders[output_index]),
                    )
                {
                    return Err("production cell/reference mismatch".into());
                }
            }
        }
        Ok(())
    }
}

/// Host assignment for the one-row Gate-2 arithmetic chip. This is built only
/// from the proof context: private weights never come from the syscall journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorGate2CoreWitness {
    pub weights: [i32; TENSOR_GATE2_WEIGHTS],
    pub commitment: [u32; 8],
    pub outputs: [i32; TENSOR_GATE2_OUTPUTS],
    pub remainders: [i32; TENSOR_GATE2_OUTPUTS],
}

/// Production raw-hints core. All K activations are carried on the ordered
/// custom record; K private weights are opened only from the proof context.
/// This proves arithmetic and ordering, not model-root authentication.
pub struct TensorProductionRawCoreConfig<E: ExtensionField, const K: usize> {
    pub cycle: WitIn,
    pub call_id: WitIn,
    pub profile: WitIn,
    pub signature_id: WitIn,
    pub tensor_id: WitIn,
    pub first_tile_id: WitIn,
    pub input_raw: [[WitIn; 2]; K],
    pub input_neg_carry: [WitIn; K],
    pub input: [TensorSignedWord<E>; K],
    pub output: TensorSignedWord<E>,
    pub remainder: TensorSignedI64Nibbles,
    pub cell: TensorProductionMatMulCellConfig<E>,
}

/// One physical K=1024 row of a production MatMul.  The row is internal to the
/// logical ecall: it consumes one ordered activation slice, opens exactly one
/// raw weight tile from `TensorWitnessProvider`, and exports only bounded sign
/// buckets to the finalize chip.  `weight_checksum` is a circuit-native
/// integrity check for accidental/tampered row data; it is deliberately not a
/// model commitment (CommittedHints remains a future gate).
pub struct TensorProductionTileCoreConfig<
    E: ExtensionField,
    const K: usize = { ceno_emul::tensor::production::PRODUCTION_K_TILE },
> {
    pub cycle: WitIn,
    pub call_id: WitIn,
    pub profile: WitIn,
    pub signature_id: WitIn,
    pub tensor_id: WitIn,
    pub first_tile_id: WitIn,
    pub global_tile_id: WitIn,
    pub tile_position: WitIn,
    pub input_raw: [[WitIn; 2]; K],
    pub input_neg_carry: [WitIn; K],
    pub input: [TensorSignedWord<E>; K],
    pub bucket: TensorSignedDotBucketConfig<E>,
    pub weight_checksum: WitIn,
}

/// Small ordered fold/finalize row.  `TILES` is 4 for hidden projections and
/// 11 for intermediate projections; Gate-5's diagnostic signature uses one
/// tile to preserve this relation with a compact E2E.  It checks all physical rows belong to
/// the same logical call, folds their bounded buckets without overflow, and
/// performs the one canonical signed rescale used by the guest-visible output.
pub struct TensorProductionFinalizeCoreConfig<E: ExtensionField, const K: usize, const TILES: usize>
{
    pub cycle: WitIn,
    pub call_id: WitIn,
    pub profile: WitIn,
    pub signature_id: WitIn,
    pub tensor_id: WitIn,
    pub first_tile_id: WitIn,
    pub checksums: [WitIn; TILES],
    pub positive: [[WitIn; 10]; TILES],
    pub negative: [[WitIn; 10]; TILES],
    pub positive_folds: [TensorBucketAddConfig<E>; TILES],
    pub negative_folds: [TensorBucketAddConfig<E>; TILES],
    pub difference: TensorBucketDifferenceConfig<E>,
    pub rescale: TensorSignedLimbRescaleConfig<E>,
    pub output: TensorSignedWord<E>,
}

pub fn production_tile_input_record<E: ExtensionField>(
    cycle: Expression<E>,
    call_id: Expression<E>,
    profile: Expression<E>,
    signature_id: Expression<E>,
    tensor_id: Expression<E>,
    first_tile_id: Expression<E>,
    global_tile_id: Expression<E>,
    position: Expression<E>,
    input_raw: impl IntoIterator<Item = Expression<E>>,
) -> Vec<Expression<E>> {
    [
        CustomRWTag::TensorState.expr::<E>(),
        cycle,
        call_id,
        E::BaseField::from_u64(TENSOR_STATE_PHASE_INPUT).expr(),
        profile,
        signature_id,
        tensor_id,
        first_tile_id,
        global_tile_id,
        position,
    ]
    .into_iter()
    .chain(input_raw)
    .collect()
}

pub fn production_tile_bucket_record<E: ExtensionField>(
    cycle: Expression<E>,
    call_id: Expression<E>,
    profile: Expression<E>,
    signature_id: Expression<E>,
    tensor_id: Expression<E>,
    first_tile_id: Expression<E>,
    global_tile_id: Expression<E>,
    position: Expression<E>,
    checksum: Expression<E>,
    positive: impl IntoIterator<Item = Expression<E>>,
    negative: impl IntoIterator<Item = Expression<E>>,
) -> Vec<Expression<E>> {
    [
        CustomRWTag::TensorState.expr::<E>(),
        cycle,
        call_id,
        E::BaseField::from_u64(TENSOR_STATE_PHASE_OUTPUT).expr(),
        profile,
        signature_id,
        tensor_id,
        first_tile_id,
        global_tile_id,
        position,
        checksum,
    ]
    .into_iter()
    .chain(positive)
    .chain(negative)
    .collect()
}

fn production_checksum_values(values: &[i32]) -> u64 {
    // BabyBear-safe linear recurrence. This is an internal row-consistency
    // checksum, not collision-resistant model authentication.
    const MODULUS: u64 = 2_013_265_921;
    values
        .iter()
        .flat_map(|v| v.unsigned_abs().to_le_bytes())
        .fold(0x5449_4c45u64, |acc, byte| {
            (acc * 257 + u64::from(byte) + 1) % MODULUS
        })
}

impl<E: ExtensionField, const K: usize> TensorProductionTileCoreConfig<E, K> {
    pub fn construct(cb: &mut CircuitBuilder<E>) -> Result<Self, ZKVMError> {
        if K == 0 || K > ceno_emul::tensor::production::PRODUCTION_K_TILE {
            return Err(ZKVMError::InvalidWitness(
                "production tile K outside supported physical domain".into(),
            ));
        }
        let cycle = cb.create_witin(|| "production_tile_cycle");
        let call_id = cb.create_witin(|| "production_tile_call_id");
        let profile = cb.create_witin(|| "production_tile_profile");
        let signature_id = cb.create_witin(|| "production_tile_signature");
        let tensor_id = cb.create_witin(|| "production_tile_tensor");
        let first_tile_id = cb.create_witin(|| "production_tile_first");
        let global_tile_id = cb.create_witin(|| "production_tile_global");
        let tile_position = cb.create_witin(|| "production_tile_position");
        cb.require_equal(
            || "production tile raw profile",
            profile.expr(),
            E::BaseField::from_u32(
                ceno_emul::tensor::production::PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1,
            )
            .expr(),
        )?;
        cb.require_equal(
            || "production tile ordered id",
            global_tile_id.expr(),
            first_tile_id.expr() + tile_position.expr(),
        )?;
        let input: [TensorSignedWord<E>; K] = (0..K)
            .map(|i| TensorSignedWord::construct(cb, &format!("production_tile_input_{i}"), 32))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap_or_else(|_| panic!("fixed tile"));
        let input_raw = std::array::from_fn(|i| {
            std::array::from_fn(|j| {
                cb.create_witin(|| format!("production_tile_input_raw_{i}_{j}"))
            })
        });
        let input_neg_carry =
            std::array::from_fn(|i| cb.create_witin(|| format!("production_tile_input_carry_{i}")));
        for (i, ((raw, signed), carry)) in input_raw
            .iter()
            .zip(&input)
            .zip(&input_neg_carry)
            .enumerate()
        {
            for (j, limb) in raw.iter().enumerate() {
                cb.assert_const_range(
                    || format!("production_tile_raw16_{i}_{j}"),
                    limb.expr(),
                    16,
                )?;
            }
            cb.assert_bit(|| format!("production_tile_carry_bit_{i}"), carry.expr())?;
            let positive = E::BaseField::ONE.expr() - signed.sign.expr();
            cb.require_zero(
                || format!("production_tile_pos_lo_{i}"),
                positive.clone() * (raw[0].expr() - signed.magnitude[0].expr()),
            )?;
            cb.require_zero(
                || format!("production_tile_pos_hi_{i}"),
                positive * (raw[1].expr() - signed.magnitude[1].expr()),
            )?;
            cb.require_zero(
                || format!("production_tile_neg_lo_{i}"),
                signed.sign.expr()
                    * (raw[0].expr() + signed.magnitude[0].expr() - carry.expr() * (1u64 << 16)),
            )?;
            cb.require_zero(
                || format!("production_tile_neg_hi_{i}"),
                signed.sign.expr()
                    * (raw[1].expr() + signed.magnitude[1].expr() + carry.expr() - (1u64 << 16)),
            )?;
        }
        let bucket = TensorSignedDotBucketConfig::construct(cb, "production_tile_bucket", K)?;
        for (boundary, product) in input.iter().zip(&bucket.products) {
            let magnitude = product
                .left
                .iter()
                .enumerate()
                .fold(E::BaseField::ZERO.expr(), |sum, (i, byte)| {
                    sum + byte.expr() * (1u64 << (8 * i))
                });
            cb.require_equal(
                || "production tile signed input",
                boundary.expr(),
                (E::BaseField::ONE.expr() - product.left_sign.expr() * 2) * magnitude,
            )?;
        }
        let weight_checksum = cb.create_witin(|| "production_tile_weight_checksum");
        let checksum_expr = bucket
            .products
            .iter()
            .flat_map(|p| p.right.iter())
            .fold(E::BaseField::from_u64(0x5449_4c45).expr(), |acc, byte| {
                acc * 257 + byte.expr() + E::BaseField::ONE.expr()
            });
        cb.require_equal(
            || "production tile weight checksum",
            weight_checksum.expr(),
            checksum_expr,
        )?;
        cb.read_record(
            || "production tile input",
            RAMType::Custom,
            production_tile_input_record(
                cycle.expr(),
                call_id.expr(),
                profile.expr(),
                signature_id.expr(),
                tensor_id.expr(),
                first_tile_id.expr(),
                global_tile_id.expr(),
                tile_position.expr(),
                input_raw.iter().flat_map(|x| x.iter().map(|v| v.expr())),
            ),
        )?;
        cb.write_record(
            || "production tile bucket",
            RAMType::Custom,
            production_tile_bucket_record(
                cycle.expr(),
                call_id.expr(),
                profile.expr(),
                signature_id.expr(),
                tensor_id.expr(),
                first_tile_id.expr(),
                global_tile_id.expr(),
                tile_position.expr(),
                weight_checksum.expr(),
                bucket.positive.iter().map(|v| v.expr()),
                bucket.negative.iter().map(|v| v.expr()),
            ),
        )?;
        Ok(Self {
            cycle,
            call_id,
            profile,
            signature_id,
            tensor_id,
            first_tile_id,
            global_tile_id,
            tile_position,
            input_raw,
            input_neg_carry,
            input,
            bucket,
            weight_checksum,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        provider: Option<&dyn TensorWitnessProvider>,
        desc: ceno_emul::tensor::production::ProductionMatMulCellDesc,
        position: usize,
        cycle: u64,
        call_id: u32,
        input: &[i32],
    ) -> Result<(), String> {
        if input.len() != K || position >= desc.tile_count as usize {
            return Err("production tile shape/position mismatch".into());
        }
        let provider =
            provider.ok_or_else(|| "tensor proof context is not installed".to_string())?;
        let tile_id = desc
            .first_tile_id
            .checked_add(position as u32)
            .ok_or("production tile id overflow")?;
        let opening = provider
            .read_tile(desc.weight_tensor_id, tile_id)
            .map_err(|e| e.to_string())?;
        if opening.tensor_id != desc.weight_tensor_id || opening.tile_id != tile_id {
            return Err("production raw tile order mismatch".into());
        }
        if ceno_emul::tensor::commit_tile(opening.tensor_id, opening.tile_id, &opening.bytes)
            != opening.root
        {
            return Err("production raw tile checksum mismatch".into());
        }
        let mut weights = decode_i32_le(&opening.bytes).map_err(|e| e.to_string())?;
        if weights.len() > K || (position + 1 < desc.tile_count as usize && weights.len() != K) {
            return Err("production raw tile length mismatch".into());
        }
        weights.resize(K, 0);
        for (column, value) in [
            (self.cycle, cycle),
            (self.call_id, call_id as u64),
            (
                self.profile,
                ceno_emul::tensor::production::PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1 as u64,
            ),
            (self.signature_id, desc.signature.id() as u64),
            (self.tensor_id, desc.weight_tensor_id as u64),
            (self.first_tile_id, desc.first_tile_id as u64),
            (self.global_tile_id, tile_id as u64),
            (self.tile_position, position as u64),
        ] {
            set_val!(instance, column, value);
        }
        for (((signed, raw), carry), &value) in self
            .input
            .iter()
            .zip(&self.input_raw)
            .zip(&self.input_neg_carry)
            .zip(input)
        {
            signed.assign(instance, lkm, value);
            for (column, limb) in raw.iter().zip([value as u32 & 0xffff, value as u32 >> 16]) {
                set_val!(instance, *column, limb as u64);
                lkm.assert_const_range(limb as u64, 16);
            }
            set_val!(
                instance,
                *carry,
                u64::from((value.unsigned_abs() & 0xffff) != 0)
            );
        }
        self.bucket.assign(instance, lkm, input, &weights)?;
        let weight_checksum = production_checksum_values(&weights);
        set_val!(instance, self.weight_checksum, weight_checksum);
        if std::env::var_os("CENO_TENSOR_E2E_RW_TRACE").is_some() {
            tracing::info!(
                target: "ceno_gpu::tensor_record_path",
                role = "tile_witness",
                record_time = cycle,
                record_slot = position,
                call_id,
                signature = desc.signature.id(),
                tensor_id = desc.weight_tensor_id,
                first_tile = desc.first_tile_id,
                tile_id,
                input_checksum = production_checksum_values(input),
                weight_checksum,
                "Gate-5 tile record witness identity/value"
            );
        }
        Ok(())
    }
}

impl<E: ExtensionField, const K: usize, const TILES: usize>
    TensorProductionFinalizeCoreConfig<E, K, TILES>
{
    pub fn construct(cb: &mut CircuitBuilder<E>, shift: u32) -> Result<Self, ZKVMError> {
        if !matches!(TILES, 1 | 4 | 11) {
            return Err(ZKVMError::InvalidWitness(
                "production finalize tile count must be 1, 4, or 11".into(),
            ));
        }
        let cycle = cb.create_witin(|| "production_finalize_cycle");
        let call_id = cb.create_witin(|| "production_finalize_call_id");
        let profile = cb.create_witin(|| "production_finalize_profile");
        let signature_id = cb.create_witin(|| "production_finalize_signature");
        let tensor_id = cb.create_witin(|| "production_finalize_tensor");
        let first_tile_id = cb.create_witin(|| "production_finalize_first_tile");
        cb.require_equal(
            || "production finalize raw profile",
            profile.expr(),
            E::BaseField::from_u32(
                ceno_emul::tensor::production::PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1,
            )
            .expr(),
        )?;
        let checksums = std::array::from_fn(|i| {
            cb.create_witin(|| format!("production_finalize_checksum_{i}"))
        });
        let positive = std::array::from_fn(|tile| {
            std::array::from_fn(|byte| {
                cb.create_witin(|| format!("production_finalize_positive_{tile}_{byte}"))
            })
        });
        let negative = std::array::from_fn(|tile| {
            std::array::from_fn(|byte| {
                cb.create_witin(|| format!("production_finalize_negative_{tile}_{byte}"))
            })
        });
        for (side, buckets) in [("positive", &positive), ("negative", &negative)] {
            for (tile, bucket) in buckets.iter().enumerate() {
                for (byte, value) in bucket.iter().enumerate() {
                    cb.assert_const_range(
                        || format!("production_finalize_{side}_{tile}_{byte}"),
                        value.expr(),
                        8,
                    )?;
                }
            }
        }
        let positive_folds: [TensorBucketAddConfig<E>; TILES] = (0..TILES)
            .map(|i| {
                TensorBucketAddConfig::construct(
                    cb,
                    &format!("production_finalize_positive_fold_{i}"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap_or_else(|_| panic!("fixed folds"));
        let negative_folds: [TensorBucketAddConfig<E>; TILES] = (0..TILES)
            .map(|i| {
                TensorBucketAddConfig::construct(
                    cb,
                    &format!("production_finalize_negative_fold_{i}"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap_or_else(|_| panic!("fixed folds"));
        for (side, folds, buckets) in [
            ("positive", &positive_folds, &positive),
            ("negative", &negative_folds, &negative),
        ] {
            for tile in 0..TILES {
                for byte in 0..10 {
                    let prior = if tile == 0 {
                        E::BaseField::ZERO.expr()
                    } else {
                        folds[tile - 1].output[byte].expr()
                    };
                    cb.require_equal(
                        || format!("production_finalize_{side}_prior_{tile}_{byte}"),
                        folds[tile].accumulator[byte].expr(),
                        prior,
                    )?;
                    cb.require_equal(
                        || format!("production_finalize_{side}_bucket_{tile}_{byte}"),
                        folds[tile].addend[byte].expr(),
                        buckets[tile][byte].expr(),
                    )?;
                }
            }
        }
        let rescale =
            TensorSignedLimbRescaleConfig::construct(cb, "production_finalize_rescale", shift)?;
        let difference = TensorBucketDifferenceConfig::construct(
            cb,
            "production_finalize_difference",
            &positive_folds[TILES - 1].output,
            &negative_folds[TILES - 1].output,
            &rescale.accumulator,
        )?;
        let output = TensorSignedWord::construct(cb, "production_finalize_output", 32)?;
        let quotient_expr = rescale
            .quotient
            .magnitude
            .iter()
            .enumerate()
            .fold(E::BaseField::ZERO.expr(), |sum, (i, digit)| {
                sum + digit.expr() * (1u64 << (4 * i))
            });
        cb.require_equal(
            || "production finalize output quotient",
            output.expr(),
            (E::BaseField::ONE.expr() - rescale.quotient.sign.expr() * 2) * quotient_expr,
        )?;
        for tile in 0..TILES {
            cb.read_record(
                || format!("production finalize bucket {tile}"),
                RAMType::Custom,
                production_tile_bucket_record(
                    cycle.expr(),
                    call_id.expr(),
                    profile.expr(),
                    signature_id.expr(),
                    tensor_id.expr(),
                    first_tile_id.expr(),
                    first_tile_id.expr() + E::BaseField::from_usize(tile).expr(),
                    E::BaseField::from_usize(tile).expr(),
                    checksums[tile].expr(),
                    positive[tile].iter().map(|v| v.expr()),
                    negative[tile].iter().map(|v| v.expr()),
                ),
            )?;
        }
        cb.write_record(
            || "production finalize output",
            RAMType::Custom,
            production_raw_state_record(
                cycle.expr(),
                call_id.expr(),
                TENSOR_STATE_PHASE_OUTPUT,
                profile.expr(),
                signature_id.expr(),
                tensor_id.expr(),
                first_tile_id.expr(),
                std::iter::empty(),
                output.expr(),
            ),
        )?;
        Ok(Self {
            cycle,
            call_id,
            profile,
            signature_id,
            tensor_id,
            first_tile_id,
            checksums,
            positive,
            negative,
            positive_folds,
            negative_folds,
            difference,
            rescale,
            output,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        provider: Option<&dyn TensorWitnessProvider>,
        desc: ceno_emul::tensor::production::ProductionMatMulCellDesc,
        cycle: u64,
        call_id: u32,
        input: &[i32],
    ) -> Result<(i32, i64), String> {
        if desc.tile_count as usize != TILES || input.len() != desc.signature.k() {
            return Err("production finalize descriptor shape mismatch".into());
        }
        let provider =
            provider.ok_or_else(|| "tensor proof context is not installed".to_string())?;
        for (column, value) in [
            (self.cycle, cycle),
            (self.call_id, call_id as u64),
            (
                self.profile,
                ceno_emul::tensor::production::PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1 as u64,
            ),
            (self.signature_id, desc.signature.id() as u64),
            (self.tensor_id, desc.weight_tensor_id as u64),
            (self.first_tile_id, desc.first_tile_id as u64),
        ] {
            set_val!(instance, column, value);
        }
        let mut positive_total = [0u8; 10];
        let mut negative_total = [0u8; 10];
        let mut positive_u128 = 0u128;
        let mut negative_u128 = 0u128;
        for tile in 0..TILES {
            let tile_id = desc
                .first_tile_id
                .checked_add(tile as u32)
                .ok_or("production tile id overflow")?;
            let opening = provider
                .read_tile(desc.weight_tensor_id, tile_id)
                .map_err(|e| e.to_string())?;
            if opening.tensor_id != desc.weight_tensor_id || opening.tile_id != tile_id {
                return Err("production finalize tile order mismatch".into());
            }
            if ceno_emul::tensor::commit_tile(opening.tensor_id, opening.tile_id, &opening.bytes)
                != opening.root
            {
                return Err("production finalize checksum mismatch".into());
            }
            let mut weights = decode_i32_le(&opening.bytes).map_err(|e| e.to_string())?;
            // The compact K64 diagnostic is a real physical K64 tile, while
            // production signatures retain the normal 1024-wide tile.  The
            // finalize witness must use exactly the same physical tile domain
            // as the tile-record producer; widening K64 here changed the
            // bucket record and broke the custom-RAM product check.
            let tile_width = K.min(ceno_emul::tensor::production::PRODUCTION_K_TILE);
            if weights.len() > tile_width || (tile + 1 < TILES && weights.len() != tile_width) {
                return Err("production finalize tile length mismatch".into());
            }
            weights.resize(tile_width, 0);
            let start = tile * tile_width;
            let end = (start + tile_width).min(input.len());
            let mut tile_input = input[start..end].to_vec();
            tile_input.resize(tile_width, 0);
            let trace =
                ceno_emul::tensor::production::signed_dot_byte_limb_tile(&tile_input, &weights)
                    .map_err(|e| e.to_string())?;
            set_val!(
                instance,
                self.checksums[tile],
                production_checksum_values(&weights)
            );
            for byte in 0..10 {
                set_val!(
                    instance,
                    self.positive[tile][byte],
                    trace.positive_base256[byte] as u64
                );
                lkm.assert_const_range(trace.positive_base256[byte] as u64, 8);
                set_val!(
                    instance,
                    self.negative[tile][byte],
                    trace.negative_base256[byte] as u64
                );
                lkm.assert_const_range(trace.negative_base256[byte] as u64, 8);
            }
            positive_total = self.positive_folds[tile].assign(
                instance,
                lkm,
                &positive_total,
                &trace.positive_base256,
            )?;
            negative_total = self.negative_folds[tile].assign(
                instance,
                lkm,
                &negative_total,
                &trace.negative_base256,
            )?;
            positive_u128 = positive_u128
                .checked_add(trace.positive)
                .ok_or("production positive overflow")?;
            negative_u128 = negative_u128
                .checked_add(trace.negative)
                .ok_or("production negative overflow")?;
            if std::env::var_os("CENO_TENSOR_E2E_RW_TRACE").is_some() {
                tracing::info!(
                    target: "ceno_gpu::tensor_record_path",
                    role = "finalize_bucket_witness",
                    record_time = cycle,
                    record_slot = tile,
                    call_id,
                    signature = desc.signature.id(),
                    tensor_id = desc.weight_tensor_id,
                    first_tile = desc.first_tile_id,
                    tile_id,
                    input_checksum = production_checksum_values(&tile_input),
                    weight_checksum = production_checksum_values(&weights),
                    positive = ?trace.positive_base256,
                    negative = ?trace.negative_base256,
                    "Gate-5 finalize bucket record identity/value"
                );
            }
        }
        let signed = i64::try_from(
            i128::try_from(positive_u128).map_err(|_| "production positive i128")?
                - i128::try_from(negative_u128).map_err(|_| "production negative i128")?,
        )
        .map_err(|_| "production accumulator outside i64")?;
        self.difference
            .assign(instance, lkm, positive_u128, negative_u128, signed)?;
        let (q, r) = self.rescale.assign(instance, lkm, signed)?;
        let output = i32::try_from(q).map_err(|_| "production output outside i32")?;
        self.output.assign(instance, lkm, output);
        if std::env::var_os("CENO_TENSOR_E2E_RW_TRACE").is_some() {
            tracing::info!(
                target: "ceno_gpu::tensor_record_path",
                role = "finalize_output_witness",
                record_time = cycle,
                record_slot = desc.first_tile_id,
                call_id,
                signature = desc.signature.id(),
                tensor_id = desc.weight_tensor_id,
                first_tile = desc.first_tile_id,
                positive_total = ?positive_total,
                negative_total = ?negative_total,
                output,
                remainder = r,
                "Gate-5 finalize output record identity/value"
            );
        }
        Ok((output, r))
    }
}

impl<E: ExtensionField, const K: usize> TensorProductionRawCoreConfig<E, K> {
    pub fn construct(cb: &mut CircuitBuilder<E>, shift: u32) -> Result<Self, ZKVMError> {
        let cycle = cb.create_witin(|| "production_raw_cycle");
        let call_id = cb.create_witin(|| "production_raw_call_id");
        let profile = cb.create_witin(|| "production_raw_profile");
        let signature_id = cb.create_witin(|| "production_raw_signature");
        let tensor_id = cb.create_witin(|| "production_raw_tensor_id");
        let first_tile_id = cb.create_witin(|| "production_raw_first_tile");
        cb.require_equal(
            || "production raw-hints profile",
            profile.expr(),
            E::BaseField::from_u32(
                ceno_emul::tensor::production::PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1,
            )
            .expr(),
        )?;
        let input: [TensorSignedWord<E>; K] = (0..K)
            .map(|i| TensorSignedWord::construct(cb, &format!("production_input_{i}"), 32))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap_or_else(|_| panic!("fixed K input"));
        let input_raw = std::array::from_fn(|i| {
            std::array::from_fn(|limb| {
                cb.create_witin(|| format!("production_input_raw_{i}_{limb}"))
            })
        });
        let input_neg_carry =
            std::array::from_fn(|i| cb.create_witin(|| format!("production_input_neg_carry_{i}")));
        for (i, ((raw, signed), carry)) in input_raw
            .iter()
            .zip(&input)
            .zip(&input_neg_carry)
            .enumerate()
        {
            for (limb, value) in raw.iter().enumerate() {
                cb.assert_const_range(
                    || format!("production_input_raw16_{i}_{limb}"),
                    value.expr(),
                    16,
                )?;
            }
            cb.assert_bit(
                || format!("production_input_neg_carry_bit_{i}"),
                carry.expr(),
            )?;
            let positive = E::BaseField::ONE.expr() - signed.sign.expr();
            cb.require_zero(
                || format!("production_input_positive_lo_{i}"),
                positive.clone() * (raw[0].expr() - signed.magnitude[0].expr()),
            )?;
            cb.require_zero(
                || format!("production_input_positive_hi_{i}"),
                positive * (raw[1].expr() - signed.magnitude[1].expr()),
            )?;
            cb.require_zero(
                || format!("production_input_negative_lo_{i}"),
                signed.sign.expr()
                    * (raw[0].expr() + signed.magnitude[0].expr() - carry.expr() * (1u64 << 16)),
            )?;
            cb.require_zero(
                || format!("production_input_negative_hi_{i}"),
                signed.sign.expr()
                    * (raw[1].expr() + signed.magnitude[1].expr() + carry.expr() - (1u64 << 16)),
            )?;
        }
        let output = TensorSignedWord::construct(cb, "production_output", 32)?;
        let remainder = TensorSignedI64Nibbles::construct(cb, "production_remainder")?;
        let cell =
            TensorProductionMatMulCellConfig::construct(cb, "production_raw_cell", K, shift)?;
        for (boundary, product) in input
            .iter()
            .zip(cell.buckets.iter().flat_map(|bucket| &bucket.products))
        {
            let magnitude = product
                .left
                .iter()
                .enumerate()
                .fold(E::BaseField::ZERO.expr(), |sum, (i, byte)| {
                    sum + byte.expr() * (1u64 << (8 * i))
                });
            cb.require_equal(
                || "production signed input boundary",
                boundary.expr(),
                (E::BaseField::ONE.expr() - product.left_sign.expr() * 2) * magnitude,
            )?;
        }
        let signed_nibbles = |word: &TensorSignedI64Nibbles| {
            let magnitude = word
                .magnitude
                .iter()
                .enumerate()
                .fold(E::BaseField::ZERO.expr(), |sum, (i, nibble)| {
                    sum + nibble.expr() * (1u64 << (4 * i))
                });
            (E::BaseField::ONE.expr() - word.sign.expr() * 2) * magnitude
        };
        cb.require_equal(
            || "production output boundary",
            output.expr(),
            signed_nibbles(&cell.rescale.quotient),
        )?;
        cb.require_equal(
            || "production remainder boundary",
            signed_nibbles(&remainder),
            signed_nibbles(&cell.rescale.remainder),
        )?;
        let record = |phase, output_expr| {
            production_raw_state_record(
                cycle.expr(),
                call_id.expr(),
                phase,
                profile.expr(),
                signature_id.expr(),
                tensor_id.expr(),
                first_tile_id.expr(),
                input_raw
                    .iter()
                    .flat_map(|raw| raw.iter().map(|limb| limb.expr())),
                output_expr,
            )
        };
        cb.read_record(
            || "production_raw_state_in",
            RAMType::Custom,
            record(TENSOR_STATE_PHASE_INPUT, E::BaseField::ZERO.expr()),
        )?;
        cb.write_record(
            || "production_raw_state_out",
            RAMType::Custom,
            record(TENSOR_STATE_PHASE_OUTPUT, output.expr()),
        )?;
        Ok(Self {
            cycle,
            call_id,
            profile,
            signature_id,
            tensor_id,
            first_tile_id,
            input_raw,
            input_neg_carry,
            input,
            output,
            remainder,
            cell,
        })
    }

    pub fn assign(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        provider: Option<&dyn TensorWitnessProvider>,
        desc: ceno_emul::tensor::production::ProductionMatMulCellDesc,
        cycle: u64,
        call_id: u32,
        input: &[i32; K],
    ) -> Result<(i32, i64), String> {
        let provider =
            provider.ok_or_else(|| "tensor proof context is not installed".to_string())?;
        if desc.signature.k() != K {
            return Err("production signature K mismatch".into());
        }
        let mut weights = Vec::with_capacity(K);
        for expected_tile in desc.first_tile_id..desc.first_tile_id + desc.tile_count {
            let opening = provider
                .read_tile(desc.weight_tensor_id, expected_tile)
                .map_err(|e| e.to_string())?;
            if opening.tensor_id != desc.weight_tensor_id || opening.tile_id != expected_tile {
                return Err("production raw tile order mismatch".into());
            }
            if ceno_emul::tensor::commit_tile(opening.tensor_id, opening.tile_id, &opening.bytes)
                != opening.root
            {
                return Err("production raw tile checksum mismatch".into());
            }
            weights.extend(decode_i32_le(&opening.bytes).map_err(|e| e.to_string())?);
        }
        if weights.len() != K {
            return Err("production opened K mismatch".into());
        }
        set_val!(instance, self.cycle, cycle);
        set_val!(instance, self.call_id, call_id as u64);
        set_val!(
            instance,
            self.profile,
            ceno_emul::tensor::production::PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1 as u64
        );
        set_val!(instance, self.signature_id, desc.signature.id() as u64);
        set_val!(instance, self.tensor_id, desc.weight_tensor_id as u64);
        set_val!(instance, self.first_tile_id, desc.first_tile_id as u64);
        for (config, &value) in self.input.iter().zip(input) {
            config.assign(instance, lkm, value);
        }
        for ((raw, carry), &value) in self.input_raw.iter().zip(&self.input_neg_carry).zip(input) {
            set_val!(instance, raw[0], u64::from(value as u32 & 0xffff));
            set_val!(instance, raw[1], u64::from(value as u32 >> 16));
            lkm.assert_const_range(u64::from(value as u32 & 0xffff), 16);
            lkm.assert_const_range(u64::from(value as u32 >> 16), 16);
            set_val!(
                instance,
                *carry,
                u64::from((value.unsigned_abs() & 0xffff) != 0)
            );
        }
        let (output, remainder) = self.cell.assign(instance, lkm, input, &weights)?;
        let output_i32 = i32::try_from(output).map_err(|_| "production output outside i32")?;
        self.output.assign(instance, lkm, output_i32);
        self.remainder.assign::<E>(instance, lkm, remainder);
        if std::env::var_os("CENO_TENSOR_E2E_RW_TRACE").is_some() {
            tracing::info!(
                target: "ceno_gpu::tensor_record_path",
                role = "raw_witness",
                record_time = cycle,
                record_slot = desc.first_tile_id,
                call_id,
                signature = desc.signature.id(),
                tensor_id = desc.weight_tensor_id,
                first_tile = desc.first_tile_id,
                tile_count = desc.tile_count,
                input_checksum = production_checksum_values(input),
                output = output_i32,
                remainder,
                "Gate-5 raw state record identity/value"
            );
        }
        Ok((output_i32, remainder))
    }
}

pub fn production_raw_state_record<E: ExtensionField>(
    cycle: Expression<E>,
    call_id: Expression<E>,
    phase: u64,
    profile: Expression<E>,
    signature_id: Expression<E>,
    tensor_id: Expression<E>,
    first_tile_id: Expression<E>,
    values: impl IntoIterator<Item = Expression<E>>,
    output: Expression<E>,
) -> Vec<Expression<E>> {
    [
        CustomRWTag::TensorState.expr::<E>(),
        cycle,
        call_id,
        E::BaseField::from_u64(phase).expr(),
        profile,
        signature_id,
        tensor_id,
        first_tile_id,
    ]
    .into_iter()
    .chain(values)
    .chain([output])
    .collect()
}

/// Open and evaluate the bounded 2x3-by-3x2 Gate-2 tile. Absence of proof
/// context is an error rather than an implicit all-zero/default witness.
pub fn assign_gate2_core_witness(
    provider: Option<&dyn TensorWitnessProvider>,
    profile: u32,
    tensor_id: u32,
    tile_id: u32,
    expected_commitment: &[u32; 8],
    input: &[i32; 6],
) -> Result<TensorGate2CoreWitness, String> {
    if profile != GATE2_LINEAR_COMMITMENT_V1 {
        return Err("Gate-2 AIR requires the circuit-native commitment profile".into());
    }
    let provider = provider.ok_or_else(|| "tensor proof context is not installed".to_string())?;
    let opening = provider
        .read_tile(tensor_id, tile_id)
        .map_err(|error| error.to_string())?;
    if opening.tensor_id != tensor_id {
        return Err("tensor opening ID mismatch".into());
    }
    if opening.tile_id != tile_id {
        return Err("tensor opening tile ID mismatch".into());
    }
    let decoded = decode_i32_le(&opening.bytes).map_err(|error| error.to_string())?;
    let weights: [i32; TENSOR_GATE2_WEIGHTS] = decoded
        .try_into()
        .map_err(|_| "Gate-2 tile must contain exactly six i32 weights".to_string())?;
    let commitment = gate2_linear_commitment_v1(tensor_id, tile_id, &weights);
    if &commitment != expected_commitment {
        return Err("Gate-2 circuit commitment mismatch".into());
    }
    let (outputs, remainders) = matmul_rescaled_i32(input, &weights, 2, 3, 2, TENSOR_GATE2_SHIFT)
        .map_err(|error| error.to_string())?;
    let outputs = outputs
        .into_iter()
        .map(i32::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Gate-2 output exceeds i32".to_string())?;
    let remainders = remainders
        .into_iter()
        .map(i32::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Gate-2 remainder exceeds i32".to_string())?;
    Ok(TensorGate2CoreWitness {
        weights,
        commitment,
        outputs: outputs.try_into().expect("2x2 output has four words"),
        remainders: remainders
            .try_into()
            .expect("2x2 output has four remainders"),
    })
}

/// Logical fields of a Gate-2 tensor boundary. Keeping this structure typed
/// prevents either split chip from silently changing field order.
pub struct TensorStateRecord<E: ExtensionField> {
    pub cycle: Expression<E>,
    pub call_id: Expression<E>,
    pub phase: u64,
    pub profile: Expression<E>,
    pub signature_id: Expression<E>,
    pub tensor_id: Expression<E>,
    pub tile_id: Expression<E>,
    pub values: [Expression<E>; 6],
    pub commitment: [Expression<E>; 8],
    pub outputs: [Expression<E>; 4],
    pub remainders: [Expression<E>; 4],
}

/// Canonical custom-RAM encoding shared by TensorMatMulEcall and
/// TensorMatMulCore. Input records place activations in `values`; core-private
/// weights are constrained internally and are never part of this boundary.
pub fn tensor_state_record<E: ExtensionField>(record: TensorStateRecord<E>) -> Vec<Expression<E>> {
    [
        CustomRWTag::TensorState.expr::<E>(),
        record.cycle,
        record.call_id,
        E::BaseField::from_u64(record.phase).expr(),
        record.profile,
        record.signature_id,
        record.tensor_id,
        record.tile_id,
    ]
    .into_iter()
    .chain(record.values)
    .chain(record.commitment)
    .chain(record.outputs)
    .chain(record.remainders)
    .collect_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        scheme::mock_prover::MockProver,
    };
    use ceno_emul::tensor::{DeterministicTileProvider, encode_i32_le};
    use ff_ext::BabyBearExt4;
    use itertools::Itertools;
    use multilinear_extensions::mle::{ArcMultilinearExtension, MultilinearExtension};

    type E = BabyBearExt4;

    fn expr(value: u64) -> Expression<E> {
        <E as ExtensionField>::BaseField::from_u64(value).expr()
    }

    fn one_row_mles(
        values: &[<E as ExtensionField>::BaseField],
    ) -> Vec<ArcMultilinearExtension<'_, E>> {
        values
            .iter()
            .map(|value| MultilinearExtension::from_evaluation_vec_smart(0, vec![*value]).into())
            .collect_vec()
    }

    fn assert_mock_satisfied(
        cs: &mut ConstraintSystem<E>,
        values: &[<E as ExtensionField>::BaseField],
    ) {
        let cb = CircuitBuilder::new(cs);
        MockProver::assert_satisfied(&cb, &one_row_mles(values), &[], &[], None, None);
    }

    fn assert_mock_rejects(
        cs: &mut ConstraintSystem<E>,
        values: &[<E as ExtensionField>::BaseField],
    ) {
        let cb = CircuitBuilder::new(cs);
        assert!(MockProver::run(&cb, &one_row_mles(values), &[], None).is_err());
    }

    #[test]
    fn tensor_state_layout_is_fixed_and_phase_separated() {
        let make = |phase| TensorStateRecord {
            cycle: expr(1),
            call_id: expr(2),
            phase,
            profile: expr(3),
            signature_id: expr(4),
            tensor_id: expr(5),
            tile_id: expr(6),
            values: std::array::from_fn(|i| expr(10 + i as u64)),
            commitment: std::array::from_fn(|i| expr(20 + i as u64)),
            outputs: std::array::from_fn(|i| expr(30 + i as u64)),
            remainders: std::array::from_fn(|i| expr(40 + i as u64)),
        };
        let input = tensor_state_record::<E>(make(TENSOR_STATE_PHASE_INPUT));
        let output = tensor_state_record::<E>(make(TENSOR_STATE_PHASE_OUTPUT));
        assert_eq!(input.len(), 30);
        assert_eq!(output.len(), 30);
        assert_ne!(format!("{:?}", input[3]), format!("{:?}", output[3]));
        assert_eq!(format!("{:?}", input[4]), format!("{:?}", output[4]));
    }

    #[test]
    fn production_raw_record_layout_is_shared_ordered_and_tamper_visible() {
        let make = |phase, signature, output| {
            production_raw_state_record::<E>(
                expr(9),
                expr(0x4000),
                phase,
                expr(ceno_emul::tensor::production::PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1 as u64),
                expr(signature),
                expr(701),
                expr(0),
                (0..8192).map(|i| expr(i as u64 & 0xffff)),
                expr(output),
            )
        };
        let input = make(
            TENSOR_STATE_PHASE_INPUT,
            ceno_emul::tensor::production::PRODUCTION_MATMUL_HIDDEN_SIGNATURE_V1 as u64,
            0,
        );
        let input_again = make(
            TENSOR_STATE_PHASE_INPUT,
            ceno_emul::tensor::production::PRODUCTION_MATMUL_HIDDEN_SIGNATURE_V1 as u64,
            0,
        );
        assert_eq!(input.len(), 8 + 4096 * 2 + 1);
        assert_eq!(format!("{input:?}"), format!("{input_again:?}"));
        let wrong_signature = make(TENSOR_STATE_PHASE_INPUT, 1, 0);
        let output = make(
            TENSOR_STATE_PHASE_OUTPUT,
            ceno_emul::tensor::production::PRODUCTION_MATMUL_HIDDEN_SIGNATURE_V1 as u64,
            7,
        );
        assert_ne!(format!("{input:?}"), format!("{wrong_signature:?}"));
        assert_ne!(format!("{input:?}"), format!("{output:?}"));
    }

    #[test]
    fn production_tile_records_bind_cross_chip_order_ids_inputs_buckets_and_checksum() {
        let input_record =
            |cycle, call_id, profile, signature, tensor, first, global, position, seed| {
                production_tile_input_record::<E>(
                    expr(cycle),
                    expr(call_id),
                    expr(profile),
                    expr(signature),
                    expr(tensor),
                    expr(first),
                    expr(global),
                    expr(position),
                    (0..2 * ceno_emul::tensor::production::PRODUCTION_K_TILE)
                        .map(|i| expr(seed + i as u64)),
                )
            };
        let profile = ceno_emul::tensor::production::PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1 as u64;
        let signature =
            ceno_emul::tensor::production::PRODUCTION_MATMUL_INTERMEDIATE_SIGNATURE_V1 as u64;
        let canonical = input_record(9, 0x4000, profile, signature, 701, 17, 27, 10, 100);
        let consumer = input_record(9, 0x4000, profile, signature, 701, 17, 27, 10, 100);
        assert_eq!(canonical.len(), 10 + 2 * 1024);
        assert_eq!(format!("{canonical:?}"), format!("{consumer:?}"));
        for tampered in [
            input_record(10, 0x4000, profile, signature, 701, 17, 27, 10, 100),
            input_record(9, 0x4001, profile, signature, 701, 17, 27, 10, 100),
            input_record(9, 0x4000, profile + 1, signature, 701, 17, 27, 10, 100),
            input_record(9, 0x4000, profile, signature + 1, 701, 17, 27, 10, 100),
            input_record(9, 0x4000, profile, signature, 702, 17, 27, 10, 100),
            input_record(9, 0x4000, profile, signature, 701, 18, 27, 10, 100),
            input_record(9, 0x4000, profile, signature, 701, 17, 28, 10, 100),
            input_record(9, 0x4000, profile, signature, 701, 17, 27, 9, 100),
            input_record(9, 0x4000, profile, signature, 701, 17, 27, 10, 101),
        ] {
            assert_ne!(format!("{canonical:?}"), format!("{tampered:?}"));
        }

        let bucket_record = |checksum, bucket_seed| {
            production_tile_bucket_record::<E>(
                expr(9),
                expr(0x4000),
                expr(profile),
                expr(signature),
                expr(701),
                expr(17),
                expr(27),
                expr(10),
                expr(checksum),
                (0..10).map(|i| expr(bucket_seed + i as u64)),
                (0..10).map(|i| expr(bucket_seed + 10 + i as u64)),
            )
        };
        let produced = bucket_record(55, 200);
        let finalized = bucket_record(55, 200);
        assert_eq!(produced.len(), 11 + 20);
        assert_eq!(format!("{produced:?}"), format!("{finalized:?}"));
        assert_ne!(
            format!("{produced:?}"),
            format!("{:?}", bucket_record(56, 200))
        );
        assert_ne!(
            format!("{produced:?}"),
            format!("{:?}", bucket_record(55, 201))
        );
    }

    #[test]
    fn gate2_core_assignment_is_provider_only_and_fail_closed() {
        let tensor_id = 41;
        let tile_id = 0;
        let weights = [65_536, 0, 0, 65_536, 65_536, 65_536];
        let commitment = gate2_linear_commitment_v1(tensor_id, tile_id, &weights);
        let input = [1, 2, 3, 4, 5, 6];
        let missing = assign_gate2_core_witness(
            None,
            GATE2_LINEAR_COMMITMENT_V1,
            tensor_id,
            tile_id,
            &commitment,
            &input,
        );
        assert!(missing.unwrap_err().to_string().contains("proof context"));

        let provider =
            DeterministicTileProvider::new(tensor_id, vec![encode_i32_le(&weights)]).unwrap();
        let witness = assign_gate2_core_witness(
            Some(&provider),
            GATE2_LINEAR_COMMITMENT_V1,
            tensor_id,
            tile_id,
            &commitment,
            &input,
        )
        .unwrap();
        assert_eq!(witness.outputs, [4, 5, 10, 11]);
        assert_eq!(witness.remainders, [0; 4]);

        let mut tampered = commitment;
        tampered[0] ^= 1;
        assert!(
            assign_gate2_core_witness(
                Some(&provider),
                GATE2_LINEAR_COMMITMENT_V1,
                tensor_id,
                tile_id,
                &tampered,
                &input,
            )
            .is_err()
        );
    }

    #[test]
    fn gate2_air_constructs_with_signed_ranges_and_rescale_equations() {
        let mut cs = ConstraintSystem::<E>::new(|| "tensor_gate2_air");
        let mut cb = CircuitBuilder::new(&mut cs);
        TensorGate2AirConfig::construct(&mut cb, expr(41), expr(0)).unwrap();
        assert!(cs.num_witin > 0);
    }

    #[test]
    fn production_i32_byte_limb_product_constrains_full_product_and_sign() {
        let mut cs = ConstraintSystem::<E>::new(|| "tensor_i32_byte_product");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = TensorI32ByteLimbProduct::construct(&mut cb, "mul").unwrap();
        let mut instance = vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
        let mut lkm = LkMultiplicity::default();
        config.assign(&mut instance, &mut lkm, i32::MIN, -65_537);
        assert_mock_satisfied(&mut cs, &instance);
        let mut tampered = instance.clone();
        set_val!(tampered, config.product[0], 1u64);
        assert_mock_rejects(&mut cs, &tampered);
        let mut bad_sign = instance;
        set_val!(bad_sign, config.product_sign, 1u64);
        assert_mock_rejects(&mut cs, &bad_sign);
    }

    #[test]
    fn production_dot_buckets_constrain_products_carries_and_sign_class() {
        let mut cs = ConstraintSystem::<E>::new(|| "tensor_signed_dot_bucket");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = TensorSignedDotBucketConfig::construct(&mut cb, "dot", 4).unwrap();
        let mut instance = vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
        let mut lkm = LkMultiplicity::default();
        config
            .assign(
                &mut instance,
                &mut lkm,
                &[i32::MIN, 65_537, -7, 9],
                &[-1, 65_539, -11, -3],
            )
            .unwrap();
        assert_mock_satisfied(&mut cs, &instance);
        let mut bad_product = instance.clone();
        set_val!(bad_product, config.products[1].product[0], 0u64);
        assert_mock_rejects(&mut cs, &bad_product);
        let mut bad_carry = instance.clone();
        set_val!(bad_carry, config.positive_carries[0], 1u64);
        assert_mock_rejects(&mut cs, &bad_carry);
        let mut bad_bucket = instance;
        set_val!(bad_bucket, config.negative[0], 0u64);
        assert_mock_rejects(&mut cs, &bad_bucket);
    }

    #[test]
    fn production_limb_rescale_q16_q20_and_negative_half_are_constrained() {
        for (shift, accumulator, expected) in [
            (16, -32_768i64, (0, -32_768)),
            (
                16,
                9_876_543i64,
                ceno_emul::tensor::zkllm_rescale(9_876_543, 16).unwrap(),
            ),
            (20, -524_288i64, (0, -524_288)),
            (
                20,
                -9_876_543i64,
                ceno_emul::tensor::zkllm_rescale(-9_876_543, 20).unwrap(),
            ),
        ] {
            let mut cs = ConstraintSystem::<E>::new(|| format!("tensor_limb_rescale_{shift}"));
            let mut cb = CircuitBuilder::new(&mut cs);
            let config =
                TensorSignedLimbRescaleConfig::construct(&mut cb, "rescale", shift).unwrap();
            let mut instance =
                vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
            let actual = config
                .assign(&mut instance, &mut LkMultiplicity::default(), accumulator)
                .unwrap();
            assert_eq!(actual, expected);
            assert_mock_satisfied(&mut cs, &instance);
            let mut bad_q = instance.clone();
            let q0 = actual.0.unsigned_abs() & 15;
            set_val!(bad_q, config.quotient.magnitude[0], (q0 + 1) & 15);
            assert_mock_rejects(&mut cs, &bad_q);
            let mut bad_r = instance;
            let r0 = actual.1.unsigned_abs() & 15;
            set_val!(bad_r, config.remainder.magnitude[0], (r0 + 1) & 15);
            assert_mock_rejects(&mut cs, &bad_r);
        }
    }

    #[test]
    fn production_cross_tile_bucket_add_binds_four_and_eleven_tile_carries() {
        for k in [4096usize, 11008] {
            let left = (0..k)
                .map(|i| if i % 3 == 0 { -257 } else { 513 })
                .collect_vec();
            let right = (0..k)
                .map(|i| if i % 5 == 0 { -1025 } else { 769 })
                .collect_vec();
            let trace =
                ceno_emul::tensor::production::signed_dot_byte_limb_rescaled(&left, &right, 16)
                    .unwrap();
            let mut cs = ConstraintSystem::<E>::new(|| format!("cross_tile_{k}"));
            let mut cb = CircuitBuilder::new(&mut cs);
            let configs = (0..trace.tiles.len())
                .map(|i| TensorBucketAddConfig::construct(&mut cb, &format!("add_{i}")))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let mut instance =
                vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
            let mut lkm = LkMultiplicity::default();
            let mut positive = [0u8; 10];
            for (i, (config, tile)) in configs.iter().zip(&trace.tiles).enumerate() {
                positive = config
                    .assign(&mut instance, &mut lkm, &positive, &tile.positive_base256)
                    .unwrap();
                assert_eq!(trace.positive_cross_tile_carries[i].len(), 16);
            }
            assert_mock_satisfied(&mut cs, &instance);
            let mut bad = instance;
            set_val!(bad, configs[configs.len() / 2].carries[0], 2u64);
            assert_mock_rejects(&mut cs, &bad);
        }
    }

    #[test]
    fn production_matmul_cell_binds_product_difference_rescale_and_tampering() {
        let left = [i32::MIN, 65_537, -7, 9];
        let right = [-1, 65_539, -11, -3];
        let mut cs = ConstraintSystem::<E>::new(|| "production_matmul_cell");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = TensorProductionMatMulCellConfig::construct(&mut cb, "cell", 4, 16).unwrap();
        let mut instance = vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
        let mut lkm = LkMultiplicity::default();
        let expected =
            ceno_emul::tensor::production::signed_dot_byte_limb_rescaled(&left, &right, 16)
                .unwrap();
        assert_eq!(
            config
                .assign(&mut instance, &mut lkm, &left, &right)
                .unwrap(),
            (expected.quotient, expected.remainder)
        );
        assert_mock_satisfied(&mut cs, &instance);

        let mut bad_product = instance.clone();
        set_val!(bad_product, config.buckets[0].products[1].product[0], 0u64);
        assert_mock_rejects(&mut cs, &bad_product);
        let mut bad_bucket_carry = instance.clone();
        set_val!(
            bad_bucket_carry,
            config.buckets[0].positive_carries[0],
            1u64
        );
        assert_mock_rejects(&mut cs, &bad_bucket_carry);
        let mut bad_difference = instance.clone();
        let normalized = expected.positive
            + if expected.signed_sum < 0 {
                u128::from(expected.signed_sum.unsigned_abs())
            } else {
                0
            };
        set_val!(
            bad_difference,
            config.difference.result[0],
            (((normalized & 15) + 1) & 15) as u64
        );
        assert_mock_rejects(&mut cs, &bad_difference);
        let mut bad_q = instance.clone();
        set_val!(
            bad_q,
            config.rescale.quotient.magnitude[0],
            ((expected.quotient.unsigned_abs() + 1) & 15) as u64
        );
        assert_mock_rejects(&mut cs, &bad_q);
        let mut bad_r = instance;
        set_val!(
            bad_r,
            config.rescale.remainder.magnitude[0],
            ((expected.remainder.unsigned_abs() + 1) & 15) as u64
        );
        assert_mock_rejects(&mut cs, &bad_r);
    }

    #[test]
    fn production_matmul_cell_folds_every_k_tile_before_one_rescale() {
        let k = ceno_emul::tensor::production::PRODUCTION_K_TILE + 1;
        let left = (0..k)
            .map(|i| if i % 3 == 0 { -257 } else { 513 })
            .collect_vec();
        let right = (0..k)
            .map(|i| if i % 5 == 0 { -1025 } else { 769 })
            .collect_vec();
        let mut cs = ConstraintSystem::<E>::new(|| "production_cross_tile_cell");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            TensorProductionMatMulCellConfig::construct(&mut cb, "cross_tile", k, 16).unwrap();
        assert_eq!(config.buckets.len(), 2);
        assert_eq!(config.positive_folds.len(), 2);
        let mut instance = vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
        let mut lkm = LkMultiplicity::default();
        let trace = ceno_emul::tensor::production::signed_dot_byte_limb_rescaled(&left, &right, 16)
            .unwrap();
        assert_eq!(
            config
                .assign(&mut instance, &mut lkm, &left, &right)
                .unwrap(),
            (trace.quotient, trace.remainder)
        );
        assert_mock_satisfied(&mut cs, &instance);

        let mut bad_weight = instance.clone();
        let weight_byte =
            u64::from(right[ceno_emul::tensor::production::PRODUCTION_K_TILE].unsigned_abs() as u8);
        set_val!(
            bad_weight,
            config.buckets[1].products[0].right[0],
            (weight_byte + 1) & 255
        );
        assert_mock_rejects(&mut cs, &bad_weight);
        let mut bad_fold = instance.clone();
        let folded_byte = trace.tiles[0].positive_base256[0];
        set_val!(
            bad_fold,
            config.positive_folds[1].accumulator[0],
            (u64::from(folded_byte) + 1) & 255
        );
        assert_mock_rejects(&mut cs, &bad_fold);
        let mut bad_boundary = instance;
        set_val!(
            bad_boundary,
            config.rescale.quotient.magnitude[0],
            (trace.quotient.unsigned_abs() + 1) & 15
        );
        assert_mock_rejects(&mut cs, &bad_boundary);
    }

    #[test]
    fn production_k1024_tile_and_k4096_finalize_are_bounded_and_tamper_rejecting() {
        std::thread::Builder::new()
            .name("production-k1024-tile-test".into())
            .stack_size(128 * 1024 * 1024)
            .spawn(|| {
                const K: usize = ceno_emul::tensor::production::PRODUCTION_K_TILE;
                let tensor_id = 991;
                let first_tile = 0;
                let tiles = (0..4)
                    .map(|tile| {
                        let values = (0..K)
                            .map(|i| match (i + tile) % 7 {
                                0 => -65_536,
                                1 => 65_536,
                                2 => -257,
                                _ => 0,
                            })
                            .collect_vec();
                        encode_i32_le(&values)
                    })
                    .collect_vec();
                let provider = DeterministicTileProvider::new(tensor_id, tiles).unwrap();
                let desc = ceno_emul::tensor::production::ProductionMatMulCellDesc::new(
                    ceno_emul::tensor::production::ProductionMatMulSignature::HiddenK4096,
                    tensor_id,
                    first_tile,
                    16,
                )
                .unwrap();
                let input = (0..4096)
                    .map(|i| match i % 9 {
                        0 => -3,
                        1 => 5,
                        _ => 0,
                    })
                    .collect_vec();

                let mut tile_cs = ConstraintSystem::<E>::new(|| "production_k1024_tile");
                let mut tile_cb = CircuitBuilder::new(&mut tile_cs);
                let tile = TensorProductionTileCoreConfig::<E>::construct(&mut tile_cb).unwrap();
                assert!(usize::from(tile_cs.num_witin) < usize::from(u16::MAX));
                let mut tile_instance =
                    vec![<E as ExtensionField>::BaseField::ZERO; usize::from(tile_cs.num_witin)];
                let mut tile_lkm = LkMultiplicity::default();
                assert!(
                    tile.assign(
                        &mut tile_instance,
                        &mut tile_lkm,
                        None,
                        desc,
                        0,
                        9,
                        0x4000,
                        &input[..K]
                    )
                    .unwrap_err()
                    .contains("proof context")
                );
                tile.assign(
                    &mut tile_instance,
                    &mut tile_lkm,
                    Some(&provider),
                    desc,
                    0,
                    9,
                    0x4000,
                    &input[..K],
                )
                .unwrap();
                assert_mock_satisfied(&mut tile_cs, &tile_instance);
                let mut bad_checksum = tile_instance.clone();
                let checksum = production_checksum_values(
                    &decode_i32_le(&provider.read_tile(tensor_id, first_tile).unwrap().bytes)
                        .unwrap(),
                );
                set_val!(bad_checksum, tile.weight_checksum, checksum + 1);
                assert_mock_rejects(&mut tile_cs, &bad_checksum);
                let mut bad_bucket = tile_instance;
                let tile_weights =
                    decode_i32_le(&provider.read_tile(tensor_id, first_tile).unwrap().bytes)
                        .unwrap();
                let tile_trace = ceno_emul::tensor::production::signed_dot_byte_limb_tile(
                    &input[..K],
                    &tile_weights,
                )
                .unwrap();
                set_val!(
                    bad_bucket,
                    tile.bucket.positive[0],
                    u64::from(tile_trace.positive_base256[0].wrapping_add(1))
                );
                assert_mock_rejects(&mut tile_cs, &bad_bucket);

                let mut final_cs = ConstraintSystem::<E>::new(|| "production_k4096_finalize");
                let mut final_cb = CircuitBuilder::new(&mut final_cs);
                let finalize =
                    TensorProductionFinalizeCoreConfig::<E, 4096, 4>::construct(&mut final_cb, 16)
                        .unwrap();
                assert!(usize::from(final_cs.num_witin) < usize::from(u16::MAX));
                let mut final_instance =
                    vec![<E as ExtensionField>::BaseField::ZERO; usize::from(final_cs.num_witin)];
                let mut final_lkm = LkMultiplicity::default();
                let expected = ceno_emul::tensor::production::execute_sparse_production_cell(
                    &provider, desc, &input,
                )
                .unwrap();
                assert_eq!(
                    finalize
                        .assign(
                            &mut final_instance,
                            &mut final_lkm,
                            Some(&provider),
                            desc,
                            9,
                            0x4000,
                            &input,
                        )
                        .unwrap(),
                    (expected.0, expected.1)
                );
                assert_mock_satisfied(&mut final_cs, &final_instance);
                let mut bad_carry = final_instance.clone();
                set_val!(bad_carry, finalize.positive_folds[1].carries[0], 2);
                assert_mock_rejects(&mut final_cs, &bad_carry);
                let mut bad_output = final_instance;
                set_val!(
                    bad_output,
                    finalize.output.magnitude[0],
                    u64::from(expected.0.unsigned_abs() & 0xffff) + 1
                );
                assert_mock_rejects(&mut final_cs, &bad_output);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn production_k32_mini_tile_matches_reference_and_rejects_tamper() {
        const K: usize = ceno_emul::tensor::production::mini_llama_10m::PROOF_TILE_K;
        let tensor_id = 10_055;
        let input = (0..K)
            .map(|i| match i % 6 {
                0 => i as i32 - 19,
                1 => -(i as i32) - 3,
                _ => 0,
            })
            .collect_vec();
        let weights = (0..K)
            .map(|i| match i % 5 {
                0 => -65_536,
                1 => 65_536,
                2 => -257,
                _ => 0,
            })
            .collect_vec();
        let provider = DeterministicTileProvider::new(
            tensor_id,
            (0..5).map(|_| encode_i32_le(&weights)).collect(),
        )
        .unwrap();
        let desc = ceno_emul::tensor::production::ProductionMatMulCellDesc::new(
            ceno_emul::tensor::production::ProductionMatMulSignature::MiniHiddenK160,
            tensor_id,
            0,
            16,
        )
        .unwrap();

        let mut cs = ConstraintSystem::<E>::new(|| "production_k32_mini_tile");
        let mut cb = CircuitBuilder::new(&mut cs);
        let tile = TensorProductionTileCoreConfig::<E, K>::construct(&mut cb).unwrap();
        let mut instance = vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
        let mut lkm = LkMultiplicity::default();
        tile.assign(
            &mut instance,
            &mut lkm,
            Some(&provider),
            desc,
            0,
            17,
            0x5050,
            &input,
        )
        .unwrap();
        let reference =
            ceno_emul::tensor::production::signed_dot_byte_limb_tile(&input, &weights).unwrap();
        for (column, &expected) in tile.bucket.positive.iter().zip(&reference.positive_base256) {
            assert_eq!(
                instance[usize::from(column.id)],
                <E as ExtensionField>::BaseField::from_u64(u64::from(expected))
            );
        }
        for (column, &expected) in tile.bucket.negative.iter().zip(&reference.negative_base256) {
            assert_eq!(
                instance[usize::from(column.id)],
                <E as ExtensionField>::BaseField::from_u64(u64::from(expected))
            );
        }
        assert_mock_satisfied(&mut cs, &instance);

        let mut bad = instance;
        let old = reference.positive_base256[0];
        set_val!(bad, tile.bucket.positive[0], u64::from(old.wrapping_add(1)));
        assert_mock_rejects(&mut cs, &bad);

        // FFN K=432 has thirteen complete K32 rows and one 16-value compact
        // provider tile. Assignment must zero-pad the logical physical row;
        // non-zero padding would change the bucket witness and fail AIR.
        let compact = weights[..16].to_vec();
        let ffn_provider = DeterministicTileProvider::new(
            tensor_id + 1,
            (0..13)
                .map(|_| encode_i32_le(&weights))
                .chain(std::iter::once(encode_i32_le(&compact)))
                .collect(),
        )
        .unwrap();
        let ffn_desc = ceno_emul::tensor::production::ProductionMatMulCellDesc::new(
            ceno_emul::tensor::production::ProductionMatMulSignature::MiniIntermediateK432,
            tensor_id + 1,
            0,
            16,
        )
        .unwrap();
        let padded_input = input.clone();
        let mut padded_instance =
            vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
        let mut padded_lkm = LkMultiplicity::default();
        tile.assign(
            &mut padded_instance,
            &mut padded_lkm,
            Some(&ffn_provider),
            ffn_desc,
            13,
            18,
            0x6060,
            &padded_input,
        )
        .unwrap();
        let mut padded_weights = compact;
        padded_weights.resize(K, 0);
        let padded_reference = ceno_emul::tensor::production::signed_dot_byte_limb_tile(
            &padded_input,
            &padded_weights,
        )
        .unwrap();
        for (column, &expected) in tile
            .bucket
            .positive
            .iter()
            .zip(&padded_reference.positive_base256)
        {
            assert_eq!(
                padded_instance[usize::from(column.id)],
                <E as ExtensionField>::BaseField::from_u64(u64::from(expected))
            );
        }
        assert_mock_satisfied(&mut cs, &padded_instance);
    }

    #[test]
    fn gate2_core_constructs_ordered_shared_records() {
        let mut cs = ConstraintSystem::<E>::new(|| "tensor_gate2_core");
        let mut cb = CircuitBuilder::new(&mut cs);
        TensorMatMulCoreConfig::construct(&mut cb).unwrap();
        assert!(cs.num_witin > 0);
    }

    #[test]
    fn q16_q20_rescale_residual_and_rope_match_reference() {
        for shift in [16, 20] {
            let mut cs = ConstraintSystem::<E>::new(|| format!("tensor_rescale_q{shift}"));
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = TensorMulRescaleConfig::construct(&mut cb, "mul", shift, 9, 10).unwrap();
            let mut instance =
                vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
            let mut lkm = LkMultiplicity::default();
            let actual = config.assign(&mut instance, &mut lkm, -256, 255).unwrap();
            let expected = ceno_emul::tensor::zkllm_rescale(-256 * 255, shift)
                .unwrap()
                .0;
            assert_eq!(i64::from(actual), expected);
            assert_mock_satisfied(&mut cs, &instance);
            let mut tampered = instance.clone();
            set_val!(
                tampered,
                config.output.value,
                <E as ExtensionField>::BaseField::from_i64(i64::from(actual) + 1)
            );
            assert_mock_rejects(&mut cs, &tampered);
        }

        let mut cs = ConstraintSystem::<E>::new(|| "tensor_residual");
        let mut cb = CircuitBuilder::new(&mut cs);
        let residual = TensorResidualConfig::construct(&mut cb, "residual", 9, 10).unwrap();
        let mut instance = vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
        assert_eq!(
            residual
                .assign(&mut instance, &mut LkMultiplicity::default(), -256, 255)
                .unwrap(),
            -1
        );
        assert_mock_satisfied(&mut cs, &instance);
        let mut tampered = instance.clone();
        set_val!(tampered, residual.output.value, 0);
        assert_mock_rejects(&mut cs, &tampered);

        let mut cs = ConstraintSystem::<E>::new(|| "tensor_rope");
        let mut cb = CircuitBuilder::new(&mut cs);
        let rope = TensorRopeConfig::construct(&mut cb, "rope").unwrap();
        let mut instance = vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
        let actual = rope
            .assign(
                &mut instance,
                &mut LkMultiplicity::default(),
                7,
                -11,
                65_536,
                0,
            )
            .unwrap();
        assert_eq!(actual, 7);
        assert_mock_satisfied(&mut cs, &instance);
        let mut tampered = instance.clone();
        set_val!(
            tampered,
            rope.output.value,
            <E as ExtensionField>::BaseField::from_i64(i64::from(actual) + 1)
        );
        assert_mock_rejects(&mut cs, &tampered);
    }

    #[test]
    fn asymmetric_9x17_rescale_is_sound_and_tamper_rejecting() {
        let mut cs = ConstraintSystem::<E>::new(|| "tensor_rescale_9x17");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            TensorMulRescaleConfig::construct_bounded(&mut cb, "mul", 16, 9, 17, 10).unwrap();
        let mut instance = vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
        let output = config
            .assign(&mut instance, &mut LkMultiplicity::default(), -255, 65_536)
            .unwrap();
        assert_eq!(output, -255);
        assert_mock_satisfied(&mut cs, &instance);
        let mut tampered = instance.clone();
        set_val!(
            tampered,
            config.output.value,
            <E as ExtensionField>::BaseField::from_i64(i64::from(output) + 1)
        );
        assert_mock_rejects(&mut cs, &tampered);
    }

    #[test]
    fn fixed_rms_and_swiglu_tables_bind_identity_input_and_output() {
        fn exercise(
            construct: impl FnOnce(
                &mut CircuitBuilder<E>,
                &[(i32, i32)],
            ) -> Result<TensorFixedLookupConfig<E>, ZKVMError>,
            profile: u32,
            table_id: u32,
        ) {
            let entries = [(-7, -3), (0, 0), (9, 5)];
            let mut cs = ConstraintSystem::<E>::new(|| "fixed_tensor_lookup");
            let mut cb = CircuitBuilder::new(&mut cs);
            let config = construct(&mut cb, &entries).unwrap();
            let mut instance =
                vec![<E as ExtensionField>::BaseField::ZERO; usize::from(cs.num_witin)];
            assert_eq!(
                config
                    .assign(
                        &mut instance,
                        &mut LkMultiplicity::default(),
                        profile,
                        table_id,
                        9,
                    )
                    .unwrap(),
                5
            );
            assert_mock_satisfied(&mut cs, &instance);

            let mut tampered = instance.clone();
            set_val!(tampered, config.profile, u64::from(profile) + 1);
            assert_mock_rejects(&mut cs, &tampered);
            let mut tampered = instance.clone();
            set_val!(tampered, config.table_id, u64::from(table_id) + 1);
            assert_mock_rejects(&mut cs, &tampered);
            let mut tampered = instance.clone();
            set_val!(
                tampered,
                config.input.value,
                <E as ExtensionField>::BaseField::from_i64(10)
            );
            assert_mock_rejects(&mut cs, &tampered);
            let mut tampered = instance.clone();
            set_val!(
                tampered,
                config.output.value,
                <E as ExtensionField>::BaseField::from_i64(6)
            );
            assert_mock_rejects(&mut cs, &tampered);
        }

        exercise(
            TensorFixedLookupConfig::construct_rms_inverse_v1,
            RMS_INV_LOOKUP_V1,
            RMS_INV_TABLE_REDUCED_V1,
        );
        exercise(
            TensorFixedLookupConfig::construct_swiglu_v1,
            SWIGLU_LOOKUP_V1,
            SWIGLU_TABLE_REDUCED_V1,
        );
    }

    #[test]
    #[should_panic(expected = "direct product may wrap BabyBear")]
    fn direct_rescale_rejects_unsafe_operand_profile() {
        let mut cs = ConstraintSystem::<E>::new(|| "unsafe_tensor_rescale");
        let mut cb = CircuitBuilder::new(&mut cs);
        let _ = TensorMulRescaleConfig::construct(&mut cb, "unsafe", 16, 16, 16);
    }
}
