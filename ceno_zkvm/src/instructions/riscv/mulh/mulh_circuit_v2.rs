//! Byte-limb (u8) multiplication circuit for MUL / MULH / MULHU / MULHSU.
//!
//! Design mirrors SP1's `MulOperation`: operands are decomposed into bytes,
//! the product is computed by a schoolbook convolution, and the carry between
//! byte positions is a *genuine non-negative magnitude* that is directly
//! range-checked. This is sound over a small prime field (e.g. BabyBear,
//! `p ~ 2^31`) because every partial product `b[i] * c[j] <= 255*255 = 65025`
//! and every byte column sum stays far below `p`, so the field equation is a
//! faithful integer equation and the byte/carry decomposition is unique.
//!
//! For MULH / MULHU / MULHSU we compute the low 64 bits of the product of the
//! (sign- or zero-extended) 64-bit operands; the high 32 bits are the result.

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::SignedExtendConfig,
    impl_collect_lk_and_shardram, impl_collect_shardram, impl_gpu_assign,
    instructions::{
        Instruction,
        gpu::utils::{LkOp, LkShardramSink, emit_byte_decomposition_ops},
        riscv::{
            RIVInstruction,
            constants::{UINT_BYTE_LIMBS, UInt8},
            r_insn::RInstructionConfig,
        },
    },
    structs::ProgramParams,
    utils::split_to_u8,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{Expression, ToExpr as _, WitIn};
use std::{array, marker::PhantomData};
use witness::set_val;

/// Number of bytes of the (possibly sign-extended) operands and product when
/// the result is the high 32 bits of a 64-bit product.
const LONG_BYTES: usize = 2 * UINT_BYTE_LIMBS;
/// Bits used to range-check each byte-column carry. The honest carry is at most
/// `8 * 255^2 / 255 ~ 2041 < 2^16`, and `2^16 * 256 + (column sum) << p` for the
/// fields in use, so a 16-bit bound both admits the honest witness and prevents
/// any field wraparound that could create a second solution.
const CARRY_BITS: usize = 16;
const BYTE_MASK: u64 = 0xff;

pub struct MulhInstructionBase<E, I>(PhantomData<(E, I)>);

pub struct MulhConfig<E: ExtensionField> {
    pub(crate) rs1_read: UInt8<E>,
    pub(crate) rs2_read: UInt8<E>,
    pub(crate) rd_written: UInt8<E>,
    pub(crate) r_insn: RInstructionConfig<E>,
    /// Carry out of each byte column of the schoolbook product.
    pub(crate) carry: Vec<WitIn>,
    /// Low product bytes (intermediate) for the high-result variants.
    pub(crate) prod_low: Option<[WitIn; UINT_BYTE_LIMBS]>,
    /// Sign bit of `rs1`, present for signed operands (MULH, MULHSU).
    pub(crate) rs1_sign: Option<SignedExtendConfig<E>>,
    /// Sign bit of `rs2`, present for signed operands (MULH).
    pub(crate) rs2_sign: Option<SignedExtendConfig<E>>,
    phantom: PhantomData<E>,
}

/// Returns `(rs1_signed, rs2_signed, result_is_high)` for the opcode.
const fn signedness(kind: InsnKind) -> (bool, bool, bool) {
    match kind {
        InsnKind::MUL => (false, false, false),
        InsnKind::MULHU => (false, false, true),
        InsnKind::MULHSU => (true, false, true),
        InsnKind::MULH => (true, true, true),
        _ => panic!("unsupported instruction kind"),
    }
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for MulhInstructionBase<E, I> {
    type InstructionConfig = MulhConfig<E>;
    type InsnType = InsnKind;

    const GPU_LK_SHARDRAM: bool = true;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[I::INST_KIND]
    }

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<MulhConfig<E>, ZKVMError> {
        let (rs1_signed, rs2_signed, is_high) = signedness(I::INST_KIND);
        let num_bytes = if is_high { LONG_BYTES } else { UINT_BYTE_LIMBS };

        // Range-checked byte operands and result. `UInt8::new` constrains each
        // byte to `[0, 256)` (via `assert_double_u8`), which makes the
        // recombination into the 16-bit register limbs unique.
        let rs1_read = UInt8::new(|| "rs1_read", circuit_builder)?;
        let rs2_read = UInt8::new(|| "rs2_read", circuit_builder)?;
        let rd_written = UInt8::new(|| "rd_written", circuit_builder)?;

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        // Sign bits for signed operands (MSB of the most significant byte).
        let rs1_sign = if rs1_signed {
            Some(SignedExtendConfig::construct_byte(
                circuit_builder,
                rs1_read.expr()[UINT_BYTE_LIMBS - 1].clone(),
            )?)
        } else {
            None
        };
        let rs2_sign = if rs2_signed {
            Some(SignedExtendConfig::construct_byte(
                circuit_builder,
                rs2_read.expr()[UINT_BYTE_LIMBS - 1].clone(),
            )?)
        } else {
            None
        };

        let byte_mask: Expression<E> = BYTE_MASK.into();
        let extend =
            |reg: &[Expression<E>], sign: &Option<SignedExtendConfig<E>>| -> Vec<Expression<E>> {
                (0..num_bytes)
                    .map(|i| {
                        if i < UINT_BYTE_LIMBS {
                            reg[i].clone()
                        } else {
                            match sign {
                                Some(s) => s.expr() * byte_mask.clone(),
                                None => Expression::ZERO,
                            }
                        }
                    })
                    .collect()
            };
        let b = extend(&rs1_read.expr(), &rs1_sign);
        let c = extend(&rs2_read.expr(), &rs2_sign);

        // Low product bytes are explicit (range-checked) witnesses only when the
        // result is the high half; otherwise the result register *is* the low
        // product.
        let prod_low = if is_high {
            let pl: [WitIn; UINT_BYTE_LIMBS] =
                array::from_fn(|i| circuit_builder.create_witin(|| format!("prod_low_{i}")));
            for (i, pair) in pl.chunks(2).enumerate() {
                circuit_builder.assert_double_u8(
                    || format!("prod_low_{i}_u8"),
                    pair[0].expr(),
                    pair[1].expr(),
                )?;
            }
            Some(pl)
        } else {
            None
        };

        // Product byte at column `i`.
        let prod_byte = |i: usize| -> Expression<E> {
            if is_high {
                if i < UINT_BYTE_LIMBS {
                    prod_low.as_ref().unwrap()[i].expr()
                } else {
                    rd_written.expr()[i - UINT_BYTE_LIMBS].clone()
                }
            } else {
                rd_written.expr()[i].clone()
            }
        };

        let carry: Vec<WitIn> = (0..num_bytes)
            .map(|i| circuit_builder.create_witin(|| format!("carry_{i}")))
            .collect();

        // Schoolbook convolution with magnitude carry propagation:
        //   m[i] + carry[i-1] == prod[i] + carry[i] * 2^8
        let base: Expression<E> = (1u64 << 8).into();
        for i in 0..num_bytes {
            let mut m = Expression::ZERO;
            for j in 0..=i {
                if i - j < num_bytes {
                    m += b[j].clone() * c[i - j].clone();
                }
            }
            let carry_in = if i > 0 {
                carry[i - 1].expr()
            } else {
                Expression::ZERO
            };
            circuit_builder.require_zero(
                || format!("mul_byte_{i}"),
                m + carry_in - prod_byte(i) - carry[i].expr() * base.clone(),
            )?;
            circuit_builder.assert_const_range(
                || format!("carry_{i}_range"),
                carry[i].expr(),
                CARRY_BITS,
            )?;
        }

        Ok(MulhConfig {
            rs1_read,
            rs2_read,
            rd_written,
            r_insn,
            carry,
            prod_low,
            rs1_sign,
            rs2_sign,
            phantom: PhantomData,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let rs1 = step.rs1().unwrap().value;
        let rs2 = step.rs2().unwrap().value;
        let rd = step.rd().unwrap().value.after;

        let rs1_bytes = split_to_u8::<u16>(rs1);
        let rs2_bytes = split_to_u8::<u16>(rs2);
        let rd_bytes = split_to_u8::<u16>(rd);
        config.rs1_read.assign_limbs(instance, &rs1_bytes);
        config.rs2_read.assign_limbs(instance, &rs2_bytes);
        config.rd_written.assign_limbs(instance, &rd_bytes);

        // Byte range-check lookups for the three operands.
        for bytes in [&rs1_bytes, &rs2_bytes, &rd_bytes] {
            for pair in bytes.chunks(2) {
                lk_multiplicity.assert_double_u8(pair[0] as u64, pair[1] as u64);
            }
        }

        config
            .r_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

        let (prod, carry, _rs1_sign, _rs2_sign) = run_mulh_bytes(I::INST_KIND, rs1, rs2);

        if let Some(prod_low) = &config.prod_low {
            for (i, w) in prod_low.iter().enumerate() {
                set_val!(instance, w, prod[i] as u64);
            }
            for pair in prod[..UINT_BYTE_LIMBS].chunks(2) {
                lk_multiplicity.assert_double_u8(pair[0] as u64, pair[1] as u64);
            }
        }

        for (w, c) in config.carry.iter().zip(carry.iter()) {
            set_val!(instance, w, *c as u64);
            lk_multiplicity.assert_const_range(*c as u64, CARRY_BITS);
        }

        if let Some(s) = &config.rs1_sign {
            s.assign_instance(instance, lk_multiplicity, ((rs1 >> 24) & 0xff) as u64)?;
        }
        if let Some(s) = &config.rs2_sign {
            s.assign_instance(instance, lk_multiplicity, ((rs2 >> 24) & 0xff) as u64)?;
        }

        Ok(())
    }

    impl_collect_lk_and_shardram!(r_insn, |sink, step, _config, _ctx| {
        let rs1 = step.rs1().unwrap().value;
        let rs2 = step.rs2().unwrap().value;
        let rd = step.rd().unwrap().value.after;

        emit_byte_decomposition_ops(sink, &split_to_u8::<u8>(rs1));
        emit_byte_decomposition_ops(sink, &split_to_u8::<u8>(rs2));
        emit_byte_decomposition_ops(sink, &split_to_u8::<u8>(rd));

        let (prod, carry, _rs1_sign, _rs2_sign) = run_mulh_bytes(I::INST_KIND, rs1, rs2);
        let (rs1_signed, rs2_signed, is_high) = signedness(I::INST_KIND);
        if is_high {
            emit_byte_decomposition_ops(sink, &prod[..UINT_BYTE_LIMBS]);
        }
        for c in &carry {
            sink.emit_lk(LkOp::DynamicRange {
                value: *c as u64,
                bits: CARRY_BITS as u32,
            });
        }
        if rs1_signed {
            let byte = (rs1 >> 24) & 0xff;
            let msb = byte >> 7;
            sink.emit_lk(LkOp::DynamicRange {
                value: (2 * byte - (msb << 8)) as u64,
                bits: 8,
            });
        }
        if rs2_signed {
            let byte = (rs2 >> 24) & 0xff;
            let msb = byte >> 7;
            sink.emit_lk(LkOp::DynamicRange {
                value: (2 * byte - (msb << 8)) as u64,
                bits: 8,
            });
        }
    });

    impl_collect_shardram!(r_insn);

    impl_gpu_assign!(match I::INST_KIND {
        InsnKind::MUL => Some(dispatch::GpuWitgenKind::Mul(0u32)),
        InsnKind::MULH => Some(dispatch::GpuWitgenKind::Mul(1u32)),
        InsnKind::MULHU => Some(dispatch::GpuWitgenKind::Mul(2u32)),
        InsnKind::MULHSU => Some(dispatch::GpuWitgenKind::Mul(3u32)),
        _ => None,
    });
}

/// Compute the schoolbook product bytes and per-column carries for the given
/// opcode. Returns `(product_bytes, carries, rs1_sign, rs2_sign)`. For the
/// low-result opcode (MUL) the product has `UINT_BYTE_LIMBS` bytes; otherwise it
/// has `LONG_BYTES` (low 4 are the intermediate low product, high 4 the result).
fn run_mulh_bytes(kind: InsnKind, rs1: u32, rs2: u32) -> (Vec<u8>, Vec<u32>, u8, u8) {
    let (rs1_signed, rs2_signed, is_high) = signedness(kind);
    let num_bytes = if is_high { LONG_BYTES } else { UINT_BYTE_LIMBS };

    let rs1_le = rs1.to_le_bytes();
    let rs2_le = rs2.to_le_bytes();
    let rs1_sign = if rs1_signed { rs1_le[3] >> 7 } else { 0 };
    let rs2_sign = if rs2_signed { rs2_le[3] >> 7 } else { 0 };

    let mut b = vec![0u8; num_bytes];
    let mut c = vec![0u8; num_bytes];
    b[..UINT_BYTE_LIMBS].copy_from_slice(&rs1_le);
    c[..UINT_BYTE_LIMBS].copy_from_slice(&rs2_le);
    if is_high {
        let b_fill = if rs1_sign == 1 { 0xff } else { 0 };
        let c_fill = if rs2_sign == 1 { 0xff } else { 0 };
        for i in UINT_BYTE_LIMBS..num_bytes {
            b[i] = b_fill;
            c[i] = c_fill;
        }
    }

    let mut acc = vec![0u64; num_bytes];
    for (j, bj) in b.iter().enumerate() {
        for (k, ck) in c.iter().enumerate() {
            if j + k < num_bytes {
                acc[j + k] += (*bj as u64) * (*ck as u64);
            }
        }
    }

    let mut prod = vec![0u8; num_bytes];
    let mut carry = vec![0u32; num_bytes];
    let mut carry_in = 0u64;
    for i in 0..num_bytes {
        let v = acc[i] + carry_in;
        prod[i] = (v & BYTE_MASK) as u8;
        carry_in = v >> 8;
        carry[i] = carry_in as u32;
    }

    (prod, carry, rs1_sign, rs2_sign)
}
