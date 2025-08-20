use crate::{
    Value,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            RIVInstruction,
            constants::{LIMB_BITS, UINT_LIMBS, UInt},
            r_insn::RInstructionConfig,
        },
    },
    structs::ProgramParams,
    utils::split_to_limb,
};
use ceno_emul::InsnKind;
use ff_ext::{ExtensionField, FieldInto};
use itertools::Itertools;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::{Field, FieldAlgebra};
use std::{array, marker::PhantomData};
use witness::set_val;

pub struct ShiftBaseConfig<E: ExtensionField, const NUM_LIMBS: usize, const LIMB_BITS: usize> {
    // bit_multiplier = 2^bit_shift
    pub bit_multiplier_left: WitIn,
    pub bit_multiplier_right: WitIn,

    // Sign of x for SRA
    pub b_sign: WitIn,

    // Boolean columns that are 1 exactly at the index of the bit/limb shift amount
    pub bit_shift_marker: [WitIn; LIMB_BITS],
    pub limb_shift_marker: [WitIn; NUM_LIMBS],

    // Part of each x[i] that gets bit shifted to the next limb
    pub bit_shift_carry: [WitIn; NUM_LIMBS],
    pub phantom: PhantomData<E>,
}

impl<E: ExtensionField, const NUM_LIMBS: usize, const LIMB_BITS: usize>
    ShiftBaseConfig<E, NUM_LIMBS, LIMB_BITS>
{
    pub fn construct_circuit(
        circuit_builder: &mut crate::circuit_builder::CircuitBuilder<E>,
        kind: InsnKind,
        a: [Expression<E>; NUM_LIMBS],
        b: [Expression<E>; NUM_LIMBS],
        c: [Expression<E>; NUM_LIMBS],
    ) -> Result<Self, crate::error::ZKVMError> {
        let bit_shift_marker =
            array::from_fn(|i| circuit_builder.create_witin(|| format!("bit_shift_marker_{}", i)));
        let limb_shift_marker =
            array::from_fn(|i| circuit_builder.create_witin(|| format!("limb_shift_marker_{}", i)));
        let bit_multiplier_left = circuit_builder.create_witin(|| "bit_multiplier_left");
        let bit_multiplier_right = circuit_builder.create_witin(|| "bit_multiplier_right");
        let b_sign = circuit_builder.create_bit(|| "b_sign")?;
        let bit_shift_carry =
            array::from_fn(|i| circuit_builder.create_witin(|| format!("bit_shift_carry_{}", i)));

        // Constrain that bit_shift, bit_multiplier are correct, i.e. that bit_multiplier =
        // 1 << bit_shift. Because the sum of all bit_shift_marker[i] is constrained to be
        // 1, bit_shift is guaranteed to be in range.
        let mut bit_marker_sum = Expression::ZERO;
        let mut bit_shift = Expression::ZERO;

        for i in 0..LIMB_BITS {
            circuit_builder.assert_bit(
                || format!("bit_shift_marker_{i}_assert_bit"),
                bit_shift_marker[i].expr(),
            )?;
            bit_marker_sum += bit_shift_marker[i].expr();
            bit_shift += E::BaseField::from_canonical_usize(i).expr() * bit_shift_marker[i].expr();

            match kind {
                InsnKind::SLL => {
                    circuit_builder.condition_require_zero(
                        || "bit_multiplier_left_condition",
                        bit_shift_marker[i].expr(),
                        bit_multiplier_left.expr()
                            - E::BaseField::from_canonical_usize(1 << i).expr(),
                    )?;
                }
                InsnKind::SRL | InsnKind::SRA => {
                    circuit_builder.condition_require_zero(
                        || "bit_multiplier_right_condition",
                        bit_shift_marker[i].expr(),
                        bit_multiplier_right.expr()
                            - E::BaseField::from_canonical_usize(1 << i).expr(),
                    )?;
                }
                _ => unreachable!(),
            }
        }
        circuit_builder.require_one(|| "bit_marker_sum_one_hot", bit_marker_sum.expr())?;

        // Check that a[i] = b[i] <</>> c[i] both on the bit and limb shift level if c <
        // NUM_LIMBS * LIMB_BITS.
        let mut limb_marker_sum = Expression::ZERO;
        let mut limb_shift = Expression::ZERO;
        for i in 0..NUM_LIMBS {
            circuit_builder.assert_bit(
                || format!("limb_shift_marker_{i}_assert_bit"),
                limb_shift_marker[i].expr(),
            )?;
            limb_marker_sum += limb_shift_marker[i].expr();
            limb_shift +=
                E::BaseField::from_canonical_usize(i).expr() * limb_shift_marker[i].expr();

            for j in 0..NUM_LIMBS {
                match kind {
                    InsnKind::SLL => {
                        if j < i {
                            circuit_builder.condition_require_zero(
                                || format!("limb_shift_marker_a_{j}"),
                                limb_shift_marker[i].expr(),
                                a[j].expr(),
                            )?;
                        } else {
                            let expected_a_left = if j - i == 0 {
                                Expression::ZERO
                            } else {
                                bit_shift_carry[j - i - 1].expr()
                            } + b[j - i].expr() * bit_multiplier_left.expr()
                                - E::BaseField::from_canonical_usize(1 << LIMB_BITS).expr()
                                    * bit_shift_carry[j - i].expr();
                            circuit_builder.condition_require_zero(
                                || format!("limb_shift_marker_a_expected_a_left_{j}",),
                                limb_shift_marker[i].expr(),
                                a[j].expr() - expected_a_left,
                            )?;
                        }
                    }
                    InsnKind::SRL | InsnKind::SRA => {
                        // SRL and SRA constraints. Combining with above would require an additional column.
                        if j + i > NUM_LIMBS - 1 {
                            circuit_builder.condition_require_zero(
                                || format!("limb_shift_marker_a_{j}"),
                                limb_shift_marker[i].expr(),
                                b_sign.expr()
                                    * E::BaseField::from_canonical_usize((1 << LIMB_BITS) - 1)
                                        .expr(),
                            )?;
                        } else {
                            let expected_a_right =
                                if j + i == NUM_LIMBS - 1 {
                                    b_sign.expr() * (bit_multiplier_right.expr() - Expression::ONE)
                                } else {
                                    bit_shift_carry[j + i + 1].expr()
                                } * E::BaseField::from_canonical_usize(1 << LIMB_BITS).expr()
                                    + (b[j + i].expr() - bit_shift_carry[j + i].expr());

                            circuit_builder.condition_require_zero(
                                || format!("limb_shift_marker_a_expected_a_left_{j}",),
                                limb_shift_marker[i].expr(),
                                a[j].expr() * bit_multiplier_right.expr() - expected_a_right,
                            )?;
                        }
                    }
                    _ => unimplemented!(),
                }
            }
        }
        circuit_builder.require_one(|| "limb_marker_sum_one_hot", limb_marker_sum.expr())?;

        // Check that bit_shift and limb_shift are correct.
        let num_bits = E::BaseField::from_canonical_usize(NUM_LIMBS * LIMB_BITS);
        // TODO switch to assert_ux_v2 once support dynamic table range check
        // circuit_builder.assert_ux_v2(
        //     || "bit_shift_vs_limb_shift",
        //     (c[0].expr()
        //         - limb_shift * E::BaseField::from_canonical_usize(LIMB_BITS).expr()
        //         - bit_shift.expr())
        //         * num_bits.inverse().expr(),
        //     LIMB_BITS - ((NUM_LIMBS * LIMB_BITS) as u32).ilog2() as usize,
        // )?;
        circuit_builder.assert_ux_in_u16(
            || "bit_shift_vs_limb_shift",
            LIMB_BITS - ((NUM_LIMBS * LIMB_BITS) as u32).ilog2() as usize,
            (c[0].expr()
                - limb_shift * E::BaseField::from_canonical_usize(LIMB_BITS).expr()
                - bit_shift.expr())
                * num_bits.inverse().expr(),
        )?;
        if !matches!(kind, InsnKind::SRA) {
            circuit_builder.require_zero(|| "b_sign_zero", b_sign.expr())?;
        } else {
            let mask = E::BaseField::from_canonical_u32(1 << (LIMB_BITS - 1)).expr();
            let b_sign_shifted = b_sign.expr() * mask.expr();
            circuit_builder.lookup_xor_byte(
                b[NUM_LIMBS - 1].expr(),
                mask.expr(),
                b[NUM_LIMBS - 1].expr() + mask.expr()
                    - (E::BaseField::from_canonical_u32(2).expr()) * b_sign_shifted.expr(),
            )?;
        }

        for (i, carry) in bit_shift_carry.iter().enumerate() {
            // TODO replace `LIMB_BITS` with `bit_shift` so we can support more strict range check
            // `bit_shift` could be expression
            // TODO refactor range check to support dynamic range
            circuit_builder.assert_ux_v2(
                || format!("bit_shift_carry_range_check_{i}"),
                carry.expr(),
                LIMB_BITS,
            )?;
        }

        Ok(Self {
            bit_shift_marker,
            bit_multiplier_left,
            bit_multiplier_right,
            limb_shift_marker,
            bit_shift_carry,
            b_sign,
            phantom: PhantomData,
        })
    }

    pub fn assign_instances(
        &self,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut crate::witness::LkMultiplicity,
        kind: InsnKind,
        b: u32,
        c: u32,
    ) {
        let b = split_to_limb::<_, LIMB_BITS>(b);
        let c = split_to_limb::<_, LIMB_BITS>(c);
        let (_, limb_shift, bit_shift) = run_shift::<NUM_LIMBS, LIMB_BITS>(
            kind,
            &b.clone().try_into().unwrap(),
            &c.clone().try_into().unwrap(),
        );

        match kind {
            InsnKind::SLL => set_val!(
                instance,
                self.bit_multiplier_left,
                E::BaseField::from_canonical_usize(1 << bit_shift)
            ),
            _ => set_val!(
                instance,
                self.bit_multiplier_right,
                E::BaseField::from_canonical_usize(1 << bit_shift)
            ),
        };

        let bit_shift_carry: [u32; NUM_LIMBS] = array::from_fn(|i| match kind {
            InsnKind::SLL => b[i] >> (LIMB_BITS - bit_shift),
            _ => b[i] % (1 << bit_shift),
        });
        for (val, witin) in bit_shift_carry.iter().zip_eq(&self.bit_shift_carry) {
            set_val!(instance, witin, E::BaseField::from_canonical_u32(*val));
            lk_multiplicity.assert_ux_v2(*val as u64, LIMB_BITS);
        }
        for (i, witin) in self.bit_shift_marker.iter().enumerate() {
            set_val!(instance, witin, E::BaseField::from_bool(i == bit_shift));
        }
        for (i, witin) in self.limb_shift_marker.iter().enumerate() {
            set_val!(instance, witin, E::BaseField::from_bool(i == limb_shift));
        }
        let num_bits_log = (NUM_LIMBS * LIMB_BITS).ilog2();
        lk_multiplicity.assert_ux_in_u16(
            LIMB_BITS - num_bits_log as usize,
            (((c[0] as usize) - bit_shift - limb_shift * LIMB_BITS)
                >> num_bits_log) as u64,
        );

        let mut b_sign = 0;
        if matches!(kind, InsnKind::SRA) {
            b_sign = b[NUM_LIMBS - 1] >> (LIMB_BITS - 1);
            lk_multiplicity.lookup_xor_byte(b[NUM_LIMBS - 1] as u64, 1 << (LIMB_BITS - 1));
        }
        set_val!(instance, self.b_sign, E::BaseField::from_bool(b_sign != 0));
    }
}

pub struct ShiftConfig<E: ExtensionField> {
    shift_base_config: ShiftBaseConfig<E, UINT_LIMBS, LIMB_BITS>,
    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    pub rd_written: UInt<E>,
    r_insn: RInstructionConfig<E>,
}

pub struct ShiftLogicalInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ShiftLogicalInstruction<E, I> {
    type InstructionConfig = ShiftConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut crate::circuit_builder::CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, crate::error::ZKVMError> {
        let (rd_written, rs1_read, rs2_read) = match I::INST_KIND {
            InsnKind::SLL => {
                let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
                let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
                let rd_written = UInt::new(|| "rd_written", circuit_builder)?;
                (rd_written, rs1_read, rs2_read)
            }
            _ => unimplemented!(),
        };

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        let shift_base_config = ShiftBaseConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rd_written.register_expr(),
            rs1_read.register_expr(),
            rs2_read.register_expr(),
        )?;

        Ok(ShiftConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
            shift_base_config,
        })
    }

    fn assign_instance(
        config: &ShiftConfig<E>,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut crate::witness::LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), crate::error::ZKVMError> {
        // rs2 & its derived values
        let rs2_read = Value::new_unchecked(step.rs2().unwrap().value);
        // let rs2_low5 = rs2_read.as_u64() & 0b11111;
        // lk_multiplicity.assert_ux::<5>(rs2_low5);
        // lk_multiplicity.lookup_pow2(rs2_low5);
        //
        // let pow2_rs2_low5 = 1u64 << rs2_low5;
        //
        // let rs2_high = Value::new(
        //     ((rs2_read.as_u64() - rs2_low5) >> 5) as u32,
        //     lk_multiplicity,
        // );
        // config.rs2_high.assign_value(instance, rs2_high);
        // config.rs2_read.assign_value(instance, rs2_read);
        //
        // set_val!(instance, config.pow2_rs2_low5, pow2_rs2_low5);
        // set_val!(instance, config.rs2_low5, rs2_low5);
        //
        // rs1
        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
        // rd
        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);
        // // outflow
        // let outflow = match I::INST_KIND {
        //     InsnKind::SLL => (rs1_read.as_u64() * pow2_rs2_low5) >> UInt::<E>::TOTAL_BITS,
        //     InsnKind::SRL => rs1_read.as_u64() & (pow2_rs2_low5 - 1),
        //     InsnKind::SRA => {
        //         let Some(signed_ext_config) = config.signed_extend_config.as_ref() else {
        //             Err(ZKVMError::CircuitError)?
        //         };
        //         signed_ext_config.assign_instance(
        //             instance,
        //             lk_multiplicity,
        //             *rs1_read.as_u16_limbs().last().unwrap() as u64,
        //         )?;
        //         rs1_read.as_u64() & (pow2_rs2_low5 - 1)
        //     }
        //     _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        // };
        //
        // set_val!(instance, config.outflow, outflow);
        //
        config.rs1_read.assign_value(instance, rs1_read);
        config.rs2_read.assign_value(instance, rs2_read);
        config.rd_written.assign_value(instance, rd_written);

        config.shift_base_config.assign_instances(
            instance,
            lk_multiplicity,
            I::INST_KIND,
            step.rs1().unwrap().value,
            step.rs2().unwrap().value,
        );
        // config.assert_lt_config.assign_instance(
        //     instance,
        //     lk_multiplicity,
        //     outflow,
        //     pow2_rs2_low5,
        // )?;
        //
        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}

fn run_shift<const NUM_LIMBS: usize, const LIMB_BITS: usize>(
    kind: InsnKind,
    x: &[u32; NUM_LIMBS],
    y: &[u32; NUM_LIMBS],
) -> ([u32; NUM_LIMBS], usize, usize) {
    match kind {
        InsnKind::SLL => run_shift_left::<NUM_LIMBS, LIMB_BITS>(x, y),
        InsnKind::SRL => run_shift_right::<NUM_LIMBS, LIMB_BITS>(x, y, true),
        InsnKind::SRA => run_shift_right::<NUM_LIMBS, LIMB_BITS>(x, y, false),
        _ => unreachable!(),
    }
}

fn run_shift_left<const NUM_LIMBS: usize, const LIMB_BITS: usize>(
    x: &[u32; NUM_LIMBS],
    y: &[u32; NUM_LIMBS],
) -> ([u32; NUM_LIMBS], usize, usize) {
    let mut result = [0u32; NUM_LIMBS];

    let (limb_shift, bit_shift) = get_shift::<NUM_LIMBS, LIMB_BITS>(y);

    for i in limb_shift..NUM_LIMBS {
        result[i] = if i > limb_shift {
            ((x[i - limb_shift] << bit_shift) + (x[i - limb_shift - 1] >> (LIMB_BITS - bit_shift)))
                % (1 << LIMB_BITS)
        } else {
            (x[i - limb_shift] << bit_shift) % (1 << LIMB_BITS)
        };
    }
    (result, limb_shift, bit_shift)
}

fn run_shift_right<const NUM_LIMBS: usize, const LIMB_BITS: usize>(
    x: &[u32; NUM_LIMBS],
    y: &[u32; NUM_LIMBS],
    logical: bool,
) -> ([u32; NUM_LIMBS], usize, usize) {
    let fill = if logical {
        0
    } else {
        ((1 << LIMB_BITS) - 1) * (x[NUM_LIMBS - 1] >> (LIMB_BITS - 1))
    };
    let mut result = [fill; NUM_LIMBS];

    let (limb_shift, bit_shift) = get_shift::<NUM_LIMBS, LIMB_BITS>(y);

    for i in 0..(NUM_LIMBS - limb_shift) {
        result[i] = if i + limb_shift + 1 < NUM_LIMBS {
            ((x[i + limb_shift] >> bit_shift) + (x[i + limb_shift + 1] << (LIMB_BITS - bit_shift)))
                % (1 << LIMB_BITS)
        } else {
            ((x[i + limb_shift] >> bit_shift) + (fill << (LIMB_BITS - bit_shift)))
                % (1 << LIMB_BITS)
        }
    }
    (result, limb_shift, bit_shift)
}

fn get_shift<const NUM_LIMBS: usize, const LIMB_BITS: usize>(y: &[u32]) -> (usize, usize) {
    // We assume `NUM_LIMBS * LIMB_BITS <= 2^LIMB_BITS` so so the shift is defined
    // entirely in y[0].
    let shift = (y[0] as usize) % (NUM_LIMBS * LIMB_BITS);
    (shift / LIMB_BITS, shift % LIMB_BITS)
}
