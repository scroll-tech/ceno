use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::InsnKind;
use ff_ext::ExtensionField;

use crate::{
    Value,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::{AssertLTConfig, SignedExtendConfig},
    instructions::Instruction,
    set_val,
};

use super::{RIVInstruction, constants::UInt, r_insn::RInstructionConfig};

pub struct ShiftConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    rd_written: UInt<E>,

    rs2_high: UInt<E>,
    rs2_low5: WitIn,
    pow2_rs2_low5: WitIn,

    outflow: WitIn,
    assert_lt_config: AssertLTConfig,

    // SRA
    signed_extend_config: Option<SignedExtendConfig<E>>,
}

pub struct ShiftLogicalInstruction<E, I>(PhantomData<(E, I)>);

pub struct SllOp;
impl RIVInstruction for SllOp {
    const INST_KIND: InsnKind = InsnKind::SLL;
}

pub struct SrlOp;
impl RIVInstruction for SrlOp {
    const INST_KIND: InsnKind = InsnKind::SRL;
}

pub struct SraOp;
impl RIVInstruction for SraOp {
    const INST_KIND: InsnKind = InsnKind::SRA;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ShiftLogicalInstruction<E, I> {
    type InstructionConfig = ShiftConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut crate::circuit_builder::CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, crate::error::ZKVMError> {
        // treat bit shifting as a bit "inflow" and "outflow" process, flowing from left to right or vice versa
        // this approach simplifies constraint and witness allocation compared to using multiplication/division gadget,
        // as the divisor/multiplier is a power of 2.
        //
        // example: right shift (bit flow from left to right)
        //    inflow || rs1_read == rd_written || outflow
        // in this case, inflow consists of either all 0s or all 1s for sign extension (if the value is signed).
        //
        // for left shifts, the inflow is always 0:
        //    rs1_read || inflow == outflow || rd_written
        //
        // additional constraint: outflow < (1 << shift), which lead to unique solution

        // soundness: take Goldilocks as example, both sides of the equation are 63 bits numbers (<2**63)
        // rd_written * pow2_rs2_low5 + outflow == inflow * 2**32 + rs1_read
        // 32 + 31.                     31.        31 + 32.         32.     (Bit widths)

        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
        let rs2_low5 = circuit_builder.create_witin(|| "rs2_low5");
        // pow2_rs2_low5 is unchecked because it's assignment will be constrained due it's use in lookup_pow2 below
        let pow2_rs2_low5 = circuit_builder.create_witin(|| "pow2_rs2_low5");
        // rs2 = rs2_high | rs2_low5
        let rs2_high = UInt::new(|| "rs2_high", circuit_builder)?;

        let outflow = circuit_builder.create_witin(|| "outflow");
        let assert_lt_config = AssertLTConfig::construct_circuit(
            circuit_builder,
            || "outflow < pow2_rs2_low5",
            outflow.expr(),
            pow2_rs2_low5.expr(),
            2,
        )?;

        let two_pow_total_bits: Expression<_> = (1u64 << UInt::<E>::TOTAL_BITS).into();

        let signed_extend_config = match I::INST_KIND {
            InsnKind::SLL => {
                circuit_builder.require_equal(
                    || "shift check",
                    rs1_read.value() * pow2_rs2_low5.expr(),
                    outflow.expr() * two_pow_total_bits + rd_written.value(),
                )?;
                None
            }
            InsnKind::SRL | InsnKind::SRA => {
                let (inflow, signed_extend_config) = match I::INST_KIND {
                    InsnKind::SRA => {
                        let signed_extend_config = rs1_read.is_negative(circuit_builder)?;
                        let msb_expr = signed_extend_config.expr();
                        let ones = pow2_rs2_low5.expr() - Expression::ONE;
                        (msb_expr * ones, Some(signed_extend_config))
                    }
                    InsnKind::SRL => (Expression::ZERO, None),
                    _ => unreachable!(),
                };

                circuit_builder.require_equal(
                    || "shift check",
                    rd_written.value() * pow2_rs2_low5.expr() + outflow.expr(),
                    inflow * two_pow_total_bits + rs1_read.value(),
                )?;
                signed_extend_config
            }
            _ => unreachable!(),
        };

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        circuit_builder.lookup_pow2(rs2_low5.expr(), pow2_rs2_low5.expr())?;
        circuit_builder.assert_ux::<_, _, 5>(|| "rs2_low5 in u5", rs2_low5.expr())?;
        circuit_builder.require_equal(
            || "rs2 == rs2_high * 2^5 + rs2_low5",
            rs2_read.value(),
            (rs2_high.value() << 5) + rs2_low5.expr(),
        )?;

        Ok(ShiftConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
            rs2_high,
            rs2_low5,
            pow2_rs2_low5,
            outflow,
            assert_lt_config,
            signed_extend_config,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [std::mem::MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut crate::witness::LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), crate::error::ZKVMError> {
        // rs2 & its derived values
        let rs2_read = Value::new_unchecked(step.rs2().unwrap().value);
        let rs2_low5 = rs2_read.as_u64() & 0b11111;
        lk_multiplicity.assert_ux::<5>(rs2_low5);
        lk_multiplicity.lookup_pow2(rs2_low5);

        let pow2_rs2_low5 = 1u64 << rs2_low5;

        let rs2_high = Value::new(
            ((rs2_read.as_u64() - rs2_low5) >> 5) as u32,
            lk_multiplicity,
        );
        config.rs2_high.assign_value(instance, rs2_high);
        config.rs2_read.assign_value(instance, rs2_read);

        set_val!(instance, config.pow2_rs2_low5, pow2_rs2_low5);
        set_val!(instance, config.rs2_low5, rs2_low5);

        // rs1
        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);

        // rd
        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);

        // outflow
        let outflow = match I::INST_KIND {
            InsnKind::SLL => (rs1_read.as_u64() * pow2_rs2_low5) >> UInt::<E>::TOTAL_BITS,
            InsnKind::SRL => rs1_read.as_u64() & (pow2_rs2_low5 - 1),
            InsnKind::SRA => {
                let Some(signed_ext_config) = config.signed_extend_config.as_ref() else {
                    Err(ZKVMError::CircuitError)?
                };
                signed_ext_config.assign_instance(
                    instance,
                    lk_multiplicity,
                    *rs1_read.as_u16_limbs().last().unwrap() as u64,
                )?;
                rs1_read.as_u64() & (pow2_rs2_low5 - 1)
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        set_val!(instance, config.outflow, outflow);

        config.rs1_read.assign_value(instance, rs1_read);
        config.rd_written.assign_value(instance, rd_written);

        config.assert_lt_config.assign_instance(
            instance,
            lk_multiplicity,
            outflow,
            pow2_rs2_low5,
        )?;

        config
            .r_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ceno_emul::{Change, InsnKind, StepRecord, encode_rv32};
    use goldilocks::GoldilocksExt2;

    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            Instruction,
            riscv::{RIVInstruction, constants::UInt},
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    use super::{ShiftLogicalInstruction, SllOp, SraOp, SrlOp};

    #[test]
    fn test_opcode_sll() {
        verify::<SllOp>("basic", 0b_0001, 3, 0b_1000);
        // 33 << 33 === 33 << 1
        verify::<SllOp>("rs2 over 5-bits", 0b_0001, 33, 0b_0010);
        verify::<SllOp>("bit loss", 1 << 31 | 1, 1, 0b_0010);
        verify::<SllOp>("zero shift", 0b_0001, 0, 0b_0001);
        verify::<SllOp>("all zeros", 0b_0000, 0, 0b_0000);
        verify::<SllOp>("base is zero", 0b_0000, 1, 0b_0000);
    }

    #[test]
    fn test_opcode_srl() {
        verify::<SrlOp>("basic", 0b_1000, 3, 0b_0001);
        // 33 >> 33 === 33 >> 1
        verify::<SrlOp>("rs2 over 5-bits", 0b_1010, 33, 0b_0101);
        verify::<SrlOp>("bit loss", 0b_1001, 1, 0b_0100);
        verify::<SrlOp>("zero shift", 0b_1000, 0, 0b_1000);
        verify::<SrlOp>("all zeros", 0b_0000, 0, 0b_0000);
        verify::<SrlOp>("base is zero", 0b_0000, 1, 0b_0000);
    }

    #[test]
    fn test_opcode_sra() {
        // positive rs1
        // rs2 = 3
        verify::<SraOp>("32 >> 3", 32, 3, 32 >> 3);
        verify::<SraOp>("33 >> 3", 33, 3, 33 >> 3);
        // rs2 = 31
        verify::<SraOp>("32 >> 31", 32, 31, 32 >> 31);
        verify::<SraOp>("33 >> 31", 33, 31, 33 >> 31);

        // negative rs1
        // rs2 = 3
        verify::<SraOp>("-32 >> 3", (-32_i32) as u32, 3, (-32_i32 >> 3) as u32);
        verify::<SraOp>("-33 >> 3", (-33_i32) as u32, 3, (-33_i32 >> 3) as u32);
        // rs2 = 31
        verify::<SraOp>("-32 >> 31", (-32_i32) as u32, 31, (-32_i32 >> 31) as u32);
        verify::<SraOp>("-33 >> 31", (-33_i32) as u32, 31, (-33_i32 >> 31) as u32);
    }

    fn verify<I: RIVInstruction>(
        name: &'static str,
        rs1_read: u32,
        rs2_read: u32,
        expected_rd_written: u32,
    ) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let shift = rs2_read & 0b11111;
        let (prefix, insn_code, rd_written) = match I::INST_KIND {
            InsnKind::SLL => (
                "SLL",
                encode_rv32(InsnKind::SLL, 2, 3, 4, 0),
                rs1_read << shift,
            ),
            InsnKind::SRL => (
                "SRL",
                encode_rv32(InsnKind::SRL, 2, 3, 4, 0),
                rs1_read >> shift,
            ),
            InsnKind::SRA => (
                "SRA",
                encode_rv32(InsnKind::SRA, 2, 3, 4, 0),
                (rs1_read as i32 >> shift) as u32,
            ),
            _ => unreachable!(),
        };

        let config = cb
            .namespace(
                || format!("{prefix}_({name})"),
                ShiftLogicalInstruction::<GoldilocksExt2, I>::construct_circuit,
            )
            .unwrap();

        config
            .rd_written
            .require_equal(
                || format!("{prefix}_({name})_assert_rd_written"),
                &mut cb,
                &UInt::from_const_unchecked(
                    Value::new_unchecked(expected_rd_written)
                        .as_u16_limbs()
                        .to_vec(),
                ),
            )
            .unwrap();

        let (raw_witin, lkm) = ShiftLogicalInstruction::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1_read,
                rs2_read,
                Change::new(0, rd_written),
                0,
            )],
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
