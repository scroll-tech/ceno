use super::RIVInstruction;
use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::{AssertLtConfig, SignedExtendConfig},
    instructions::{
        Instruction,
        riscv::{constants::UInt, i_insn::IInstructionConfig},
    },
    set_val,
    tables::InsnRecord,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use std::marker::PhantomData;

pub struct ShiftImmConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    imm: WitIn,
    rs1_read: UInt<E>,
    rd_written: UInt<E>,
    outflow: WitIn,
    assert_lt_config: AssertLtConfig,

    // SRAI
    is_lt_config: Option<SignedExtendConfig<E>>,
}

pub struct ShiftImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct SlliOp;
impl RIVInstruction for SlliOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLLI;
}
pub type SlliInstruction<E> = ShiftImmInstruction<E, SlliOp>;

pub struct SraiOp;
impl RIVInstruction for SraiOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SRAI;
}
pub type SraiInstruction<E> = ShiftImmInstruction<E, SraiOp>;

pub struct SrliOp;
impl RIVInstruction for SrliOp {
    const INST_KIND: ceno_emul::InsnKind = InsnKind::SRLI;
}
pub type SrliInstruction<E> = ShiftImmInstruction<E, SrliOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for ShiftImmInstruction<E, I> {
    type InstructionConfig = ShiftImmConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
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
        // rd * imm + outflow == inflow * 2**32 + rs1
        // 32 + 31.   31.        31 + 32.         32.     (Bit widths)

        // Note: `imm` wtns is set to 2**imm (upto 32 bit) just for efficient verification.
        let imm = circuit_builder.create_witin(|| "imm");
        let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
        let rd_written = UInt::new(|| "rd_written", circuit_builder)?;

        let outflow = circuit_builder.create_witin(|| "outflow");
        let assert_lt_config = AssertLtConfig::construct_circuit(
            circuit_builder,
            || "outflow < imm",
            outflow.expr(),
            imm.expr(),
            2,
        )?;

        let two_pow_total_bits: Expression<_> = (1u64 << UInt::<E>::TOTAL_BITS).into();

        let is_lt_config = match I::INST_KIND {
            InsnKind::SLLI => {
                circuit_builder.require_equal(
                    || "shift check",
                    rs1_read.value() * imm.expr(), // inflow is zero for this case
                    outflow.expr() * two_pow_total_bits + rd_written.value(),
                )?;
                None
            }
            InsnKind::SRAI | InsnKind::SRLI => {
                let (inflow, is_lt_config) = match I::INST_KIND {
                    InsnKind::SRAI => {
                        let is_rs1_neg = rs1_read.is_negative(circuit_builder)?;
                        let ones = imm.expr() - 1;
                        (is_rs1_neg.expr() * ones, Some(is_rs1_neg))
                    }
                    InsnKind::SRLI => (Expression::ZERO, None),
                    _ => unreachable!(),
                };
                circuit_builder.require_equal(
                    || "shift check",
                    rd_written.value() * imm.expr() + outflow.expr(),
                    inflow * two_pow_total_bits + rs1_read.value(),
                )?;
                is_lt_config
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            &imm.expr(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
        )?;

        Ok(ShiftImmConfig {
            i_insn,
            imm,
            rs1_read,
            rd_written,
            outflow,
            assert_lt_config,
            is_lt_config,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // imm_internal is a precomputed 2**shift.
        let imm = InsnRecord::imm_internal(&step.insn()) as u64;
        let rs1_read = Value::new_unchecked(step.rs1().unwrap().value);
        let rd_written = Value::new(step.rd().unwrap().value.after, lk_multiplicity);

        set_val!(instance, config.imm, imm);
        config.rs1_read.assign_value(instance, rs1_read.clone());
        config.rd_written.assign_value(instance, rd_written);

        let outflow = match I::INST_KIND {
            InsnKind::SLLI => (rs1_read.as_u64() * imm) >> UInt::<E>::TOTAL_BITS,
            InsnKind::SRAI | InsnKind::SRLI => {
                if I::INST_KIND == InsnKind::SRAI {
                    config.is_lt_config.as_ref().unwrap().assign_instance(
                        instance,
                        lk_multiplicity,
                        *rs1_read.as_u16_limbs().last().unwrap() as u64,
                    )?;
                }

                rs1_read.as_u64() & (imm - 1)
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        set_val!(instance, config.outflow, outflow);
        config
            .assert_lt_config
            .assign_instance(instance, lk_multiplicity, outflow, imm)?;

        config
            .i_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32u};
    use goldilocks::GoldilocksExt2;

    use super::{ShiftImmInstruction, SlliOp, SraiOp, SrliOp};
    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            Instruction,
            riscv::{RIVInstruction, constants::UInt},
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    #[test]
    fn test_opcode_slli() {
        // imm = 3
        verify::<SlliOp>("32 << 3", 32, 3, 32 << 3);
        verify::<SlliOp>("33 << 3", 33, 3, 33 << 3);
        // imm = 31
        verify::<SlliOp>("32 << 31", 32, 31, 32 << 31);
        verify::<SlliOp>("33 << 31", 33, 31, 33 << 31);
    }

    #[test]
    fn test_opcode_srai() {
        // positive rs1
        // imm = 3
        verify::<SraiOp>("32 >> 3", 32, 3, 32 >> 3);
        verify::<SraiOp>("33 >> 3", 33, 3, 33 >> 3);
        // imm = 31
        verify::<SraiOp>("32 >> 31", 32, 31, 32 >> 31);
        verify::<SraiOp>("33 >> 31", 33, 31, 33 >> 31);

        // negative rs1
        // imm = 3
        verify::<SraiOp>("-32 >> 3", (-32_i32) as u32, 3, (-32_i32 >> 3) as u32);
        verify::<SraiOp>("-33 >> 3", (-33_i32) as u32, 3, (-33_i32 >> 3) as u32);
        // imm = 31
        verify::<SraiOp>("-32 >> 31", (-32_i32) as u32, 31, (-32_i32 >> 31) as u32);
        verify::<SraiOp>("-33 >> 31", (-33_i32) as u32, 31, (-33_i32 >> 31) as u32);
    }

    #[test]
    fn test_opcode_srli() {
        // imm = 3
        verify::<SrliOp>("32 >> 3", 32, 3, 32 >> 3);
        verify::<SrliOp>("33 >> 3", 33, 3, 33 >> 3);
        // imm = 31
        verify::<SrliOp>("32 >> 31", 32, 31, 32 >> 31);
        verify::<SrliOp>("33 >> 31", 33, 31, 33 >> 31);
        // rs1 top bit is 1
        verify::<SrliOp>("-32 >> 3", (-32_i32) as u32, 3, (-32_i32) as u32 >> 3);
    }

    fn verify<I: RIVInstruction>(
        name: &'static str,
        rs1_read: u32,
        imm: u32,
        expected_rd_written: u32,
    ) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let (prefix, insn_code, rd_written) = match I::INST_KIND {
            InsnKind::SLLI => (
                "SLLI",
                encode_rv32u(InsnKind::SLLI, 2, 0, 4, imm),
                rs1_read << imm,
            ),
            InsnKind::SRAI => (
                "SRAI",
                encode_rv32u(InsnKind::SRAI, 2, 0, 4, imm),
                (rs1_read as i32 >> imm as i32) as u32,
            ),
            InsnKind::SRLI => (
                "SRLI",
                encode_rv32u(InsnKind::SRLI, 2, 0, 4, imm),
                rs1_read >> imm,
            ),
            _ => unreachable!(),
        };

        let config = cb
            .namespace(
                || format!("{prefix}_({name})"),
                |cb| {
                    let config = ShiftImmInstruction::<GoldilocksExt2, I>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
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

        let (raw_witin, lkm) = ShiftImmInstruction::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                rs1_read,
                Change::new(0, rd_written),
                0,
            )],
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
