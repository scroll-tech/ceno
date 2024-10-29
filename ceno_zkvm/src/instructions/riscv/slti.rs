use std::marker::PhantomData;

use ceno_emul::{InsnKind, SWord, StepRecord, Word};
use ff_ext::ExtensionField;

use super::{
    RIVInstruction,
    constants::{UINT_LIMBS, UInt},
    i_insn::IInstructionConfig,
};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::IsLtConfig,
    instructions::Instruction,
    set_val,
    tables::InsnRecord,
    uint::Value,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

#[derive(Debug)]
pub struct SetLessThanImmConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt<E>,
    imm: WitIn,
    #[allow(dead_code)]
    rd_written: UInt<E>,
    lt: IsLtConfig,

    // SLTI
    is_rs1_neg: Option<IsLtConfig>,
}

pub struct SetLessThanImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct SltiOp;
impl RIVInstruction for SltiOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLTI;
}

pub struct SltiuOp;
impl RIVInstruction for SltiuOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLTIU;
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for SetLessThanImmInstruction<E, I> {
    type InstructionConfig = SetLessThanImmConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        // If rs1_read < imm, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let imm = cb.create_witin(|| "imm")?;

        let (value_expr, is_rs1_neg) = match I::INST_KIND {
            InsnKind::SLTI => {
                let max_signed_limb_expr: Expression<_> =
                    ((1 << (UInt::<E>::LIMB_BITS - 1)) - 1).into();
                let is_rs1_neg = IsLtConfig::construct_circuit(
                    cb,
                    || "lhs_msb",
                    max_signed_limb_expr,
                    rs1_read.limbs.iter().last().unwrap().expr(), // msb limb
                    1,
                )?;
                (rs1_read.to_field_expr(is_rs1_neg.expr()), Some(is_rs1_neg))
            }
            InsnKind::SLTIU => (rs1_read.value(), None),
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let lt =
            IsLtConfig::construct_circuit(cb, || "rs1 < imm", value_expr, imm.expr(), UINT_LIMBS)?;
        let rd_written = UInt::from_exprs_unchecked(vec![lt.expr()]);

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            &imm.expr(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
        )?;

        Ok(SetLessThanImmConfig {
            i_insn,
            rs1_read,
            imm,
            rd_written,
            is_rs1_neg,
            lt,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config.i_insn.assign_instance(instance, lkm, step)?;

        let rs1 = step.rs1().unwrap().value;
        let max_signed_limb = (1u64 << (UInt::<E>::LIMB_BITS - 1)) - 1;
        let rs1_value = Value::new_unchecked(rs1 as Word);
        config
            .rs1_read
            .assign_value(instance, Value::new_unchecked(rs1));

        let imm = step.insn().imm_or_funct7();
        let imm_field = InsnRecord::imm_or_funct7_field::<E::BaseField>(&step.insn());
        set_val!(instance, config.imm, imm_field);

        match I::INST_KIND {
            InsnKind::SLTI => {
                config.is_rs1_neg.as_ref().unwrap().assign_instance(
                    instance,
                    lkm,
                    max_signed_limb,
                    *rs1_value.limbs.last().unwrap() as u64,
                )?;
                config
                    .lt
                    .assign_instance_signed(instance, lkm, rs1 as SWord, imm as SWord)?;
            }
            InsnKind::SLTIU => {
                config
                    .lt
                    .assign_instance(instance, lkm, rs1 as u64, imm as u64)?;
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, PC_STEP_SIZE, StepRecord, Word, encode_rv32};
    use goldilocks::GoldilocksExt2;

    use rand::Rng;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::test_utils::imm_i},
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    #[test]
    fn test_slti_true() {
        verify_slti("lt = true, 0 < 1", 0, 1, 1);
        verify_slti("lt = true, 1 < 2", 1, 2, 1);
        verify_slti("lt = true, -1 < 0", -1, 0, 1);
        verify_slti("lt = true, -1 < 1", -1, 1, 1);
        verify_slti("lt = true, -2 < -1", -2, -1, 1);
        // -2048 <= imm <= 2047
        verify_slti("lt = true, imm upper bondary", i32::MIN, 2047, 1);
        verify_slti("lt = true, imm lower bondary", i32::MIN, -2048, 1);
    }

    #[test]
    fn test_slti_false() {
        verify_slti("lt = false, 1 < 0", 1, 0, 0);
        verify_slti("lt = false, 2 < 1", 2, 1, 0);
        verify_slti("lt = false, 0 < -1", 0, -1, 0);
        verify_slti("lt = false, 1 < -1", 1, -1, 0);
        verify_slti("lt = false, -1 < -2", -1, -2, 0);
        verify_slti("lt = false, 0 == 0", 0, 0, 0);
        verify_slti("lt = false, 1 == 1", 1, 1, 0);
        verify_slti("lt = false, -1 == -1", -1, -1, 0);
        // -2048 <= imm <= 2047
        verify_slti("lt = false, imm upper bondary", i32::MAX, 2047, 0);
        verify_slti("lt = false, imm lower bondary", i32::MAX, -2048, 0);
    }

    #[test]
    fn test_slti_random() {
        let mut rng = rand::thread_rng();
        let a: i32 = rng.gen();
        let b: i32 = rng.gen::<i32>() % 2048;
        println!("random: {} <? {}", a, b); // For debugging, do not delete.
        verify_slti("random 1", a, b, (a < b) as u32);
    }

    fn verify_slti(name: &'static str, rs1: i32, imm: i32, rd: Word) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("SLTI/{name}"),
                |cb| {
                    let config =
                        SetLessThanImmInstruction::<GoldilocksExt2, SltiOp>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::SLTI, 2, 0, 4, imm_i(imm));
        let (raw_witin, lkm) =
            SetLessThanImmInstruction::<GoldilocksExt2, SltiOp>::assign_instances(
                &config,
                cb.cs.num_witin as usize,
                vec![StepRecord::new_i_instruction(
                    3,
                    Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                    insn_code,
                    rs1 as Word,
                    Change::new(0, rd),
                    0,
                )],
            )
            .unwrap();

        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(rd).as_u16_limbs().to_vec());
        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }

    #[test]
    fn test_sltiu_true() {
        verify_sltiu("lt = true, 0 < 1", 0, 1, 1);
        verify_sltiu("lt = true, 1 < 2", 1, 2, 1);
        verify_sltiu("lt = true, 10 < 20", 10, 20, 1);
        verify_sltiu("lt = true, 2000 < 2500", 2000, 2500, 1);
        // 0 <= imm <= 4095
        verify_sltiu("lt = true, 0 < imm upper boundary", 0, 4095, 1);
        verify_sltiu("lt = true, 2047 < imm upper boundary", 2047, 4095, 1);
        verify_sltiu("lt = true, imm upper boundary", 1000, 4095, 1);
    }

    #[test]
    fn test_sltiu_false() {
        verify_sltiu("lt = false, 1 < 0", 1, 0, 0);
        verify_sltiu("lt = false, 2 < 1", 2, 1, 0);
        verify_sltiu("lt = false, 100 < 50", 100, 50, 0);
        verify_sltiu("lt = false, 500 < 100", 500, 100, 0);
        verify_sltiu("lt = false, 2500 < 2500", 2500, 2500, 0);
        verify_sltiu("lt = false, 4095 < 0", 4095, 0, 0);
        verify_sltiu("lt = false, 4095 < 2048", 4095, 2048, 0);
        verify_sltiu("lt = false, 4095 < 4095", 4095, 4095, 0);
        // rs1 max value
        verify_sltiu("lt = false, 0xFFFFFFFF < 0", 0xFFFFFFFF, 0, 0);
        verify_sltiu("lt = false, 0xFFFFFFFF < 4095", 0xFFFFFFFF, 4095, 0);
    }

    #[test]
    fn test_sltiu_random() {
        let mut rng = rand::thread_rng();
        let a: u32 = rng.gen::<u32>();
        let b: u32 = rng.gen::<u32>() % 4096;
        println!("random: {} <? {}", a, b); // For debugging, do not delete.
        verify_sltiu("random unsigned comparison", a, b, (a < b) as u32);
    }

    fn verify_sltiu(name: &'static str, rs1: u32, imm: u32, rd: Word) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("SLTIU/{name}"),
                |cb| {
                    let config =
                        SetLessThanImmInstruction::<GoldilocksExt2, SltiuOp>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::SLTIU, 2, 0, 4, imm);
        let (raw_witin, lkm) =
            SetLessThanImmInstruction::<GoldilocksExt2, SltiuOp>::assign_instances(
                &config,
                cb.cs.num_witin as usize,
                vec![StepRecord::new_i_instruction(
                    3,
                    Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                    insn_code,
                    rs1 as Word,
                    Change::new(0, rd),
                    0,
                )],
            )
            .unwrap();

        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(rd).as_u16_limbs().to_vec());
        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
