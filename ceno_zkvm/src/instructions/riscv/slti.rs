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
    expression::{ToExpr, WitIn},
    gadgets::{IsLtConfig, SignedExtendConfig},
    instructions::Instruction,
    set_val,
    tables::InsnRecord,
    uint::Value,
    utils::i64_to_base,
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
    is_rs1_neg: Option<SignedExtendConfig<E>>,
}

pub struct SetLessThanImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct SltiOp;
impl RIVInstruction for SltiOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLTI;
}
pub type SltiInstruction<E> = SetLessThanImmInstruction<E, SltiOp>;

pub struct SltiuOp;
impl RIVInstruction for SltiuOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLTIU;
}
pub type SltiuInstruction<E> = SetLessThanImmInstruction<E, SltiuOp>;

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for SetLessThanImmInstruction<E, I> {
    type InstructionConfig = SetLessThanImmConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        // If rs1_read < imm, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let imm = cb.create_witin(|| "imm");

        let (value_expr, is_rs1_neg) = match I::INST_KIND {
            InsnKind::SLTIU => (rs1_read.value(), None),
            InsnKind::SLTI => {
                let is_rs1_neg = rs1_read.is_negative(cb)?;
                (
                    rs1_read.to_field_expr((&is_rs1_neg).expr()),
                    Some(is_rs1_neg),
                )
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        };

        let lt = IsLtConfig::construct_circuit(cb, || "rs1 < imm", value_expr, imm, UINT_LIMBS)?;
        let rd_written = UInt::from_exprs_unchecked(vec![(&lt).expr()]);

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            imm,
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
        let rs1_value = Value::new_unchecked(rs1 as Word);
        config
            .rs1_read
            .assign_value(instance, Value::new_unchecked(rs1));

        let imm = InsnRecord::imm_internal(&step.insn());
        set_val!(instance, config.imm, i64_to_base::<E::BaseField>(imm));

        match I::INST_KIND {
            InsnKind::SLTIU => {
                config
                    .lt
                    .assign_instance(instance, lkm, rs1 as u64, imm as u64)?;
            }
            InsnKind::SLTI => {
                config.is_rs1_neg.as_ref().unwrap().assign_instance(
                    instance,
                    lkm,
                    *rs1_value.as_u16_limbs().last().unwrap() as u64,
                )?;
                config
                    .lt
                    .assign_instance_signed(instance, lkm, rs1 as SWord, imm as SWord)?;
            }
            _ => unreachable!("Unsupported instruction kind {:?}", I::INST_KIND),
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, PC_STEP_SIZE, StepRecord, encode_rv32};
    use goldilocks::GoldilocksExt2;

    use rand::Rng;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    #[test]
    fn test_sltiu_true() {
        let verify = |name, a, imm| verify::<SltiuOp>(name, a, imm, true);
        verify("lt = true, 0 < 1", 0, 1);
        verify("lt = true, 1 < 2", 1, 2);
        verify("lt = true, 10 < 20", 10, 20);
        verify("lt = true, 0 < imm upper boundary", 0, 2047);
        // negative imm is treated as positive
        verify("lt = true, 0 < u32::MAX-1", 0, -1);
        verify("lt = true, 1 < u32::MAX-1", 1, -1);
        verify("lt = true, 0 < imm lower bondary", 0, -2048);
    }

    #[test]
    fn test_sltiu_false() {
        let verify = |name, a, imm| verify::<SltiuOp>(name, a, imm, false);
        verify("lt = false, 1 < 0", 1, 0);
        verify("lt = false, 2 < 1", 2, 1);
        verify("lt = false, 100 < 50", 100, 50);
        verify("lt = false, 500 < 100", 500, 100);
        verify("lt = false, 100000 < 2047", 100000, 2047);
        verify("lt = false, 100000 < 0", 100000, 0);
        verify("lt = false, 0 == 0", 0, 0);
        verify("lt = false, 1 == 1", 1, 1);
        verify("lt = false, imm upper bondary", u32::MAX, 2047);
        // negative imm is treated as positive
        verify("lt = false, imm lower bondary", u32::MAX, -2048);
    }

    #[test]
    fn test_sltiu_random() {
        let mut rng = rand::thread_rng();
        let a: u32 = rng.gen::<u32>();
        let b: i32 = rng.gen_range(-2048..2048);
        println!("random: {} <? {}", a, b); // For debugging, do not delete.
        verify::<SltiuOp>("random unsigned comparison", a, b, a < (b as u32));
    }

    #[test]
    fn test_slti_true() {
        let verify = |name, a: i32, imm| verify::<SltiOp>(name, a as u32, imm, true);
        verify("lt = true, 0 < 1", 0, 1);
        verify("lt = true, 1 < 2", 1, 2);
        verify("lt = true, -1 < 0", -1, 0);
        verify("lt = true, -1 < 1", -1, 1);
        verify("lt = true, -2 < -1", -2, -1);
        // -2048 <= imm <= 2047
        verify("lt = true, imm upper bondary", i32::MIN, 2047);
        verify("lt = true, imm lower bondary", i32::MIN, -2048);
    }

    #[test]
    fn test_slti_false() {
        let verify = |name, a: i32, imm| verify::<SltiOp>(name, a as u32, imm, false);
        verify("lt = false, 1 < 0", 1, 0);
        verify("lt = false, 2 < 1", 2, 1);
        verify("lt = false, 0 < -1", 0, -1);
        verify("lt = false, 1 < -1", 1, -1);
        verify("lt = false, -1 < -2", -1, -2);
        verify("lt = false, 0 == 0", 0, 0);
        verify("lt = false, 1 == 1", 1, 1);
        verify("lt = false, -1 == -1", -1, -1);
        // -2048 <= imm <= 2047
        verify("lt = false, imm upper bondary", i32::MAX, 2047);
        verify("lt = false, imm lower bondary", i32::MAX, -2048);
    }

    #[test]
    fn test_slti_random() {
        let mut rng = rand::thread_rng();
        let a: i32 = rng.gen();
        let b: i32 = rng.gen_range(-2048..2048);
        println!("random: {} <? {}", a, b); // For debugging, do not delete.
        verify::<SltiOp>("random 1", a as u32, b, a < b);
    }

    fn verify<I: RIVInstruction>(name: &'static str, rs1_read: u32, imm: i32, expected_rd: bool) {
        let expected_rd = expected_rd as u32;
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let insn_code = encode_rv32(I::INST_KIND, 2, 0, 4, imm as u32);

        let config = cb
            .namespace(
                || format!("{:?}_({name})", I::INST_KIND),
                SetLessThanImmInstruction::<GoldilocksExt2, I>::construct_circuit,
            )
            .unwrap();

        let (raw_witin, lkm) = SetLessThanImmInstruction::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                rs1_read,
                Change::new(0, expected_rd),
                0,
            )],
        )
        .unwrap();

        let expected_rd =
            UInt::from_const_unchecked(Value::new_unchecked(expected_rd).as_u16_limbs().to_vec());
        config
            .rd_written
            .require_equal(
                || format!("{:?}_({name})_assert_rd_written", I::INST_KIND),
                &mut cb,
                &expected_rd,
            )
            .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
