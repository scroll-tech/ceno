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

    is_rs1_neg: IsLtConfig,
    lt: IsLtConfig,
}

pub struct SetLessThanImmInstruction<E, I>(PhantomData<(E, I)>);

pub struct SltiOp;
impl RIVInstruction for SltiOp {
    const INST_KIND: ceno_emul::InsnKind = ceno_emul::InsnKind::SLTI;
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

        let max_signed_limb_expr: Expression<_> = ((1 << (UInt::<E>::LIMB_BITS - 1)) - 1).into();
        let is_rs1_neg = IsLtConfig::construct_circuit(
            cb,
            || "lhs_msb",
            max_signed_limb_expr,
            rs1_read.limbs.iter().last().unwrap().expr(), // msb limb
            1,
        )?;

        let lt = IsLtConfig::construct_circuit(
            cb,
            || "rs1 < imm",
            rs1_read.to_field_expr(is_rs1_neg.expr()),
            imm.expr(),
            UINT_LIMBS,
        )?;
        let rd_written = UInt::from_exprs_unchecked(vec![lt.expr()]);

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            InsnKind::SLTI,
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
        config.is_rs1_neg.assign_instance(
            instance,
            lkm,
            max_signed_limb,
            *rs1_value.limbs.last().unwrap() as u64,
        )?;

        let imm = step.insn().imm_or_funct7();
        let imm_field = InsnRecord::imm_or_funct7_field::<E::BaseField>(&step.insn());
        set_val!(instance, config.imm, imm_field);

        config
            .lt
            .assign_instance_signed(instance, lkm, rs1 as SWord, imm as SWord)?;

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

    fn verify<I: RIVInstruction>(name: &'static str, rs1: i32, imm: i32, rd: Word) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let (prefix, insn_code, rd_written) = match I::INST_KIND {
            InsnKind::SLTI => (
                "SLTI",
                encode_rv32(InsnKind::SLTI, 2, 0, 4, imm_i(imm)),
                (rs1 < imm) as u32,
            ),
            _ => unreachable!(),
        };

        let config = cb
            .namespace(
                || format!("{prefix}_({name})"),
                |cb| {
                    let config =
                        SetLessThanImmInstruction::<GoldilocksExt2, SltiOp>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

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

        assert_eq!(
            rd_written, rd,
            "calculated and expected rd_written mismatch"
        );

        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(rd).as_u16_limbs().to_vec());
        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }

    #[test]
    fn test_slti_true() {
        verify::<SltiOp>("lt = true, 0 < 1", 0, 1, 1);
        verify::<SltiOp>("lt = true, 1 < 2", 1, 2, 1);
        verify::<SltiOp>("lt = true, -1 < 0", -1, 0, 1);
        verify::<SltiOp>("lt = true, -1 < 1", -1, 1, 1);
        verify::<SltiOp>("lt = true, -2 < -1", -2, -1, 1);
        // -2048 <= imm <= 2047
        verify::<SltiOp>("lt = true, imm upper bondary", i32::MIN, 2047, 1);
        verify::<SltiOp>("lt = true, imm lower bondary", i32::MIN, -2048, 1);
    }

    #[test]
    fn test_slti_false() {
        verify::<SltiOp>("lt = false, 1 < 0", 1, 0, 0);
        verify::<SltiOp>("lt = false, 2 < 1", 2, 1, 0);
        verify::<SltiOp>("lt = false, 0 < -1", 0, -1, 0);
        verify::<SltiOp>("lt = false, 1 < -1", 1, -1, 0);
        verify::<SltiOp>("lt = false, -1 < -2", -1, -2, 0);
        verify::<SltiOp>("lt = false, 0 == 0", 0, 0, 0);
        verify::<SltiOp>("lt = false, 1 == 1", 1, 1, 0);
        verify::<SltiOp>("lt = false, -1 == -1", -1, -1, 0);
        // -2048 <= imm <= 2047
        verify::<SltiOp>("lt = false, imm upper bondary", i32::MAX, 2047, 0);
        verify::<SltiOp>("lt = false, imm lower bondary", i32::MAX, -2048, 0);
    }

    #[test]
    fn test_slti_random() {
        let mut rng = rand::thread_rng();
        let a: i32 = rng.gen();
        let b: i32 = rng.gen::<i32>() % 2048;
        println!("random: {} <? {}", a, b); // For debugging, do not delete.
        verify::<SltiOp>("random 1", a, b, (a < b) as u32);
    }
}
