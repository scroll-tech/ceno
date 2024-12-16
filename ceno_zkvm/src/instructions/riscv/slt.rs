use std::marker::PhantomData;

use ceno_emul::{InsnKind, SWord, StepRecord};
use ff_ext::ExtensionField;

use super::{
    RIVInstruction,
    constants::{UINT_LIMBS, UInt},
    r_insn::RInstructionConfig,
};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    gadgets::{IsLtConfig, SignedLtConfig},
    instructions::Instruction,
    uint::Value,
    witness::LkMultiplicity,
};

pub struct SetLessThanInstruction<E, I>(PhantomData<(E, I)>);

pub struct SltOp;
impl RIVInstruction for SltOp {
    const INST_KIND: InsnKind = InsnKind::SLT;
}
pub type SltInstruction<E> = SetLessThanInstruction<E, SltOp>;

pub struct SltuOp;
impl RIVInstruction for SltuOp {
    const INST_KIND: InsnKind = InsnKind::SLTU;
}
pub type SltuInstruction<E> = SetLessThanInstruction<E, SltuOp>;

/// This config handles R-Instructions that represent registers values as 2 * u16.
pub struct SetLessThanConfig<E: ExtensionField> {
    r_insn: RInstructionConfig<E>,

    rs1_read: UInt<E>,
    rs2_read: UInt<E>,
    #[cfg_attr(not(test), allow(dead_code))]
    rd_written: UInt<E>,

    deps: SetLessThanDependencies<E>,
}

enum SetLessThanDependencies<E: ExtensionField> {
    Slt { signed_lt: SignedLtConfig<E> },
    Sltu { is_lt: IsLtConfig },
}

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for SetLessThanInstruction<E, I> {
    type InstructionConfig = SetLessThanConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        // If rs1_read < rs2_read, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let rs2_read = UInt::new_unchecked(|| "rs2_read", cb)?;

        let (deps, rd_written) = match I::INST_KIND {
            InsnKind::SLT => {
                let signed_lt =
                    SignedLtConfig::construct_circuit(cb, || "rs1 < rs2", &rs1_read, &rs2_read)?;
                let rd_written = UInt::from_exprs_unchecked(vec![signed_lt.expr()]);
                (SetLessThanDependencies::Slt { signed_lt }, rd_written)
            }
            InsnKind::SLTU => {
                let is_lt = IsLtConfig::construct_circuit(
                    cb,
                    || "rs1 < rs2",
                    rs1_read.value(),
                    rs2_read.value(),
                    UINT_LIMBS,
                )?;
                let rd_written = UInt::from_exprs_unchecked(vec![is_lt.expr()]);
                (SetLessThanDependencies::Sltu { is_lt }, rd_written)
            }
            _ => unreachable!(),
        };

        let r_insn = RInstructionConfig::<E>::construct_circuit(
            cb,
            I::INST_KIND,
            rs1_read.register_expr(),
            rs2_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(SetLessThanConfig {
            r_insn,
            rs1_read,
            rs2_read,
            rd_written,
            deps,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [<E as ExtensionField>::BaseField],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config.r_insn.assign_instance(instance, lkm, step)?;

        let rs1 = step.rs1().unwrap().value;
        let rs2 = step.rs2().unwrap().value;

        let rs1_read = Value::new_unchecked(rs1);
        let rs2_read = Value::new_unchecked(rs2);
        config
            .rs1_read
            .assign_limbs(instance, rs1_read.as_u16_limbs());
        config
            .rs2_read
            .assign_limbs(instance, rs2_read.as_u16_limbs());

        match &config.deps {
            SetLessThanDependencies::Slt { signed_lt } => {
                signed_lt.assign_instance(instance, lkm, rs1 as SWord, rs2 as SWord)?
            }
            SetLessThanDependencies::Sltu { is_lt } => {
                is_lt.assign_instance(instance, lkm, rs1.into(), rs2.into())?
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, StepRecord, Word, encode_rv32};
    use goldilocks::GoldilocksExt2;

    use rand::Rng;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::Instruction,
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    fn verify<I: RIVInstruction>(name: &'static str, rs1: Word, rs2: Word, rd: Word) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("{}/{name}", I::INST_KIND),
                |cb| {
                    let config = SetLessThanInstruction::<_, I>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(I::INST_KIND, 2, 3, 4, 0);
        let (raw_witin, lkm) = SetLessThanInstruction::<_, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_r_instruction(
                3,
                MOCK_PC_START,
                insn_code,
                rs1,
                rs2,
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
    fn test_slt_true() {
        verify::<SltOp>("lt = true, 0 < 1", 0, 1, 1);
        verify::<SltOp>("lt = true, 1 < 2", 1, 2, 1);
        verify::<SltOp>("lt = true, -1 < 0", -1i32 as Word, 0, 1);
        verify::<SltOp>("lt = true, -1 < 1", -1i32 as Word, 1, 1);
        verify::<SltOp>("lt = true, -2 < -1", -2i32 as Word, -1i32 as Word, 1);
        verify::<SltOp>(
            "lt = true, large number",
            i32::MIN as Word,
            i32::MAX as Word,
            1,
        );
    }

    #[test]
    fn test_slt_false() {
        verify::<SltOp>("lt = false, 1 < 0", 1, 0, 0);
        verify::<SltOp>("lt = false, 2 < 1", 2, 1, 0);
        verify::<SltOp>("lt = false, 0 < -1", 0, -1i32 as Word, 0);
        verify::<SltOp>("lt = false, 1 < -1", 1, -1i32 as Word, 0);
        verify::<SltOp>("lt = false, -1 < -2", -1i32 as Word, -2i32 as Word, 0);
        verify::<SltOp>("lt = false, 0 == 0", 0, 0, 0);
        verify::<SltOp>("lt = false, 1 == 1", 1, 1, 0);
        verify::<SltOp>("lt = false, -1 == -1", -1i32 as Word, -1i32 as Word, 0);
        // This case causes subtract overflow in `assign_instance_signed`
        verify::<SltOp>(
            "lt = false, large number",
            i32::MAX as Word,
            i32::MIN as Word,
            0,
        );
    }

    #[test]
    fn test_slt_random() {
        let mut rng = rand::thread_rng();
        let a: i32 = rng.gen();
        let b: i32 = rng.gen();
        println!("random: {} <? {}", a, b); // For debugging, do not delete.
        verify::<SltOp>("random 1", a as Word, b as Word, (a < b) as u32);
        verify::<SltOp>("random 2", b as Word, a as Word, (a >= b) as u32);
    }

    #[test]
    fn test_sltu_simple() {
        verify::<SltuOp>("lt = true, 0 < 1", 0, 1, 1);
        verify::<SltuOp>("lt = true, 1 < 2", 1, 2, 1);
        verify::<SltuOp>("lt = true, 0 < u32::MAX", 0, u32::MAX, 1);
        verify::<SltuOp>("lt = true, u32::MAX - 1", u32::MAX - 1, u32::MAX, 1);
        verify::<SltuOp>("lt = false, u32::MAX", u32::MAX, u32::MAX, 0);
        verify::<SltuOp>("lt = false, u32::MAX - 1", u32::MAX, u32::MAX - 1, 0);
        verify::<SltuOp>("lt = false, u32::MAX > 0", u32::MAX, 0, 0);
        verify::<SltuOp>("lt = false, 2 > 1", 2, 1, 0);
    }

    #[test]
    fn test_sltu_random() {
        let mut rng = rand::thread_rng();
        let a: u32 = rng.gen();
        let b: u32 = rng.gen();
        verify::<SltuOp>("random 1", a, b, (a < b) as u32);
        verify::<SltuOp>("random 2", b, a, (a >= b) as u32);
    }
}
