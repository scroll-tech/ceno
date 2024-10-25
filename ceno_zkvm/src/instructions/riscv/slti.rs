use std::marker::PhantomData;

use ceno_emul::{InsnKind, SWord, StepRecord};
use ff_ext::ExtensionField;

use super::{constants::UInt, i_insn::IInstructionConfig};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    gadgets::SignedLtConfig,
    instructions::Instruction,
    set_val,
    tables::InsnRecord,
    uint::Value,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

#[derive(Debug)]
pub struct InstructionConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,
    rs1_read: UInt<E>,

    // `imm` data is a field element (which is a u64 data since we're using Goldilock)
    // and `imm` is used as an lookup argument in the instruction lookup.
    // However, our current gadgets (IsLtConfig or SignedLtConfig) don't support a field element comparison.
    // That's the reason why we add `imm_uint` to compare `rs1_read` in SignedLtConfig.
    imm: WitIn,
    imm_uint: UInt<E>,
    #[allow(dead_code)]
    rd_written: UInt<E>,

    signed_lt: SignedLtConfig,
}

pub struct SltiInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for SltiInstruction<E> {
    type InstructionConfig = InstructionConfig<E>;

    fn name() -> String {
        format!("{:?}", InsnKind::SLTI)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        // If rs1_read < imm, rd_written = 1. Otherwise rd_written = 0
        let rs1_read = UInt::new_unchecked(|| "rs1_read", cb)?;
        let imm_uint = UInt::new_unchecked(|| "imm_uint", cb)?;
        let imm = cb.create_witin(|| "imm")?;

        let lt = SignedLtConfig::construct_circuit(cb, || "rs1 < imm_uint", &rs1_read, &imm_uint)?;
        let rd_written = UInt::from_exprs_unchecked(vec![lt.expr()])?;

        // Constrain imm == imm_uint by converting imm_uint to a field element
        let imm_field_expr = imm_uint.to_field_expr(lt.config.is_rhs_neg.expr());
        cb.require_equal(|| "imm_uint == imm", imm_field_expr, imm.expr())?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            InsnKind::SLTI,
            &imm.expr(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
            false,
        )?;

        Ok(InstructionConfig {
            i_insn,
            rs1_read,
            imm_uint,
            imm,
            rd_written,
            signed_lt: lt,
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
        config
            .rs1_read
            .assign_value(instance, Value::new_unchecked(rs1));

        let imm = step.insn().imm_or_funct7();
        let imm_field = InsnRecord::imm_or_funct7_field::<E::BaseField>(&step.insn());
        set_val!(instance, config.imm, imm_field);
        config
            .imm_uint
            .assign_value(instance, Value::new_unchecked(imm));

        config
            .signed_lt
            .assign_instance::<E>(instance, lkm, rs1 as SWord, imm as SWord)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{Change, PC_STEP_SIZE, StepRecord, Word, encode_rv32};
    use goldilocks::GoldilocksExt2;

    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            Instruction,
            riscv::test_utils::{i32_extra, imm_i},
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
    };

    fn verify(name: &'static str, rs1: i32, imm: i32, rd: Word) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || format!("SLTI/{name}"),
                |cb| {
                    let config = SltiInstruction::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::SLTI, 2, 0, 4, imm_i(imm));
        let (raw_witin, lkm) =
            SltiInstruction::assign_instances(&config, cb.cs.num_witin as usize, vec![
                StepRecord::new_i_instruction(
                    3,
                    Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                    insn_code,
                    rs1 as Word,
                    Change::new(0, rd),
                    0,
                ),
            ])
            .unwrap();

        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(rd).as_u16_limbs().to_vec());
        config
            .rd_written
            .require_equal(|| "assert_rd_written", &mut cb, &expected_rd_written)
            .unwrap();

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            &[insn_code],
            None,
            Some(lkm),
        );
    }

    #[test]
    fn test_slti_true() {
        verify("lt = true, 0 < 1", 0, 1, 1);
        verify("lt = true, 1 < 2", 1, 2, 1);
        verify("lt = true, -1 < 0", -1, 0, 1);
        verify("lt = true, -1 < 1", -1, 1, 1);
        verify("lt = true, -2 < -1", -2, -1, 1);
        // -2048 <= imm <= 2047
        verify("lt = true, imm upper bondary", i32::MIN, 2047, 1);
        verify("lt = true, imm lower bondary", i32::MIN, -2048, 1);
    }

    #[test]
    fn test_slti_false() {
        verify("lt = false, 1 < 0", 1, 0, 0);
        verify("lt = false, 2 < 1", 2, 1, 0);
        verify("lt = false, 0 < -1", 0, -1, 0);
        verify("lt = false, 1 < -1", 1, -1, 0);
        verify("lt = false, -1 < -2", -1, -2, 0);
        verify("lt = false, 0 == 0", 0, 0, 0);
        verify("lt = false, 1 == 1", 1, 1, 0);
        verify("lt = false, -1 == -1", -1, -1, 0);
        // -2048 <= imm <= 2047
        verify("lt = false, imm upper bondary", i32::MAX, 2047, 0);
        verify("lt = false, imm lower bondary", i32::MAX, -2048, 0);
    }

    use proptest::{prelude::Strategy, proptest};
    proptest! {
        #[test]
        fn test_slti_prop(
            a in i32_extra(),
            b in i32_extra().prop_map(|x| x & 0x7FF),
        ) {
            verify("random 1", a, b, (a < b) as u32);
        }
    }
}
