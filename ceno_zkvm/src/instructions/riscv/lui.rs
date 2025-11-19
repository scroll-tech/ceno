use ff_ext::{ExtensionField, FieldInto};
use itertools::{Itertools, izip};
use std::marker::PhantomData;

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{UINT_BYTE_LIMBS, UInt8},
            i_insn::IInstructionConfig,
        },
    },
    structs::ProgramParams,
    tables::InsnRecord,
    utils::split_to_u8,
    witness::LkMultiplicity,
};
use ceno_emul::InsnKind;
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::FieldAlgebra;
use witness::set_val;

pub struct LuiConfig<E: ExtensionField> {
    pub i_insn: IInstructionConfig<E>,
    pub imm: WitIn,
    // for rd, we skip lsb byte as it's always zero
    pub rd_written: [WitIn; UINT_BYTE_LIMBS - 1],
}

pub struct LuiInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for LuiInstruction<E> {
    type InstructionConfig = LuiConfig<E>;

    fn name() -> String {
        format!("{:?}", InsnKind::LUI)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<LuiConfig<E>, ZKVMError> {
        let rd_written = std::array::from_fn(|i| {
            circuit_builder
                .create_u8(|| format!("rd_written_limb_{}", i))
                .unwrap()
        });
        // rd lsb byte is always zero
        let rd_exprs = std::iter::once(0.into())
            .chain(rd_written.map(|w| w.expr()))
            .collect_vec();
        let imm = circuit_builder.create_witin(|| "imm");
        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            InsnKind::LUI,
            imm.expr(),
            0.into(),
            [0.into(), 0.into()],
            UInt8::from_exprs_unchecked(rd_exprs.clone()).register_expr(),
            false,
        )?;

        let intermed_val =
            rd_exprs
                .iter()
                .skip(1)
                .enumerate()
                .fold(Expression::ZERO, |acc, (i, val)| {
                    acc + val.expr()
                        * E::BaseField::from_canonical_u32(1 << (i * UInt8::<E>::LIMB_BITS)).expr()
                });

        // imm * 2^4 is the correct composition of intermed_val in case of LUI
        circuit_builder.require_equal(
            || "imm * 2^4 is the correct composition of intermed_val in case of LUI",
            intermed_val.expr(),
            imm.expr() * E::BaseField::from_canonical_u32(1 << (12 - UInt8::<E>::LIMB_BITS)).expr(),
        )?;

        Ok(LuiConfig {
            i_insn,
            imm,
            rd_written,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .i_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

        let rd_written = split_to_u8(step.rd().unwrap().value.after);
        for (val, witin) in izip!(rd_written.iter().skip(1), config.rd_written) {
            lk_multiplicity.assert_ux::<8>(*val as u64);
            set_val!(instance, witin, E::BaseField::from_canonical_u8(*val));
        }
        let imm = InsnRecord::<E::BaseField>::imm_internal(&step.insn()).0 as u64;
        set_val!(instance, config.imm, imm);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ceno_emul::{Change, InsnKind, PC_STEP_SIZE, StepRecord, encode_rv32};
    use ff_ext::{BabyBearExt4, ExtensionField, GoldilocksExt2};
    use gkr_iop::circuit_builder::DebugIndex;

    use crate::{
        Value,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        e2e::ShardContext,
        instructions::{
            Instruction,
            riscv::{constants::UInt, lui::LuiInstruction},
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
    };

    #[test]
    fn test_lui() {
        let cases = vec![0, 0x1, 0xfffff];
        for imm in &cases {
            test_opcode_lui::<GoldilocksExt2>((*imm as u32) << 12, imm << 12);
            #[cfg(feature = "u16limb_circuit")]
            test_opcode_lui::<BabyBearExt4>((*imm as u32) << 12, imm << 12);
        }
    }

    fn test_opcode_lui<E: ExtensionField>(rd: u32, imm: i32) {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = cb
            .namespace(
                || "lui",
                |cb| {
                    let config =
                        LuiInstruction::<E>::construct_circuit(cb, &ProgramParams::default());
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::LUI, 0, 0, 4, imm);
        let (raw_witin, lkm) = LuiInstruction::<E>::assign_instances(
            &config,
            &mut ShardContext::default(),
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![&StepRecord::new_i_instruction(
                3,
                Change::new(MOCK_PC_START, MOCK_PC_START + PC_STEP_SIZE),
                insn_code,
                0,
                Change::new(0, rd),
                0,
            )],
        )
        .unwrap();

        // verify rd_written
        let expected_rd_written =
            UInt::from_const_unchecked(Value::new_unchecked(rd).as_u16_limbs().to_vec());
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(
            || "assert_rd_written",
            rd_written_expr,
            expected_rd_written.value(),
        )
        .unwrap();

        MockProver::assert_satisfied_raw(&cb, raw_witin, &[insn_code], None, Some(lkm));
    }
}
