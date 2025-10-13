use ff_ext::{ExtensionField, FieldInto};
use itertools::izip;
use std::marker::PhantomData;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            constants::{PC_BITS, UINT_BYTE_LIMBS, UInt8},
            i_insn::IInstructionConfig,
        },
    },
    structs::ProgramParams,
    tables::InsnRecord,
    utils::split_to_u8,
    witness::LkMultiplicity,
};
use ceno_emul::InsnKind;
use gkr_iop::tables::{LookupTable, ops::XorTable};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use p3::field::{Field, FieldAlgebra};
use witness::set_val;

pub struct AuipcConfig<E: ExtensionField> {
    pub i_insn: IInstructionConfig<E>,
    // The limbs of the immediate except the least significant limb since it is always 0
    pub imm_limbs: [WitIn; UINT_BYTE_LIMBS - 1],
    // The limbs of the PC except the most significant and the least significant limbs
    pub pc_limbs: [WitIn; UINT_BYTE_LIMBS - 2],
    pub rd_written: UInt8<E>,
}

#[derive(Default)]
pub struct AuipcInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for AuipcInstruction<E> {
    type InstructionConfig = AuipcConfig<E>;

    fn name() -> String {
        format!("{:?}", InsnKind::AUIPC)
    }

    fn construct_circuit(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<AuipcConfig<E>, ZKVMError> {
        let rd_written = UInt8::<E>::new(|| "rd_written", circuit_builder)?;
        let rd_exprs = rd_written.expr();
        // TODO: use double u8 for these limbs
        let pc_limbs = std::array::from_fn(|i| {
            circuit_builder
                .create_u8(|| format!("pc_limbs_{}", i))
                .unwrap()
        });
        let imm_limbs = std::array::from_fn(|i| {
            circuit_builder
                .create_u8(|| format!("imm_limbs_{}", i))
                .unwrap()
        });
        let imm = imm_limbs
            .iter()
            .enumerate()
            .fold(E::BaseField::ZERO.expr(), |acc, (i, &val)| {
                acc + val.expr()
                    * E::BaseField::from_canonical_u32(1 << (i * UInt8::<E>::LIMB_BITS)).expr()
            });

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            circuit_builder,
            InsnKind::AUIPC,
            imm.expr(),
            0.into(),
            [0.into(), 0.into()],
            UInt8::from_exprs_unchecked(rd_exprs.clone()).register_expr(),
            false,
        )?;

        let intermed_val = rd_exprs[0].expr()
            + pc_limbs
                .iter()
                .enumerate()
                .fold(E::BaseField::ZERO.expr(), |acc, (i, val)| {
                    acc + val.expr()
                        * E::BaseField::from_canonical_u32(1 << ((i + 1) * UInt8::<E>::LIMB_BITS))
                            .expr()
                });

        // Compute the most significant limb of PC
        let pc_msl = (i_insn.vm_state.pc.expr() - intermed_val.expr())
            * (E::BaseField::from_canonical_usize(
                1 << (UInt8::<E>::LIMB_BITS * (UINT_BYTE_LIMBS - 1)),
            )
            .inverse())
            .expr();

        // The vector pc_limbs contains the actual limbs of PC in little endian order
        let pc_limbs_expr = [rd_exprs[0].expr()]
            .into_iter()
            .chain(pc_limbs.iter().map(|w| w.expr()))
            .map(|x| x.expr())
            .chain([pc_msl.expr()])
            .collect::<Vec<_>>();
        assert_eq!(pc_limbs_expr.len(), UINT_BYTE_LIMBS);

        // Range check the most significant limb of pc to be in [0, 2^{PC_BITS-(RV32_REGISTER_NUM_LIMBS-1)*RV32_CELL_BITS})
        let last_limb_bits = PC_BITS - UInt8::<E>::LIMB_BITS * (UINT_BYTE_LIMBS - 1);
        let additional_bits =
            (last_limb_bits..UInt8::<E>::LIMB_BITS).fold(0, |acc, x| acc + (1 << x));
        let additional_bits = E::BaseField::from_canonical_u32(additional_bits);
        circuit_builder.logic_u8(
            LookupTable::Xor,
            pc_limbs_expr[3].expr(),
            additional_bits.expr(),
            pc_limbs_expr[3].expr() + additional_bits.expr(),
        )?;

        let mut carry: [Expression<E>; UINT_BYTE_LIMBS] =
            std::array::from_fn(|_| E::BaseField::ZERO.expr());
        let carry_divide = E::BaseField::from_canonical_usize(1 << UInt8::<E>::LIMB_BITS)
            .inverse()
            .expr();

        // Don't need to constrain the least significant limb of the addition
        // since we already know that rd_data[0] = pc_limbs[0] and the least significant limb of imm is 0
        // Note: imm_limbs doesn't include the least significant limb so imm_limbs[i - 1] means the i-th limb of imm
        for i in 1..UINT_BYTE_LIMBS {
            carry[i] = carry_divide.expr()
                * (pc_limbs_expr[i].expr() + imm_limbs[i - 1].expr() - rd_exprs[i].expr()
                    + carry[i - 1].expr());
            // carry[i] * 2^(UInt8::LIMB_BITS) + rd_exprs[i].expr() = pc_limbs_expr[i] + imm_limbs[i].expr() + carry[i - 1].expr()
            circuit_builder.assert_bit(|| format!("carry_bit_{i}"), carry[i].expr())?;
        }

        Ok(AuipcConfig {
            i_insn,
            imm_limbs,
            pc_limbs,
            rd_written,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        config
            .i_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        let rd_written = split_to_u8(step.rd().unwrap().value.after);
        config.rd_written.assign_limbs(instance, &rd_written);
        for chunk in rd_written.chunks(2) {
            if chunk.len() == 2 {
                lk_multiplicity.assert_double_u8(chunk[0] as u64, chunk[1] as u64)
            } else {
                lk_multiplicity.assert_const_range(chunk[0] as u64, 8);
            }
        }
        let pc = split_to_u8(step.pc().before.0);
        for (val, witin) in izip!(pc.iter().skip(1), config.pc_limbs) {
            lk_multiplicity.assert_ux::<8>(*val as u64);
            set_val!(instance, witin, E::BaseField::from_canonical_u8(*val));
        }
        let imm = InsnRecord::<E::BaseField>::imm_internal(&step.insn()).0 as u32;
        let imm = split_to_u8(imm);
        for (val, witin) in izip!(imm.iter(), config.imm_limbs) {
            lk_multiplicity.assert_ux::<8>(*val as u64);
            set_val!(instance, witin, E::BaseField::from_canonical_u8(*val));
        }
        // constrain pc msb limb range via xor
        let last_limb_bits = PC_BITS - UInt8::<E>::LIMB_BITS * (UINT_BYTE_LIMBS - 1);
        let additional_bits =
            (last_limb_bits..UInt8::<E>::LIMB_BITS).fold(0, |acc, x| acc + (1 << x));
        lk_multiplicity.logic_u8::<XorTable>(pc[3] as u64, additional_bits as u64);

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
        instructions::{
            Instruction,
            riscv::{auipc::AuipcInstruction, constants::UInt},
        },
        scheme::mock_prover::{MOCK_PC_START, MockProver},
        structs::ProgramParams,
    };

    #[test]
    fn test_auipc() {
        let cases = vec![
            // imm without lower 12 bits zero
            0, 0x1,
            // imm = -1 → all 1’s in 20-bit imm
            // rd = PC - 0x1000
            -1i32, 0x12345, // imm = 0x12345
            // max positive imm
            0xfffff,
        ];
        for imm in &cases {
            test_opcode_auipc::<GoldilocksExt2>(
                MOCK_PC_START.0.wrapping_add((*imm as u32) << 12),
                imm << 12,
            );
            #[cfg(feature = "u16limb_circuit")]
            test_opcode_auipc::<BabyBearExt4>(
                MOCK_PC_START.0.wrapping_add((*imm as u32) << 12),
                imm << 12,
            );
        }
    }

    fn test_opcode_auipc<E: ExtensionField>(rd: u32, imm: i32) {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let inst = AuipcInstruction::default();
        let config = cb
            .namespace(
                || "auipc",
                |cb| {
                    let config = inst.construct_circuit(cb, &ProgramParams::default());
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let insn_code = encode_rv32(InsnKind::AUIPC, 0, 0, 4, imm);
        let (raw_witin, lkm) = AuipcInstruction::<E>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            cb.cs.num_structural_witin as usize,
            vec![StepRecord::new_i_instruction(
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
