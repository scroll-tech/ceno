//! The circuit implementation of logic instructions.

use core::mem::MaybeUninit;
use ff_ext::ExtensionField;
use std::marker::PhantomData;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{constants::UInt8, i_insn::IInstructionConfig},
    },
    tables::OpsTable,
    utils::split_to_u8,
    witness::LkMultiplicity,
};
use ceno_emul::{InsnKind, StepRecord};

/// This trait defines a logic instruction, connecting an instruction type to a lookup table.
pub trait LogicOp {
    const INST_KIND: InsnKind;
    type OpsTable: OpsTable;
}

/// The Instruction circuit for a given LogicOp.
pub struct LogicInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: LogicOp> Instruction<E> for LogicInstruction<E, I> {
    type InstructionConfig = LogicConfig<E>;

    fn name() -> String {
        format!("{:?}", I::INST_KIND)
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        let config = LogicConfig::construct_circuit(cb, I::INST_KIND)?;

        // Constrain the registers based on the given lookup table.
        UInt8::logic(
            cb,
            I::OpsTable::ROM_TYPE,
            &config.rs1_read,
            &config.imm,
            &config.rd_written,
        )?;

        Ok(config)
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        UInt8::<E>::logic_assign::<I::OpsTable>(
            lkm,
            step.rs1().unwrap().value.into(),
            step.insn().imm_or_funct7().into(),
        );

        config.assign_instance(instance, lkm, step)
    }
}

/// This config implements I-Instructions that represent registers values as 4 * u8.
/// Non-generic code shared by several circuits.
#[derive(Debug)]
pub struct LogicConfig<E: ExtensionField> {
    i_insn: IInstructionConfig<E>,

    rs1_read: UInt8<E>,
    pub(crate) rd_written: UInt8<E>,
    imm: UInt8<E>,
}

impl<E: ExtensionField> LogicConfig<E> {
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        insn_kind: InsnKind,
    ) -> Result<Self, ZKVMError> {
        let rs1_read = UInt8::new_unchecked(|| "rs1_read", cb)?;
        let rd_written = UInt8::new_unchecked(|| "rd_written", cb)?;
        let imm = UInt8::new_unchecked(|| "imm", cb)?;

        let i_insn = IInstructionConfig::<E>::construct_circuit(
            cb,
            insn_kind,
            &imm.value(),
            rs1_read.register_expr(),
            rd_written.register_expr(),
        )?;

        Ok(Self {
            i_insn,
            rs1_read,
            imm,
            rd_written,
        })
    }

    fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lkm: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        self.i_insn.assign_instance(instance, lkm, step)?;

        let rs1_read = split_to_u8(step.rs1().unwrap().value);
        self.rs1_read.assign_limbs(instance, &rs1_read);

        let imm = split_to_u8::<u16>(step.insn().imm_or_funct7());
        self.imm.assign_limbs(instance, &imm);

        let rd_written = split_to_u8(step.rd().unwrap().value.after);
        self.rd_written.assign_limbs(instance, &rd_written);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ceno_emul::{ByteAddr, CENO_PLATFORM, Change, InsnKind, StepRecord};
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{
        chip_handler::test::DebugIndex,
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{
            Instruction,
            riscv::{
                constants::UInt8,
                logic_imm::{AndiOp, OriOp, XoriOp, logic_imm_circuit::LogicInstruction},
            },
        },
        scheme::mock_prover::{MOCK_PC_ANDI, MOCK_PC_ORI, MOCK_PC_XORI, MOCK_PROGRAM, MockProver},
        utils::split_to_u8,
    };

    use super::LogicOp;

    #[test]
    fn test_opcode_andi() {
        let pc = MOCK_PC_ANDI;
        let prog_idx: usize = ((pc.0 - CENO_PLATFORM.pc_start()) / 4) as usize;
        let prog = MOCK_PROGRAM[prog_idx];
        let imm = 3;
        verify::<AndiOp>("basic", pc, prog, 0x0000_0011, 0x0000_0011 & imm);
        verify::<AndiOp>("zero result", pc, prog, 0x0000_0100, 0x0000_0100 & imm);
    }

    #[test]
    fn test_opcode_ori() {
        let pc = MOCK_PC_ORI;
        let prog_idx: usize = ((pc.0 - CENO_PLATFORM.pc_start()) / 4) as usize;
        let prog = MOCK_PROGRAM[prog_idx];
        let imm = 3;
        verify::<OriOp>("basic", pc, prog, 0x0000_0011, 0x0000_0011 | imm);
        verify::<OriOp>("basic2", pc, prog, 0x0000_0100, 0x0000_0100 | imm);
    }

    #[test]
    fn test_opcode_xori() {
        let pc = MOCK_PC_XORI;
        let prog_idx: usize = ((pc.0 - CENO_PLATFORM.pc_start()) / 4) as usize;
        let prog = MOCK_PROGRAM[prog_idx];
        let imm = 3;
        verify::<XoriOp>("basic", pc, prog, 0x0000_0011, 0x0000_0011 ^ imm);
        verify::<XoriOp>("non-overlap", pc, prog, 0x0000_0100, 0x0000_0100 ^ imm);
    }

    fn verify<I: LogicOp>(
        name: &'static str,
        pc: ByteAddr,
        program: u32,
        rs1_read: u32,
        expected_rd_written: u32,
    ) {
        let mut cs = ConstraintSystem::<GoldilocksExt2>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let imm: u32 = 3;
        let (prefix, rd_written) = match I::INST_KIND {
            InsnKind::ANDI => ("ANDI", rs1_read & imm),
            InsnKind::ORI => ("ORI", rs1_read | imm),
            InsnKind::XORI => ("XORI", rs1_read ^ imm),
            _ => unreachable!(),
        };

        let config = cb
            .namespace(
                || format!("{prefix}_({name})"),
                |cb| {
                    let config = LogicInstruction::<GoldilocksExt2, I>::construct_circuit(cb);
                    Ok(config)
                },
            )
            .unwrap()
            .unwrap();

        let (raw_witin, lkm) = LogicInstruction::<GoldilocksExt2, I>::assign_instances(
            &config,
            cb.cs.num_witin as usize,
            vec![StepRecord::new_i_instruction(
                3,
                pc,
                program,
                rs1_read,
                Change::new(0, rd_written),
                0,
            )],
        )
        .unwrap();

        let expected = UInt8::from_const_unchecked(split_to_u8::<u64>(expected_rd_written));
        let rd_written_expr = cb.get_debug_expr(DebugIndex::RdWrite as usize)[0].clone();
        cb.require_equal(|| "assert_rd_written", rd_written_expr, expected.value())
            .unwrap();

        MockProver::assert_satisfied(
            &cb,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
            Some(lkm),
        );
    }
}
