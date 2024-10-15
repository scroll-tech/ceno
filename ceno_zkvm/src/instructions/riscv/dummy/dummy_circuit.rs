use std::marker::PhantomData;

use ceno_emul::{InsnCodes, InsnFormat, InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::super::{
    constants::UInt,
    insn_base::{ReadMEM, ReadRS1, ReadRS2, StateInOut, WriteMEM, WriteRD},
    RIVInstruction,
};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::Instruction,
    set_val,
    tables::InsnRecord,
    uint::Value,
    witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

/// DummyInstruction can handle any instruction and produce its side-effects.
pub struct DummyInstruction<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: RIVInstruction> Instruction<E> for DummyInstruction<E, I> {
    type InstructionConfig = DummyConfig<E>;

    fn name() -> String {
        format!("{:?}_DUMMY", I::INST_KIND)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        DummyConfig::construct_circuit(circuit_builder, I::INST_KIND.codes())
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        config.assign_instance(instance, lk_multiplicity, step)
    }
}

#[derive(Debug)]
pub struct DummyConfig<E: ExtensionField> {
    vm_state: StateInOut<E>,

    rs1: Option<(ReadRS1<E>, UInt<E>)>,
    rs2: Option<(ReadRS2<E>, UInt<E>)>,
    rd: Option<(WriteRD<E>, UInt<E>)>,

    mem_addr_val: Option<(UInt<E>, UInt<E>)>,
    mem_read: Option<ReadMEM<E>>,
    mem_write: Option<WriteMEM<E>>,

    imm: WitIn,
}

impl<E: ExtensionField> DummyConfig<E> {
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        codes: InsnCodes,
    ) -> Result<Self, ZKVMError> {
        let (with_rs1, with_rs2, with_rd) = match codes.format {
            InsnFormat::R => (true, true, true),
            InsnFormat::I => (true, false, true),
            InsnFormat::S => (true, true, false),
            InsnFormat::B => (true, true, false),
            InsnFormat::U => (false, false, true),
            InsnFormat::J => (false, false, true),
        };
        let with_mem_write = codes.opcode == InsnKind::SW.codes().opcode;
        let with_mem_read = codes.opcode == InsnKind::LW.codes().opcode;
        let branching = [
            InsnKind::BEQ.codes().opcode, // All branches.
            InsnKind::JAL.codes().opcode,
            InsnKind::JALR.codes().opcode,
            InsnKind::EANY.codes().opcode,
        ]
        .contains(&codes.opcode);

        // State in and out
        let vm_state = StateInOut::construct_circuit(circuit_builder, branching)?;

        // Registers
        let rs1 = if with_rs1 {
            let rs1_read = UInt::new_unchecked(|| "rs1_read", circuit_builder)?;
            let rs1_op =
                ReadRS1::construct_circuit(circuit_builder, rs1_read.register_expr(), vm_state.ts)?;
            Some((rs1_op, rs1_read))
        } else {
            None
        };

        let rs2 = if with_rs2 {
            let rs2_read = UInt::new_unchecked(|| "rs2_read", circuit_builder)?;
            let rs2_op =
                ReadRS2::construct_circuit(circuit_builder, rs2_read.register_expr(), vm_state.ts)?;
            Some((rs2_op, rs2_read))
        } else {
            None
        };

        let rd = if with_rd {
            let rd_written = UInt::new_unchecked(|| "rd_written", circuit_builder)?;
            let rd_op = WriteRD::construct_circuit(
                circuit_builder,
                rd_written.register_expr(),
                vm_state.ts,
            )?;
            Some((rd_op, rd_written))
        } else {
            None
        };

        // Memory
        let mem_addr_val = if with_mem_read || with_mem_write {
            Some((
                UInt::new_unchecked(|| "mem_addr", circuit_builder)?,
                UInt::new_unchecked(|| "mem_val", circuit_builder)?,
            ))
        } else {
            None
        };

        let mem_read = if with_mem_read {
            Some(ReadMEM::construct_circuit(
                circuit_builder,
                mem_addr_val.as_ref().unwrap().0.memory_expr(),
                mem_addr_val.as_ref().unwrap().1.memory_expr(),
                vm_state.ts,
            )?)
        } else {
            None
        };

        let mem_write = if with_mem_write {
            Some(WriteMEM::construct_circuit(
                circuit_builder,
                mem_addr_val.as_ref().unwrap().0.memory_expr(),
                mem_addr_val.as_ref().unwrap().1.memory_expr(),
                vm_state.ts,
            )?)
        } else {
            None
        };

        // Fetch instruction
        let imm = circuit_builder.create_witin(|| "imm")?;

        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            codes.opcode.into(),
            rd.as_ref().map(|(r, _)| r.id.expr()).unwrap_or(0.into()),
            codes.funct3_or_zero().into(),
            rs1.as_ref().map(|(r, _)| r.id.expr()).unwrap_or(0.into()),
            rs2.as_ref().map(|(r, _)| r.id.expr()).unwrap_or(0.into()),
            imm.expr(),
        ))?;

        Ok(DummyConfig {
            vm_state,
            rs1,
            rs2,
            rd,
            mem_addr_val,
            mem_read,
            mem_write,
            imm,
        })
    }

    fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        // State in and out
        self.vm_state.assign_instance(instance, step)?;

        // Fetch instruction
        lk_multiplicity.fetch(step.pc().before.0);

        // Registers
        if let Some((rs1_op, rs1_read)) = &self.rs1 {
            rs1_op.assign_instance(instance, lk_multiplicity, step)?;

            let rs1_val = Value::new_unchecked(step.rs1().expect("rs1 value").value);
            rs1_read.assign_value(instance, rs1_val);
        }
        if let Some((rs2_op, rs2_read)) = &self.rs2 {
            rs2_op.assign_instance(instance, lk_multiplicity, step)?;

            let rs2_val = Value::new_unchecked(step.rs2().expect("rs2 value").value);
            rs2_read.assign_value(instance, rs2_val);
        }
        if let Some((rd_op, rd_written)) = &self.rd {
            rd_op.assign_instance(instance, lk_multiplicity, step)?;

            let rd_val = Value::new_unchecked(step.rd().expect("rd value").value.after);
            rd_written.assign_value(instance, rd_val);
        }

        // Memory
        if let Some((mem_addr, mem_val)) = &self.mem_addr_val {
            let mem_op = step.memory_op().expect("memory operation");
            mem_addr.assign_value(instance, Value::new_unchecked(mem_op.addr));
            mem_val.assign_value(instance, Value::new_unchecked(mem_op.value.after));
        }
        if let Some(mem_read) = &self.mem_read {
            mem_read.assign_instance(instance, lk_multiplicity, step)?;
        }
        if let Some(mem_write) = &self.mem_write {
            mem_write.assign_instance(instance, lk_multiplicity, step)?;
        }

        set_val!(
            instance,
            self.imm,
            InsnRecord::imm_or_funct7_field::<E::BaseField>(&step.insn())
        );

        Ok(())
    }
}
