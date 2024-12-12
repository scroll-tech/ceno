use std::marker::PhantomData;

use ceno_emul::{InsnCategory, InsnFormat, InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::super::{
    RIVInstruction,
    constants::UInt,
    insn_base::{ReadMEM, ReadRS1, ReadRS2, StateInOut, WriteMEM, WriteRD},
};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::Instruction,
    set_val,
    tables::InsnRecord,
    uint::Value,
    utils::i64_to_base,
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
        let codes = I::INST_KIND.codes();

        // ECALL can do everything.
        let is_ecall = matches!(codes.kind, InsnKind::EANY);

        // Regular instructions do what is implied by their format.
        let (with_rs1, with_rs2, with_rd) = match codes.format {
            _ if is_ecall => (true, true, true),
            InsnFormat::R => (true, true, true),
            InsnFormat::I => (true, false, true),
            InsnFormat::S => (true, true, false),
            InsnFormat::B => (true, true, false),
            InsnFormat::U => (false, false, true),
            InsnFormat::J => (false, false, true),
        };
        let with_mem_write = matches!(codes.category, InsnCategory::Store) || is_ecall;
        let with_mem_read = matches!(codes.category, InsnCategory::Load);
        let branching = matches!(codes.category, InsnCategory::Branch)
            || matches!(codes.kind, InsnKind::JAL | InsnKind::JALR)
            || is_ecall;

        DummyConfig::construct_circuit(
            circuit_builder,
            I::INST_KIND,
            with_rs1,
            with_rs2,
            with_rd,
            with_mem_write,
            with_mem_read,
            branching,
        )
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
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

    mem_addr_val: Option<[WitIn; 3]>,
    mem_read: Option<ReadMEM<E>>,
    mem_write: Option<WriteMEM>,

    imm: WitIn,
}

impl<E: ExtensionField> DummyConfig<E> {
    #[allow(clippy::too_many_arguments)]
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
        kind: InsnKind,
        with_rs1: bool,
        with_rs2: bool,
        with_rd: bool,
        with_mem_write: bool,
        with_mem_read: bool,
        branching: bool,
    ) -> Result<Self, ZKVMError> {
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
            Some([
                circuit_builder.create_witin(|| "mem_addr"),
                circuit_builder.create_witin(|| "mem_before"),
                circuit_builder.create_witin(|| "mem_after"),
            ])
        } else {
            None
        };

        let mem_read = if with_mem_read {
            Some(ReadMEM::construct_circuit(
                circuit_builder,
                mem_addr_val.as_ref().unwrap()[0].expr(),
                mem_addr_val.as_ref().unwrap()[1].expr(),
                vm_state.ts,
            )?)
        } else {
            None
        };

        let mem_write = if with_mem_write {
            Some(WriteMEM::construct_circuit(
                circuit_builder,
                mem_addr_val.as_ref().unwrap()[0].expr(),
                mem_addr_val.as_ref().unwrap()[1].expr(),
                mem_addr_val.as_ref().unwrap()[2].expr(),
                vm_state.ts,
            )?)
        } else {
            None
        };

        // Fetch instruction

        // The register IDs of ECALL is fixed, not encoded.
        let is_ecall = matches!(kind, InsnKind::EANY);
        let rs1_id = match &rs1 {
            Some((r, _)) if !is_ecall => r.id.expr(),
            _ => 0.into(),
        };
        let rs2_id = match &rs2 {
            Some((r, _)) if !is_ecall => r.id.expr(),
            _ => 0.into(),
        };
        let rd_id = match &rd {
            Some((r, _)) if !is_ecall => Some(r.id.expr()),
            _ => None,
        };

        let imm = circuit_builder.create_witin(|| "imm");

        circuit_builder.lk_fetch(&InsnRecord::new(
            vm_state.pc.expr(),
            kind.into(),
            rd_id,
            rs1_id,
            rs2_id,
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
        instance: &mut [MaybeUninit<E::BaseField>],
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
        if let Some([mem_addr, mem_before, mem_after]) = &self.mem_addr_val {
            let mem_op = step.memory_op().expect("memory operation");
            set_val!(instance, mem_addr, u64::from(mem_op.addr));
            set_val!(instance, mem_before, mem_op.value.before as u64);
            set_val!(instance, mem_after, mem_op.value.after as u64);
        }
        if let Some(mem_read) = &self.mem_read {
            mem_read.assign_instance(instance, lk_multiplicity, step)?;
        }
        if let Some(mem_write) = &self.mem_write {
            mem_write.assign_instance::<E>(instance, lk_multiplicity, step)?;
        }

        let imm = i64_to_base::<E::BaseField>(InsnRecord::imm_internal(&step.insn()));
        set_val!(instance, self.imm, imm);

        Ok(())
    }
}
