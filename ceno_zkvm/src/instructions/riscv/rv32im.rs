use crate::{
    error::ZKVMError,
    instructions::Instruction,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        AndTableCircuit, LtuTableCircuit, MemFinalRecord, MemInitRecord, MemTableCircuit,
        RegTableCircuit, TableCircuit, U14TableCircuit, U16TableCircuit,
    },
};
use ceno_emul::{CENO_PLATFORM, InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::{
    arith::AddInstruction,
    branch::BltuInstruction,
    ecall::HaltInstruction,
    jump::{JalInstruction, LuiInstruction},
    memory::LwInstruction,
};

pub struct Rv32imConfig<E: ExtensionField> {
    // Opcodes.
    pub add_config: <AddInstruction<E> as Instruction<E>>::InstructionConfig,
    pub bltu_config: <BltuInstruction as Instruction<E>>::InstructionConfig,
    pub jal_config: <JalInstruction<E> as Instruction<E>>::InstructionConfig,
    pub halt_config: <HaltInstruction<E> as Instruction<E>>::InstructionConfig,
    pub lui_config: <LuiInstruction<E> as Instruction<E>>::InstructionConfig,
    pub lw_config: <LwInstruction<E> as Instruction<E>>::InstructionConfig,

    // Tables.
    pub u16_range_config: <U16TableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub u14_range_config: <U14TableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub and_config: <AndTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub ltu_config: <LtuTableCircuit<E> as TableCircuit<E>>::TableConfig,

    // RW tables.
    pub reg_config: <RegTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub mem_config: <MemTableCircuit<E> as TableCircuit<E>>::TableConfig,
}

impl<E: ExtensionField> Rv32imConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        // opcode circuits
        let add_config = cs.register_opcode_circuit::<AddInstruction<E>>();
        let bltu_config = cs.register_opcode_circuit::<BltuInstruction>();
        let jal_config = cs.register_opcode_circuit::<JalInstruction<E>>();
        let halt_config = cs.register_opcode_circuit::<HaltInstruction<E>>();
        let lui_config = cs.register_opcode_circuit::<LuiInstruction<E>>();
        let lw_config = cs.register_opcode_circuit::<LwInstruction<E>>();

        // tables
        let u16_range_config = cs.register_table_circuit::<U16TableCircuit<E>>();
        let u14_range_config = cs.register_table_circuit::<U14TableCircuit<E>>();
        let and_config = cs.register_table_circuit::<AndTableCircuit<E>>();
        let ltu_config = cs.register_table_circuit::<LtuTableCircuit<E>>();

        // RW tables
        let reg_config = cs.register_table_circuit::<RegTableCircuit<E>>();
        let mem_config = cs.register_table_circuit::<MemTableCircuit<E>>();

        Self {
            add_config,
            bltu_config,
            jal_config,
            halt_config,
            lui_config,
            lw_config,
            u16_range_config,
            u14_range_config,
            and_config,
            ltu_config,

            reg_config,
            mem_config,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
        reg_init: &[MemInitRecord],
        mem_init: &[MemInitRecord],
    ) {
        fixed.register_opcode_circuit::<AddInstruction<E>>(cs);
        fixed.register_opcode_circuit::<BltuInstruction>(cs);
        fixed.register_opcode_circuit::<JalInstruction<E>>(cs);
        fixed.register_opcode_circuit::<HaltInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LuiInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LwInstruction<E>>(cs);

        fixed.register_table_circuit::<U16TableCircuit<E>>(cs, self.u16_range_config.clone(), &());
        fixed.register_table_circuit::<U14TableCircuit<E>>(cs, self.u14_range_config.clone(), &());
        fixed.register_table_circuit::<AndTableCircuit<E>>(cs, self.and_config.clone(), &());
        fixed.register_table_circuit::<LtuTableCircuit<E>>(cs, self.ltu_config.clone(), &());

        fixed.register_table_circuit::<RegTableCircuit<E>>(cs, self.reg_config.clone(), reg_init);
        fixed.register_table_circuit::<MemTableCircuit<E>>(cs, self.mem_config.clone(), mem_init);
    }

    pub fn assign_opcode_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
        steps: Vec<StepRecord>,
    ) -> Result<(), ZKVMError> {
        use InsnKind::*;

        let mut add_records = Vec::new();
        let mut bltu_records = Vec::new();
        let mut jal_records = Vec::new();
        let mut halt_records = Vec::new();
        let mut lui_records = Vec::new();
        let mut lw_records = Vec::new();
        steps
            .into_iter()
            .for_each(|record| match record.insn().codes().kind {
                ADD => add_records.push(record),
                BLTU => bltu_records.push(record),
                JAL => jal_records.push(record),
                EANY if record.rs1().unwrap().value == CENO_PLATFORM.ecall_halt() => {
                    halt_records.push(record);
                }
                LUI => lui_records.push(record),
                LW => lw_records.push(record),
                i => unimplemented!("instruction {i:?}"),
            });

        tracing::info!(
            "tracer generated {} ADD records, {} BLTU records, {} JAL records",
            add_records.len(),
            bltu_records.len(),
            jal_records.len(),
        );
        assert_eq!(halt_records.len(), 1);

        witness.assign_opcode_circuit::<AddInstruction<E>>(cs, &self.add_config, add_records)?;
        witness.assign_opcode_circuit::<BltuInstruction>(cs, &self.bltu_config, bltu_records)?;
        witness.assign_opcode_circuit::<JalInstruction<E>>(cs, &self.jal_config, jal_records)?;
        witness.assign_opcode_circuit::<HaltInstruction<E>>(cs, &self.halt_config, halt_records)?;
        witness.assign_opcode_circuit::<LuiInstruction<E>>(cs, &self.lui_config, lui_records)?;
        witness.assign_opcode_circuit::<LwInstruction<E>>(cs, &self.lw_config, lw_records)?;
        Ok(())
    }

    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
        reg_final: &[MemFinalRecord],
        mem_final: &[MemFinalRecord],
    ) -> Result<(), ZKVMError> {
        witness.assign_table_circuit::<U16TableCircuit<E>>(cs, &self.u16_range_config, &())?;
        witness.assign_table_circuit::<U14TableCircuit<E>>(cs, &self.u14_range_config, &())?;
        witness.assign_table_circuit::<AndTableCircuit<E>>(cs, &self.and_config, &())?;
        witness.assign_table_circuit::<LtuTableCircuit<E>>(cs, &self.ltu_config, &())?;

        // assign register finalization.
        witness
            .assign_table_circuit::<RegTableCircuit<E>>(cs, &self.reg_config, reg_final)
            .unwrap();
        // assign memory finalization.
        witness
            .assign_table_circuit::<MemTableCircuit<E>>(cs, &self.mem_config, mem_final)
            .unwrap();
        Ok(())
    }
}
