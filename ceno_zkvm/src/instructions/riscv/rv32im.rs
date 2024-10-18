use crate::{
    error::ZKVMError,
    instructions::Instruction,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{AndTableCircuit, LtuTableCircuit, TableCircuit, U16TableCircuit},
};
use ceno_emul::{CENO_PLATFORM, InsnKind, StepRecord};
use ff_ext::ExtensionField;

use super::{
    arith::AddInstruction, branch::BltuInstruction, ecall::HaltInstruction, jump::JalInstruction,
};

pub struct Rv32imConfig<E: ExtensionField> {
    // Opcodes.
    pub add_config: <AddInstruction<E> as Instruction<E>>::InstructionConfig,
    pub bltu_config: <BltuInstruction as Instruction<E>>::InstructionConfig,
    pub jal_config: <JalInstruction<E> as Instruction<E>>::InstructionConfig,
    pub halt_config: <HaltInstruction<E> as Instruction<E>>::InstructionConfig,

    // Tables.
    pub u16_range_config: <U16TableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub and_config: <AndTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub ltu_config: <LtuTableCircuit<E> as TableCircuit<E>>::TableConfig,
}

impl<E: ExtensionField> Rv32imConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        // opcode circuits
        let add_config = cs.register_opcode_circuit::<AddInstruction<E>>();
        let bltu_config = cs.register_opcode_circuit::<BltuInstruction>();
        let jal_config = cs.register_opcode_circuit::<JalInstruction<E>>();
        let halt_config = cs.register_opcode_circuit::<HaltInstruction<E>>();

        // tables
        let u16_range_config = cs.register_table_circuit::<U16TableCircuit<E>>();
        let and_config = cs.register_table_circuit::<AndTableCircuit<E>>();
        let ltu_config = cs.register_table_circuit::<LtuTableCircuit<E>>();

        Self {
            add_config,
            bltu_config,
            jal_config,
            halt_config,

            u16_range_config,
            and_config,
            ltu_config,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
    ) {
        fixed.register_opcode_circuit::<AddInstruction<E>>(cs);
        fixed.register_opcode_circuit::<BltuInstruction>(cs);
        fixed.register_opcode_circuit::<JalInstruction<E>>(cs);
        fixed.register_opcode_circuit::<HaltInstruction<E>>(cs);

        fixed.register_table_circuit::<U16TableCircuit<E>>(cs, self.u16_range_config.clone(), &());
        fixed.register_table_circuit::<AndTableCircuit<E>>(cs, self.and_config.clone(), &());
        fixed.register_table_circuit::<LtuTableCircuit<E>>(cs, self.ltu_config.clone(), &());
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
        steps
            .into_iter()
            .for_each(|record| match record.insn().codes().kind {
                ADD => add_records.push(record),
                BLTU => bltu_records.push(record),
                JAL => jal_records.push(record),
                EANY if record.rs1().unwrap().value == CENO_PLATFORM.ecall_halt() => {
                    halt_records.push(record);
                }
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
        Ok(())
    }

    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
    ) -> Result<(), ZKVMError> {
        witness.assign_table_circuit::<U16TableCircuit<E>>(cs, &self.u16_range_config, &())?;
        witness.assign_table_circuit::<AndTableCircuit<E>>(cs, &self.and_config, &())?;
        witness.assign_table_circuit::<LtuTableCircuit<E>>(cs, &self.ltu_config, &())?;
        Ok(())
    }
}
