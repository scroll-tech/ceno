use crate::{
    error::ZKVMError,
    instructions::{Instruction, riscv::*},
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        AndTableCircuit, LtuTableCircuit, MemFinalRecord, MemInitRecord, MemTableCircuit,
        RegTableCircuit, TableCircuit, U14TableCircuit, U16TableCircuit,
    },
};
use ceno_emul::{CENO_PLATFORM, InsnKind, InsnKind::*, StepRecord};
use ff_ext::ExtensionField;
use itertools::Itertools;
use num_traits::cast::ToPrimitive;
use strum::IntoEnumIterator;

use super::{
    arith::AddInstruction,
    branch::BltuInstruction,
    ecall::HaltInstruction,
    jump::{JalInstruction, LuiInstruction},
    memory::LwInstruction,
};

pub struct Rv32imConfig<E: ExtensionField> {
    // ALU Opcodes.
    pub add_config: <AddInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sub_config: <SubInstruction<E> as Instruction<E>>::InstructionConfig,

    // Branching Opcodes
    pub bltu_config: <BltuInstruction as Instruction<E>>::InstructionConfig,

    // Imm
    pub lui_config: <LuiInstruction<E> as Instruction<E>>::InstructionConfig,

    // Jump Opcodes
    pub jal_config: <JalInstruction<E> as Instruction<E>>::InstructionConfig,
    pub jalr_config: <JalrInstruction<E> as Instruction<E>>::InstructionConfig,
    pub auipc_config: <AuipcInstruction<E> as Instruction<E>>::InstructionConfig,

    // Memory Opcodes
    pub lw_config: <LwInstruction<E> as Instruction<E>>::InstructionConfig,
    pub lhu_config: <LhuInstruction<E> as Instruction<E>>::InstructionConfig,
    pub lh_config: <LhInstruction<E> as Instruction<E>>::InstructionConfig,
    pub lbu_config: <LbuInstruction<E> as Instruction<E>>::InstructionConfig,
    pub lb_config: <LbInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sw_config: <SwInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sh_config: <ShInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sb_config: <SbInstruction<E> as Instruction<E>>::InstructionConfig,

    // Ecall Opcodes
    pub halt_config: <HaltInstruction<E> as Instruction<E>>::InstructionConfig,
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
        // alu opcodes
        let add_config = cs.register_opcode_circuit::<AddInstruction<E>>();
        let sub_config = cs.register_opcode_circuit::<SubInstruction<E>>();

        // branching opcodes
        let bltu_config = cs.register_opcode_circuit::<BltuInstruction>();

        // jump opcodes
        let lui_config = cs.register_opcode_circuit::<LuiInstruction<E>>();
        let jal_config = cs.register_opcode_circuit::<JalInstruction<E>>();
        let jalr_config = cs.register_opcode_circuit::<JalrInstruction<E>>();
        let auipc_config = cs.register_opcode_circuit::<AuipcInstruction<E>>();

        // memory opcodes
        let lw_config = cs.register_opcode_circuit::<LwInstruction<E>>();
        let lhu_config = cs.register_opcode_circuit::<LhuInstruction<E>>();
        let lh_config = cs.register_opcode_circuit::<LhInstruction<E>>();
        let lbu_config = cs.register_opcode_circuit::<LbuInstruction<E>>();
        let lb_config = cs.register_opcode_circuit::<LbInstruction<E>>();
        let sw_config = cs.register_opcode_circuit::<SwInstruction<E>>();
        let sh_config = cs.register_opcode_circuit::<ShInstruction<E>>();
        let sb_config = cs.register_opcode_circuit::<SbInstruction<E>>();

        // ecall opcodes
        let halt_config = cs.register_opcode_circuit::<HaltInstruction<E>>();
        // tables
        let u16_range_config = cs.register_table_circuit::<U16TableCircuit<E>>();
        let u14_range_config = cs.register_table_circuit::<U14TableCircuit<E>>();
        let and_config = cs.register_table_circuit::<AndTableCircuit<E>>();
        let ltu_config = cs.register_table_circuit::<LtuTableCircuit<E>>();

        // RW tables
        let reg_config = cs.register_table_circuit::<RegTableCircuit<E>>();
        let mem_config = cs.register_table_circuit::<MemTableCircuit<E>>();

        Self {
            // alu opcodes
            add_config,
            sub_config,
            // branching opcodes
            bltu_config,
            // jump opcodes
            lui_config,
            jal_config,
            jalr_config,
            auipc_config,
            // memory opcodes
            sw_config,
            sh_config,
            sb_config,
            lw_config,
            lhu_config,
            lh_config,
            lbu_config,
            lb_config,
            // ecall opcodes
            halt_config,
            // tables
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
        fixed.register_opcode_circuit::<SubInstruction<E>>(cs);

        fixed.register_opcode_circuit::<BltuInstruction>(cs);

        fixed.register_opcode_circuit::<JalInstruction<E>>(cs);
        fixed.register_opcode_circuit::<JalrInstruction<E>>(cs);
        fixed.register_opcode_circuit::<AuipcInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LuiInstruction<E>>(cs);

        fixed.register_opcode_circuit::<SwInstruction<E>>(cs);
        fixed.register_opcode_circuit::<ShInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SbInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LwInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LhuInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LhInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LbuInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LbInstruction<E>>(cs);

        fixed.register_opcode_circuit::<HaltInstruction<E>>(cs);

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
        let mut all_records = vec![Vec::new(); InsnKind::iter().count()];
        let mut halt_records = Vec::new();
        steps.into_iter().for_each(|record| {
            let insn_kind = record.insn().codes().kind;
            match insn_kind {
                // ecall
                EANY if record.rs1().unwrap().value == CENO_PLATFORM.ecall_halt() => {
                    halt_records.push(record);
                }
                _ => all_records[insn_kind.to_usize().unwrap()].push(record),
            }
        });

        for (insn_kind, records) in InsnKind::iter()
            .zip(all_records.iter())
            .sorted_by(|a, b| Ord::cmp(&a.1.len(), &b.1.len()))
            .rev()
        {
            if records.len() != 0 {
                tracing::info!("tracer generated {:?} {} records", insn_kind, records.len());
            }
        }
        assert_eq!(halt_records.len(), 1);

        witness.assign_opcode_circuit::<AddInstruction<E>>(
            cs,
            &self.add_config,
            all_records[ADD.to_usize().unwrap()].as_slice(),
        )?;
        witness.assign_opcode_circuit::<BltuInstruction>(
            cs,
            &self.bltu_config,
            all_records[BLTU.to_usize().unwrap()].as_slice(),
        )?;
        witness.assign_opcode_circuit::<JalInstruction<E>>(
            cs,
            &self.jal_config,
            all_records[JAL.to_usize().unwrap()].as_slice(),
        )?;
        witness.assign_opcode_circuit::<LuiInstruction<E>>(
            cs,
            &self.lui_config,
            all_records[LUI.to_usize().unwrap()].as_slice(),
        )?;
        witness.assign_opcode_circuit::<LwInstruction<E>>(
            cs,
            &self.lw_config,
            all_records[SW.to_usize().unwrap()].as_slice(),
        )?;
        witness.assign_opcode_circuit::<HaltInstruction<E>>(
            cs,
            &self.halt_config,
            &halt_records,
        )?;
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
