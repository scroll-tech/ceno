use crate::{
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            arith_imm::AddiInstruction,
            branch::{
                BeqInstruction, BgeInstruction, BgeuInstruction, BltInstruction, BneInstruction,
            },
            divu::DivUInstruction,
            logic::{AndInstruction, OrInstruction, XorInstruction},
            logic_imm::{AndiInstruction, OriInstruction, XoriInstruction},
            mul::MulhuInstruction,
            shift::{SllInstruction, SrlInstruction},
            shift_imm::{SlliInstruction, SraiInstruction, SrliInstruction},
            slti::SltiInstruction,
            *,
        },
    },
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        AndTableCircuit, LtuTableCircuit, OrTableCircuit, PowTableCircuit, TableCircuit,
        U5TableCircuit, U8TableCircuit, U14TableCircuit, U16TableCircuit, XorTableCircuit,
    },
};
use ceno_emul::{
    InsnKind::{self, *},
    Platform, StepRecord,
};
use divu::{DivDummy, RemDummy, RemuDummy};
use ecall::EcallDummy;
use ff_ext::ExtensionField;
use itertools::Itertools;
use mul::{MulInstruction, MulhInstruction, MulhsuInstruction};
use shift::SraInstruction;
use slt::{SltInstruction, SltuInstruction};
use slti::SltiuInstruction;
use std::collections::{BTreeMap, BTreeSet};
use strum::IntoEnumIterator;

use super::{
    arith::AddInstruction,
    branch::BltuInstruction,
    ecall::HaltInstruction,
    jump::{JalInstruction, LuiInstruction},
    memory::LwInstruction,
};

pub mod mmu;

pub struct Rv32imConfig<E: ExtensionField> {
    // ALU Opcodes.
    pub add_config: <AddInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sub_config: <SubInstruction<E> as Instruction<E>>::InstructionConfig,
    pub and_config: <AndInstruction<E> as Instruction<E>>::InstructionConfig,
    pub or_config: <OrInstruction<E> as Instruction<E>>::InstructionConfig,
    pub xor_config: <XorInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sll_config: <SllInstruction<E> as Instruction<E>>::InstructionConfig,
    pub srl_config: <SrlInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sra_config: <SraInstruction<E> as Instruction<E>>::InstructionConfig,
    pub slt_config: <SltInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sltu_config: <SltuInstruction<E> as Instruction<E>>::InstructionConfig,
    pub mul_config: <MulInstruction<E> as Instruction<E>>::InstructionConfig,
    pub mulh_config: <MulhInstruction<E> as Instruction<E>>::InstructionConfig,
    pub mulhsu_config: <MulhsuInstruction<E> as Instruction<E>>::InstructionConfig,
    pub mulhu_config: <MulhuInstruction<E> as Instruction<E>>::InstructionConfig,
    pub divu_config: <DivUInstruction<E> as Instruction<E>>::InstructionConfig,

    // ALU with imm
    pub addi_config: <AddiInstruction<E> as Instruction<E>>::InstructionConfig,
    pub andi_config: <AndiInstruction<E> as Instruction<E>>::InstructionConfig,
    pub ori_config: <OriInstruction<E> as Instruction<E>>::InstructionConfig,
    pub xori_config: <XoriInstruction<E> as Instruction<E>>::InstructionConfig,
    pub slli_config: <SlliInstruction<E> as Instruction<E>>::InstructionConfig,
    pub srli_config: <SrliInstruction<E> as Instruction<E>>::InstructionConfig,
    pub srai_config: <SraiInstruction<E> as Instruction<E>>::InstructionConfig,
    pub slti_config: <SltiInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sltiu_config: <SltiuInstruction<E> as Instruction<E>>::InstructionConfig,

    // Branching Opcodes
    pub beq_config: <BeqInstruction<E> as Instruction<E>>::InstructionConfig,
    pub bne_config: <BneInstruction<E> as Instruction<E>>::InstructionConfig,
    pub blt_config: <BltInstruction<E> as Instruction<E>>::InstructionConfig,
    pub bltu_config: <BltuInstruction<E> as Instruction<E>>::InstructionConfig,
    pub bge_config: <BgeInstruction<E> as Instruction<E>>::InstructionConfig,
    pub bgeu_config: <BgeuInstruction<E> as Instruction<E>>::InstructionConfig,

    // Jump Opcodes
    pub jal_config: <JalInstruction<E> as Instruction<E>>::InstructionConfig,
    pub jalr_config: <JalrInstruction<E> as Instruction<E>>::InstructionConfig,
    pub auipc_config: <AuipcInstruction<E> as Instruction<E>>::InstructionConfig,
    pub lui_config: <LuiInstruction<E> as Instruction<E>>::InstructionConfig,

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
    pub u8_range_config: <U8TableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub u5_range_config: <U5TableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub and_table_config: <AndTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub or_table_config: <OrTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub xor_table_config: <XorTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub ltu_config: <LtuTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub pow_config: <PowTableCircuit<E> as TableCircuit<E>>::TableConfig,
}

impl<E: ExtensionField> Rv32imConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        // opcode circuits
        // alu opcodes
        let add_config = cs.register_opcode_circuit::<AddInstruction<E>>();
        let sub_config = cs.register_opcode_circuit::<SubInstruction<E>>();
        let and_config = cs.register_opcode_circuit::<AndInstruction<E>>();
        let or_config = cs.register_opcode_circuit::<OrInstruction<E>>();
        let xor_config = cs.register_opcode_circuit::<XorInstruction<E>>();
        let sll_config = cs.register_opcode_circuit::<SllInstruction<E>>();
        let srl_config = cs.register_opcode_circuit::<SrlInstruction<E>>();
        let sra_config = cs.register_opcode_circuit::<SraInstruction<E>>();
        let slt_config = cs.register_opcode_circuit::<SltInstruction<E>>();
        let sltu_config = cs.register_opcode_circuit::<SltuInstruction<E>>();
        let mul_config = cs.register_opcode_circuit::<MulInstruction<E>>();
        let mulh_config = cs.register_opcode_circuit::<MulhInstruction<E>>();
        let mulhsu_config = cs.register_opcode_circuit::<MulhsuInstruction<E>>();
        let mulhu_config = cs.register_opcode_circuit::<MulhuInstruction<E>>();
        let divu_config = cs.register_opcode_circuit::<DivUInstruction<E>>();

        // alu with imm opcodes
        let addi_config = cs.register_opcode_circuit::<AddiInstruction<E>>();
        let andi_config = cs.register_opcode_circuit::<AndiInstruction<E>>();
        let ori_config = cs.register_opcode_circuit::<OriInstruction<E>>();
        let xori_config = cs.register_opcode_circuit::<XoriInstruction<E>>();
        let slli_config = cs.register_opcode_circuit::<SlliInstruction<E>>();
        let srli_config = cs.register_opcode_circuit::<SrliInstruction<E>>();
        let srai_config = cs.register_opcode_circuit::<SraiInstruction<E>>();
        let slti_config = cs.register_opcode_circuit::<SltiInstruction<E>>();
        let sltiu_config = cs.register_opcode_circuit::<SltiuInstruction<E>>();

        // branching opcodes
        let beq_config = cs.register_opcode_circuit::<BeqInstruction<E>>();
        let bne_config = cs.register_opcode_circuit::<BneInstruction<E>>();
        let blt_config = cs.register_opcode_circuit::<BltInstruction<E>>();
        let bltu_config = cs.register_opcode_circuit::<BltuInstruction<E>>();
        let bge_config = cs.register_opcode_circuit::<BgeInstruction<E>>();
        let bgeu_config = cs.register_opcode_circuit::<BgeuInstruction<E>>();

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
        let u8_range_config = cs.register_table_circuit::<U8TableCircuit<E>>();
        let u5_range_config = cs.register_table_circuit::<U5TableCircuit<E>>();
        let and_table_config = cs.register_table_circuit::<AndTableCircuit<E>>();
        let or_table_config = cs.register_table_circuit::<OrTableCircuit<E>>();
        let xor_table_config = cs.register_table_circuit::<XorTableCircuit<E>>();
        let ltu_config = cs.register_table_circuit::<LtuTableCircuit<E>>();
        let pow_config = cs.register_table_circuit::<PowTableCircuit<E>>();

        Self {
            // alu opcodes
            add_config,
            sub_config,
            and_config,
            or_config,
            xor_config,
            sll_config,
            srl_config,
            sra_config,
            slt_config,
            sltu_config,
            mul_config,
            mulh_config,
            mulhsu_config,
            mulhu_config,
            divu_config,
            // alu with imm
            addi_config,
            andi_config,
            ori_config,
            xori_config,
            slli_config,
            srli_config,
            srai_config,
            slti_config,
            sltiu_config,
            // branching opcodes
            beq_config,
            bne_config,
            blt_config,
            bltu_config,
            bge_config,
            bgeu_config,
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
            u8_range_config,
            u5_range_config,
            and_table_config,
            or_table_config,
            xor_table_config,
            ltu_config,
            pow_config,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
    ) {
        // alu
        fixed.register_opcode_circuit::<AddInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SubInstruction<E>>(cs);
        fixed.register_opcode_circuit::<AndInstruction<E>>(cs);
        fixed.register_opcode_circuit::<OrInstruction<E>>(cs);
        fixed.register_opcode_circuit::<XorInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SllInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SrlInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SraInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SltInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SltuInstruction<E>>(cs);
        fixed.register_opcode_circuit::<MulInstruction<E>>(cs);
        fixed.register_opcode_circuit::<MulhInstruction<E>>(cs);
        fixed.register_opcode_circuit::<MulhsuInstruction<E>>(cs);
        fixed.register_opcode_circuit::<MulhuInstruction<E>>(cs);
        fixed.register_opcode_circuit::<DivUInstruction<E>>(cs);
        // alu with imm
        fixed.register_opcode_circuit::<AddiInstruction<E>>(cs);
        fixed.register_opcode_circuit::<AndiInstruction<E>>(cs);
        fixed.register_opcode_circuit::<OriInstruction<E>>(cs);
        fixed.register_opcode_circuit::<XoriInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SlliInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SrliInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SraiInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SltiInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SltiuInstruction<E>>(cs);
        // branching
        fixed.register_opcode_circuit::<BeqInstruction<E>>(cs);
        fixed.register_opcode_circuit::<BneInstruction<E>>(cs);
        fixed.register_opcode_circuit::<BltInstruction<E>>(cs);
        fixed.register_opcode_circuit::<BltuInstruction<E>>(cs);
        fixed.register_opcode_circuit::<BgeInstruction<E>>(cs);
        fixed.register_opcode_circuit::<BgeuInstruction<E>>(cs);
        // jump
        fixed.register_opcode_circuit::<JalInstruction<E>>(cs);
        fixed.register_opcode_circuit::<JalrInstruction<E>>(cs);
        fixed.register_opcode_circuit::<AuipcInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LuiInstruction<E>>(cs);
        // memory
        fixed.register_opcode_circuit::<SwInstruction<E>>(cs);
        fixed.register_opcode_circuit::<ShInstruction<E>>(cs);
        fixed.register_opcode_circuit::<SbInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LwInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LhuInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LhInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LbuInstruction<E>>(cs);
        fixed.register_opcode_circuit::<LbInstruction<E>>(cs);

        fixed.register_opcode_circuit::<HaltInstruction<E>>(cs);

        fixed.register_table_circuit::<U16TableCircuit<E>>(cs, &self.u16_range_config, &());
        fixed.register_table_circuit::<U14TableCircuit<E>>(cs, &self.u14_range_config, &());
        fixed.register_table_circuit::<U8TableCircuit<E>>(cs, &self.u8_range_config, &());
        fixed.register_table_circuit::<U5TableCircuit<E>>(cs, &self.u5_range_config, &());
        fixed.register_table_circuit::<AndTableCircuit<E>>(cs, &self.and_table_config, &());
        fixed.register_table_circuit::<OrTableCircuit<E>>(cs, &self.or_table_config, &());
        fixed.register_table_circuit::<XorTableCircuit<E>>(cs, &self.xor_table_config, &());
        fixed.register_table_circuit::<LtuTableCircuit<E>>(cs, &self.ltu_config, &());
        fixed.register_table_circuit::<PowTableCircuit<E>>(cs, &self.pow_config, &());
    }

    pub fn assign_opcode_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
        steps: Vec<StepRecord>,
    ) -> Result<GroupedSteps, ZKVMError> {
        let mut all_records: BTreeMap<usize, Vec<StepRecord>> = InsnKind::iter()
            .map(|insn_kind| ((insn_kind as usize), Vec::new()))
            .collect();
        let mut halt_records = Vec::new();
        steps.into_iter().for_each(|record| {
            let insn_kind = record.insn().codes().kind;
            match insn_kind {
                // ecall / halt
                EANY if record.rs1().unwrap().value == Platform::ecall_halt() => {
                    halt_records.push(record);
                }
                // other type of ecalls are handled by dummy ecall instruction
                _ => {
                    let insn_kind = insn_kind as usize;
                    // it's safe to unwrap as all_records are initialized with Vec::new()
                    all_records.get_mut(&insn_kind).unwrap().push(record);
                }
            }
        });

        for (insn_kind, (_, records)) in InsnKind::iter()
            .zip(all_records.iter())
            .sorted_by(|a, b| Ord::cmp(&a.1.1.len(), &b.1.1.len()))
            .rev()
        {
            if !records.is_empty() {
                tracing::info!("tracer generated {:?} {} records", insn_kind, records.len());
            }
        }

        macro_rules! assign_opcode {
            ($insn_kind:ident,$instruction:ty,$config:ident) => {
                witness.assign_opcode_circuit::<$instruction>(
                    cs,
                    &self.$config,
                    all_records.remove(&($insn_kind as usize)).unwrap(),
                )?;
            };
        }
        // alu
        assign_opcode!(ADD, AddInstruction<E>, add_config);
        assign_opcode!(SUB, SubInstruction<E>, sub_config);
        assign_opcode!(AND, AndInstruction<E>, and_config);
        assign_opcode!(OR, OrInstruction<E>, or_config);
        assign_opcode!(XOR, XorInstruction<E>, xor_config);
        assign_opcode!(SLL, SllInstruction<E>, sll_config);
        assign_opcode!(SRL, SrlInstruction<E>, srl_config);
        assign_opcode!(SRA, SraInstruction<E>, sra_config);
        assign_opcode!(SLT, SltInstruction<E>, slt_config);
        assign_opcode!(SLTU, SltuInstruction<E>, sltu_config);
        assign_opcode!(MUL, MulInstruction<E>, mul_config);
        assign_opcode!(MULH, MulhInstruction<E>, mulh_config);
        assign_opcode!(MULHSU, MulhsuInstruction<E>, mulhsu_config);
        assign_opcode!(MULHU, MulhuInstruction<E>, mulhu_config);
        assign_opcode!(DIVU, DivUInstruction<E>, divu_config);
        // alu with imm
        assign_opcode!(ADDI, AddiInstruction<E>, addi_config);
        assign_opcode!(ANDI, AndiInstruction<E>, andi_config);
        assign_opcode!(ORI, OriInstruction<E>, ori_config);
        assign_opcode!(XORI, XoriInstruction<E>, xori_config);
        assign_opcode!(SLLI, SlliInstruction<E>, slli_config);
        assign_opcode!(SRLI, SrliInstruction<E>, srli_config);
        assign_opcode!(SRAI, SraiInstruction<E>, srai_config);
        assign_opcode!(SLTI, SltiInstruction<E>, slti_config);
        assign_opcode!(SLTIU, SltiuInstruction<E>, sltiu_config);
        // branching
        assign_opcode!(BEQ, BeqInstruction<E>, beq_config);
        assign_opcode!(BNE, BneInstruction<E>, bne_config);
        assign_opcode!(BLT, BltInstruction<E>, blt_config);
        assign_opcode!(BLTU, BltuInstruction<E>, bltu_config);
        assign_opcode!(BGE, BgeInstruction<E>, bge_config);
        assign_opcode!(BGEU, BgeuInstruction<E>, bgeu_config);
        // jump
        assign_opcode!(JAL, JalInstruction<E>, jal_config);
        assign_opcode!(JALR, JalrInstruction<E>, jalr_config);
        assign_opcode!(AUIPC, AuipcInstruction<E>, auipc_config);
        assign_opcode!(LUI, LuiInstruction<E>, lui_config);
        // memory
        assign_opcode!(LW, LwInstruction<E>, lw_config);
        assign_opcode!(LB, LbInstruction<E>, lb_config);
        assign_opcode!(LBU, LbuInstruction<E>, lbu_config);
        assign_opcode!(LH, LhInstruction<E>, lh_config);
        assign_opcode!(LHU, LhuInstruction<E>, lhu_config);
        assign_opcode!(SW, SwInstruction<E>, sw_config);
        assign_opcode!(SH, ShInstruction<E>, sh_config);
        assign_opcode!(SB, SbInstruction<E>, sb_config);

        // ecall / halt
        witness.assign_opcode_circuit::<HaltInstruction<E>>(cs, &self.halt_config, halt_records)?;

        assert_eq!(
            all_records.keys().cloned().collect::<BTreeSet<_>>(),
            // these are opcodes that haven't been implemented
            [INVALID, DIV, REM, REMU, EANY]
                .into_iter()
                .map(|insn_kind| insn_kind as usize)
                .collect::<BTreeSet<_>>(),
        );
        Ok(GroupedSteps(all_records))
    }

    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
    ) -> Result<(), ZKVMError> {
        witness.assign_table_circuit::<U16TableCircuit<E>>(cs, &self.u16_range_config, &())?;
        witness.assign_table_circuit::<U14TableCircuit<E>>(cs, &self.u14_range_config, &())?;
        witness.assign_table_circuit::<U8TableCircuit<E>>(cs, &self.u8_range_config, &())?;
        witness.assign_table_circuit::<U5TableCircuit<E>>(cs, &self.u5_range_config, &())?;
        witness.assign_table_circuit::<AndTableCircuit<E>>(cs, &self.and_table_config, &())?;
        witness.assign_table_circuit::<OrTableCircuit<E>>(cs, &self.or_table_config, &())?;
        witness.assign_table_circuit::<XorTableCircuit<E>>(cs, &self.xor_table_config, &())?;
        witness.assign_table_circuit::<LtuTableCircuit<E>>(cs, &self.ltu_config, &())?;
        witness.assign_table_circuit::<PowTableCircuit<E>>(cs, &self.pow_config, &())?;

        Ok(())
    }
}

/// Opaque type to pass unimplemented instructions from Rv32imConfig to DummyExtraConfig.
pub struct GroupedSteps(BTreeMap<usize, Vec<StepRecord>>);

/// Fake version of what is missing in Rv32imConfig, for some tests.
pub struct DummyExtraConfig<E: ExtensionField> {
    ecall_config: <EcallDummy<E> as Instruction<E>>::InstructionConfig,
    div_config: <DivDummy<E> as Instruction<E>>::InstructionConfig,
    rem_config: <RemDummy<E> as Instruction<E>>::InstructionConfig,
    remu_config: <RemuDummy<E> as Instruction<E>>::InstructionConfig,
}

impl<E: ExtensionField> DummyExtraConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let div_config = cs.register_opcode_circuit::<DivDummy<E>>();
        let rem_config = cs.register_opcode_circuit::<RemDummy<E>>();
        let remu_config = cs.register_opcode_circuit::<RemuDummy<E>>();
        let ecall_config = cs.register_opcode_circuit::<EcallDummy<E>>();
        Self {
            div_config,
            rem_config,
            remu_config,
            ecall_config,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
    ) {
        fixed.register_opcode_circuit::<DivDummy<E>>(cs);
        fixed.register_opcode_circuit::<RemDummy<E>>(cs);
        fixed.register_opcode_circuit::<RemuDummy<E>>(cs);
        fixed.register_opcode_circuit::<EcallDummy<E>>(cs);
    }

    pub fn assign_opcode_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
        steps: GroupedSteps,
    ) -> Result<(), ZKVMError> {
        let mut steps = steps.0;

        macro_rules! assign_opcode {
            ($insn_kind:ident,$instruction:ty,$config:ident) => {
                witness.assign_opcode_circuit::<$instruction>(
                    cs,
                    &self.$config,
                    steps.remove(&($insn_kind as usize)).unwrap(),
                )?;
            };
        }

        assign_opcode!(DIV, DivDummy<E>, div_config);
        assign_opcode!(REM, RemDummy<E>, rem_config);
        assign_opcode!(REMU, RemuDummy<E>, remu_config);
        assign_opcode!(EANY, EcallDummy<E>, ecall_config);

        let _ = steps.remove(&(INVALID as usize));
        assert!(steps.is_empty());
        Ok(())
    }
}
