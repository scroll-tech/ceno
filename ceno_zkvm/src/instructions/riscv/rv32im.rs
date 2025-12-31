use super::{
    arith::AddInstruction, branch::BltuInstruction, ecall::HaltInstruction, jump::JalInstruction,
    memory::LwInstruction,
};
#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::auipc::AuipcInstruction;
#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::lui::LuiInstruction;
#[cfg(not(feature = "u16limb_circuit"))]
use crate::tables::PowTableCircuit;
use crate::{
    e2e::{ShardContext, StepCellExtractor},
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{
            arith_imm::AddiInstruction,
            branch::{
                BeqInstruction, BgeInstruction, BgeuInstruction, BltInstruction, BneInstruction,
            },
            div::{DivInstruction, DivuInstruction, RemInstruction, RemuInstruction},
            ecall::{
                KeccakInstruction, Secp256k1InvInstruction, Secp256r1InvInstruction,
                Uint256MulInstruction, WeierstrassAddAssignInstruction,
                WeierstrassDecompressInstruction, WeierstrassDoubleAssignInstruction,
            },
            logic::{AndInstruction, OrInstruction, XorInstruction},
            logic_imm::{AndiInstruction, OriInstruction, XoriInstruction},
            mulh::MulhuInstruction,
            shift::{SllInstruction, SrlInstruction},
            shift_imm::{SlliInstruction, SraiInstruction, SrliInstruction},
            slti::SltiInstruction,
            *,
        },
    },
    scheme::constants::DYNAMIC_RANGE_MAX_BITS,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        AndTableCircuit, DoubleU8TableCircuit, DynamicRangeTableCircuit, LtuTableCircuit,
        OrTableCircuit, TableCircuit, XorTableCircuit,
    },
};
use ceno_emul::{
    Bn254AddSpec, Bn254DoubleSpec, Bn254Fp2AddSpec, Bn254Fp2MulSpec, Bn254FpAddSpec,
    Bn254FpMulSpec,
    InsnKind::{self, *},
    KeccakSpec, LogPcCycleSpec, Platform, Secp256k1AddSpec, Secp256k1DecompressSpec,
    Secp256k1DoubleSpec, Secp256k1ScalarInvertSpec, Secp256r1AddSpec, Secp256r1DoubleSpec,
    Secp256r1ScalarInvertSpec, Sha256ExtendSpec, StepRecord, SyscallSpec, Uint256MulSpec,
};
use dummy::LargeEcallDummy;
use ecall::EcallDummy;
use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use mulh::{MulInstruction, MulhInstruction, MulhsuInstruction};
use shift::SraInstruction;
use slt::{SltInstruction, SltuInstruction};
use slti::SltiuInstruction;
use sp1_curves::weierstrass::{SwCurve, bn254::Bn254, secp256k1::Secp256k1, secp256r1::Secp256r1};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, HashMap},
};
use strum::{EnumCount, IntoEnumIterator};

pub mod mmu;

const ECALL_HALT: u32 = Platform::ecall_halt();

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
    pub divu_config: <DivuInstruction<E> as Instruction<E>>::InstructionConfig,
    pub remu_config: <RemuInstruction<E> as Instruction<E>>::InstructionConfig,
    pub div_config: <DivInstruction<E> as Instruction<E>>::InstructionConfig,
    pub rem_config: <RemInstruction<E> as Instruction<E>>::InstructionConfig,

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
    #[cfg(feature = "u16limb_circuit")]
    pub lui_config: <LuiInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "u16limb_circuit")]
    pub auipc_config: <AuipcInstruction<E> as Instruction<E>>::InstructionConfig,

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
    pub keccak_config: <KeccakInstruction<E> as Instruction<E>>::InstructionConfig,
    pub bn254_add_config:
        <WeierstrassAddAssignInstruction<E, SwCurve<Bn254>> as Instruction<E>>::InstructionConfig,
    pub bn254_double_config:
        <WeierstrassDoubleAssignInstruction<E, SwCurve<Bn254>> as Instruction<E>>::InstructionConfig,
    pub secp256k1_add_config:
        <WeierstrassAddAssignInstruction<E, SwCurve<Secp256k1>> as Instruction<E>>::InstructionConfig,
    pub secp256k1_double_config:
        <WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256k1>> as Instruction<E>>::InstructionConfig,
    pub secp256k1_scalar_invert:
        <Secp256k1InvInstruction<E> as Instruction<E>>::InstructionConfig,
    pub secp256k1_decompress_config:
        <WeierstrassDecompressInstruction<E, SwCurve<Secp256k1>> as Instruction<E>>::InstructionConfig,
    pub secp256r1_add_config:
        <WeierstrassAddAssignInstruction<E, SwCurve<Secp256r1>> as Instruction<E>>::InstructionConfig,
    pub secp256r1_double_config:
        <WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256r1>> as Instruction<E>>::InstructionConfig,
    pub secp256r1_scalar_invert:
        <Secp256r1InvInstruction<E> as Instruction<E>>::InstructionConfig,
    pub uint256_mul_config:
        <Uint256MulInstruction<E> as Instruction<E>>::InstructionConfig,

    // Tables.
    pub dynamic_range_config: <DynamicRangeTableCircuit<E, 18> as TableCircuit<E>>::TableConfig,
    pub double_u8_range_config: <DoubleU8TableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub and_table_config: <AndTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub or_table_config: <OrTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub xor_table_config: <XorTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub ltu_config: <LtuTableCircuit<E> as TableCircuit<E>>::TableConfig,
    #[cfg(not(feature = "u16limb_circuit"))]
    pub pow_config: <PowTableCircuit<E> as TableCircuit<E>>::TableConfig,
    // record InsnKind -> cells
    pub inst_cells_map: Vec<u64>,
    // record opcode name -> cells
    // serve ecall/table for no InsnKind
    pub ecall_cells_map: HashMap<String, u64>,
}

const KECCAK_CELL_BLOWUP_FACTOR: u64 = 2;

impl<E: ExtensionField> Rv32imConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let mut inst_cells_map = vec![0; InsnKind::COUNT];
        let mut ecall_cells_map = HashMap::new();

        macro_rules! register_opcode_circuit {
            ($insn_kind:ident, $instruction:ty, $inst_cells_map:ident) => {{
                let config = cs.register_opcode_circuit::<$instruction>();

                // update estimated cell
                $inst_cells_map[$insn_kind as usize] = cs
                    .get_cs(&<$instruction>::name())
                    .as_ref()
                    .map(|cs| {
                        (cs.zkvm_v1_css.num_witin as u64
                            + cs.zkvm_v1_css.num_structural_witin as u64
                            + cs.zkvm_v1_css.num_fixed as u64)
                            * (1 << cs.rotation_vars().unwrap_or(0))
                    })
                    .unwrap_or_default();

                config
            }};
        }
        // opcode circuits
        // alu opcodes
        let add_config = register_opcode_circuit!(ADD, AddInstruction<E>, inst_cells_map);
        let sub_config = register_opcode_circuit!(SUB, SubInstruction<E>, inst_cells_map);
        let and_config = register_opcode_circuit!(AND, AndInstruction<E>, inst_cells_map);
        let or_config = register_opcode_circuit!(OR, OrInstruction<E>, inst_cells_map);
        let xor_config = register_opcode_circuit!(XOR, XorInstruction<E>, inst_cells_map);
        let sll_config = register_opcode_circuit!(SLL, SllInstruction<E>, inst_cells_map);
        let srl_config = register_opcode_circuit!(SRL, SrlInstruction<E>, inst_cells_map);
        let sra_config = register_opcode_circuit!(SRA, SraInstruction<E>, inst_cells_map);
        let slt_config = register_opcode_circuit!(SLT, SltInstruction<E>, inst_cells_map);
        let sltu_config = register_opcode_circuit!(SLTU, SltuInstruction<E>, inst_cells_map);
        let mul_config = register_opcode_circuit!(MUL, MulInstruction<E>, inst_cells_map);
        let mulh_config = register_opcode_circuit!(MULH, MulhInstruction<E>, inst_cells_map);
        let mulhsu_config = register_opcode_circuit!(MULHSU, MulhsuInstruction<E>, inst_cells_map);
        let mulhu_config = register_opcode_circuit!(MULHU, MulhuInstruction<E>, inst_cells_map);
        let divu_config = register_opcode_circuit!(DIVU, DivuInstruction<E>, inst_cells_map);
        let remu_config = register_opcode_circuit!(REMU, RemuInstruction<E>, inst_cells_map);
        let div_config = register_opcode_circuit!(DIV, DivInstruction<E>, inst_cells_map);
        let rem_config = register_opcode_circuit!(REM, RemInstruction<E>, inst_cells_map);

        // alu with imm opcodes
        let addi_config = register_opcode_circuit!(ADDI, AddiInstruction<E>, inst_cells_map);
        let andi_config = register_opcode_circuit!(ANDI, AndiInstruction<E>, inst_cells_map);
        let ori_config = register_opcode_circuit!(ORI, OriInstruction<E>, inst_cells_map);
        let xori_config = register_opcode_circuit!(XORI, XoriInstruction<E>, inst_cells_map);
        let slli_config = register_opcode_circuit!(SLLI, SlliInstruction<E>, inst_cells_map);
        let srli_config = register_opcode_circuit!(SRLI, SrliInstruction<E>, inst_cells_map);
        let srai_config = register_opcode_circuit!(SRAI, SraiInstruction<E>, inst_cells_map);
        let slti_config = register_opcode_circuit!(SLTI, SltiInstruction<E>, inst_cells_map);
        let sltiu_config = register_opcode_circuit!(SLTIU, SltiuInstruction<E>, inst_cells_map);
        #[cfg(feature = "u16limb_circuit")]
        let lui_config = register_opcode_circuit!(LUI, LuiInstruction<E>, inst_cells_map);
        #[cfg(feature = "u16limb_circuit")]
        let auipc_config = register_opcode_circuit!(AUIPC, AuipcInstruction<E>, inst_cells_map);

        // branching opcodes
        let beq_config = register_opcode_circuit!(BEQ, BeqInstruction<E>, inst_cells_map);
        let bne_config = register_opcode_circuit!(BNE, BneInstruction<E>, inst_cells_map);
        let blt_config = register_opcode_circuit!(BLT, BltInstruction<E>, inst_cells_map);
        let bltu_config = register_opcode_circuit!(BLTU, BltuInstruction<E>, inst_cells_map);
        let bge_config = register_opcode_circuit!(BGE, BgeInstruction<E>, inst_cells_map);
        let bgeu_config = register_opcode_circuit!(BGEU, BgeuInstruction<E>, inst_cells_map);

        // jump opcodes
        let jal_config = register_opcode_circuit!(JAL, JalInstruction<E>, inst_cells_map);
        let jalr_config = register_opcode_circuit!(JALR, JalrInstruction<E>, inst_cells_map);

        // memory opcodes
        let lw_config = register_opcode_circuit!(LW, LwInstruction<E>, inst_cells_map);
        let lhu_config = register_opcode_circuit!(LHU, LhuInstruction<E>, inst_cells_map);
        let lh_config = register_opcode_circuit!(LH, LhInstruction<E>, inst_cells_map);
        let lbu_config = register_opcode_circuit!(LBU, LbuInstruction<E>, inst_cells_map);
        let lb_config = register_opcode_circuit!(LB, LbInstruction<E>, inst_cells_map);
        let sw_config = register_opcode_circuit!(SW, SwInstruction<E>, inst_cells_map);
        let sh_config = register_opcode_circuit!(SH, ShInstruction<E>, inst_cells_map);
        let sb_config = register_opcode_circuit!(SB, SbInstruction<E>, inst_cells_map);

        // ecall opcodes
        macro_rules! register_ecall_circuit {
            ($instruction:ty, $ecall_cells_map:ident) => {{
                let config = cs.register_opcode_circuit::<$instruction>();

                // update estimated cell
                assert!(
                    $ecall_cells_map
                        .insert(
                            <$instruction>::name(),
                            cs.get_cs(&<$instruction>::name())
                                .as_ref()
                                .map(|cs| {
                                    (cs.zkvm_v1_css.num_witin as u64
                                        + cs.zkvm_v1_css.num_structural_witin as u64
                                        + cs.zkvm_v1_css.num_fixed as u64)
                                        * (1 << cs.rotation_vars().unwrap_or(0))
                                })
                                .unwrap_or_default(),
                        )
                        .is_none()
                );

                config
            }};
        }
        let halt_config = register_ecall_circuit!(HaltInstruction<E>, ecall_cells_map);

        // Keccak precompile is a known hotspot for peak memory.
        // Its heavy read/write/LK activity inflates tower-witness usage, causing
        // substantial memory overhead which not reflected on basic column count.
        //
        // We estimate this effect by applying an extra scaling factor that models
        // tower-witness blowup proportional to the number of base columns.
        let keccak_config = cs.register_opcode_circuit::<KeccakInstruction<E>>();
        assert!(
            ecall_cells_map
                .insert(
                    <KeccakInstruction<E>>::name(),
                    cs.get_cs(&<KeccakInstruction<E>>::name())
                        .as_ref()
                        .map(|cs| {
                            (cs.zkvm_v1_css.num_witin as u64
                                + cs.zkvm_v1_css.num_structural_witin as u64
                                + cs.zkvm_v1_css.num_fixed as u64)
                                * (1 << cs.rotation_vars().unwrap_or(0))
                                * KECCAK_CELL_BLOWUP_FACTOR
                        })
                        .unwrap_or_default(),
                )
                .is_none()
        );
        let bn254_add_config = register_ecall_circuit!(WeierstrassAddAssignInstruction<E, SwCurve<Bn254>>, ecall_cells_map);
        let bn254_double_config = register_ecall_circuit!(WeierstrassDoubleAssignInstruction<E, SwCurve<Bn254>>, ecall_cells_map);
        let secp256k1_add_config = register_ecall_circuit!(WeierstrassAddAssignInstruction<E, SwCurve<Secp256k1>>, ecall_cells_map);
        let secp256k1_double_config = register_ecall_circuit!(WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256k1>>, ecall_cells_map);
        let secp256k1_decompress_config = register_ecall_circuit!(WeierstrassDecompressInstruction<E, SwCurve<Secp256k1>>, ecall_cells_map);
        let secp256k1_scalar_invert =
            register_ecall_circuit!(Secp256k1InvInstruction<E>, ecall_cells_map);
        let secp256r1_add_config = register_ecall_circuit!(WeierstrassAddAssignInstruction<E, SwCurve<Secp256r1>>, ecall_cells_map);
        let secp256r1_double_config = register_ecall_circuit!(WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256r1>>, ecall_cells_map);
        let secp256r1_scalar_invert =
            register_ecall_circuit!(Secp256r1InvInstruction<E>, ecall_cells_map);
        let uint256_mul_config = register_ecall_circuit!(Uint256MulInstruction<E>, ecall_cells_map);

        // tables
        let dynamic_range_config =
            cs.register_table_circuit::<DynamicRangeTableCircuit<E, DYNAMIC_RANGE_MAX_BITS>>();
        let double_u8_range_config = cs.register_table_circuit::<DoubleU8TableCircuit<E>>();
        let and_table_config = cs.register_table_circuit::<AndTableCircuit<E>>();
        let or_table_config = cs.register_table_circuit::<OrTableCircuit<E>>();
        let xor_table_config = cs.register_table_circuit::<XorTableCircuit<E>>();
        let ltu_config = cs.register_table_circuit::<LtuTableCircuit<E>>();
        #[cfg(not(feature = "u16limb_circuit"))]
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
            remu_config,
            div_config,
            rem_config,
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
            #[cfg(feature = "u16limb_circuit")]
            lui_config,
            #[cfg(feature = "u16limb_circuit")]
            auipc_config,
            // branching opcodes
            beq_config,
            bne_config,
            blt_config,
            bltu_config,
            bge_config,
            bgeu_config,
            // jump opcodes
            jal_config,
            jalr_config,
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
            keccak_config,
            bn254_add_config,
            bn254_double_config,
            secp256k1_add_config,
            secp256k1_double_config,
            secp256k1_scalar_invert,
            secp256k1_decompress_config,
            secp256r1_add_config,
            secp256r1_double_config,
            secp256r1_scalar_invert,
            uint256_mul_config,
            // tables
            dynamic_range_config,
            double_u8_range_config,
            and_table_config,
            or_table_config,
            xor_table_config,
            ltu_config,
            #[cfg(not(feature = "u16limb_circuit"))]
            pow_config,
            inst_cells_map,
            ecall_cells_map,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
    ) {
        // alu
        fixed.register_opcode_circuit::<AddInstruction<E>>(cs, &self.add_config);
        fixed.register_opcode_circuit::<SubInstruction<E>>(cs, &self.sub_config);
        fixed.register_opcode_circuit::<AndInstruction<E>>(cs, &self.and_config);
        fixed.register_opcode_circuit::<OrInstruction<E>>(cs, &self.or_config);
        fixed.register_opcode_circuit::<XorInstruction<E>>(cs, &self.xor_config);
        fixed.register_opcode_circuit::<SllInstruction<E>>(cs, &self.sll_config);
        fixed.register_opcode_circuit::<SrlInstruction<E>>(cs, &self.srl_config);
        fixed.register_opcode_circuit::<SraInstruction<E>>(cs, &self.sra_config);
        fixed.register_opcode_circuit::<SltInstruction<E>>(cs, &self.slt_config);
        fixed.register_opcode_circuit::<SltuInstruction<E>>(cs, &self.sltu_config);
        fixed.register_opcode_circuit::<MulInstruction<E>>(cs, &self.mul_config);
        fixed.register_opcode_circuit::<MulhInstruction<E>>(cs, &self.mulh_config);
        fixed.register_opcode_circuit::<MulhsuInstruction<E>>(cs, &self.mulhsu_config);
        fixed.register_opcode_circuit::<MulhuInstruction<E>>(cs, &self.mulhu_config);
        fixed.register_opcode_circuit::<DivuInstruction<E>>(cs, &self.divu_config);
        fixed.register_opcode_circuit::<RemuInstruction<E>>(cs, &self.remu_config);
        fixed.register_opcode_circuit::<DivInstruction<E>>(cs, &self.div_config);
        fixed.register_opcode_circuit::<RemInstruction<E>>(cs, &self.rem_config);
        // alu with imm
        fixed.register_opcode_circuit::<AddiInstruction<E>>(cs, &self.addi_config);
        fixed.register_opcode_circuit::<AndiInstruction<E>>(cs, &self.andi_config);
        fixed.register_opcode_circuit::<OriInstruction<E>>(cs, &self.ori_config);
        fixed.register_opcode_circuit::<XoriInstruction<E>>(cs, &self.xori_config);
        fixed.register_opcode_circuit::<SlliInstruction<E>>(cs, &self.slli_config);
        fixed.register_opcode_circuit::<SrliInstruction<E>>(cs, &self.srli_config);
        fixed.register_opcode_circuit::<SraiInstruction<E>>(cs, &self.srai_config);
        fixed.register_opcode_circuit::<SltiInstruction<E>>(cs, &self.slti_config);
        fixed.register_opcode_circuit::<SltiuInstruction<E>>(cs, &self.sltiu_config);
        #[cfg(feature = "u16limb_circuit")]
        fixed.register_opcode_circuit::<LuiInstruction<E>>(cs, &self.lui_config);
        #[cfg(feature = "u16limb_circuit")]
        fixed.register_opcode_circuit::<AuipcInstruction<E>>(cs, &self.auipc_config);
        // branching
        fixed.register_opcode_circuit::<BeqInstruction<E>>(cs, &self.beq_config);
        fixed.register_opcode_circuit::<BneInstruction<E>>(cs, &self.bne_config);
        fixed.register_opcode_circuit::<BltInstruction<E>>(cs, &self.blt_config);
        fixed.register_opcode_circuit::<BltuInstruction<E>>(cs, &self.bltu_config);
        fixed.register_opcode_circuit::<BgeInstruction<E>>(cs, &self.bge_config);
        fixed.register_opcode_circuit::<BgeuInstruction<E>>(cs, &self.bgeu_config);

        // jump
        fixed.register_opcode_circuit::<JalInstruction<E>>(cs, &self.jal_config);
        fixed.register_opcode_circuit::<JalrInstruction<E>>(cs, &self.jalr_config);

        // memory
        fixed.register_opcode_circuit::<SwInstruction<E>>(cs, &self.sw_config);
        fixed.register_opcode_circuit::<ShInstruction<E>>(cs, &self.sh_config);
        fixed.register_opcode_circuit::<SbInstruction<E>>(cs, &self.sb_config);
        fixed.register_opcode_circuit::<LwInstruction<E>>(cs, &self.lw_config);
        fixed.register_opcode_circuit::<LhuInstruction<E>>(cs, &self.lhu_config);
        fixed.register_opcode_circuit::<LhInstruction<E>>(cs, &self.lh_config);
        fixed.register_opcode_circuit::<LbuInstruction<E>>(cs, &self.lbu_config);
        fixed.register_opcode_circuit::<LbInstruction<E>>(cs, &self.lb_config);

        // system
        fixed.register_opcode_circuit::<HaltInstruction<E>>(cs, &self.halt_config);
        fixed.register_opcode_circuit::<KeccakInstruction<E>>(cs, &self.keccak_config);
        fixed.register_opcode_circuit::<WeierstrassAddAssignInstruction<E, SwCurve<Bn254>>>(
            cs,
            &self.bn254_add_config,
        );
        fixed.register_opcode_circuit::<WeierstrassDoubleAssignInstruction<E, SwCurve<Bn254>>>(
            cs,
            &self.bn254_double_config,
        );
        fixed.register_opcode_circuit::<WeierstrassAddAssignInstruction<E, SwCurve<Secp256k1>>>(
            cs,
            &self.secp256k1_add_config,
        );
        fixed.register_opcode_circuit::<WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256k1>>>(
            cs,
            &self.secp256k1_double_config,
        );
        fixed.register_opcode_circuit::<WeierstrassDecompressInstruction<E, SwCurve<Secp256k1>>>(
            cs,
            &self.secp256k1_decompress_config,
        );
        fixed.register_opcode_circuit::<WeierstrassAddAssignInstruction<E, SwCurve<Secp256r1>>>(
            cs,
            &self.secp256r1_add_config,
        );
        fixed.register_opcode_circuit::<WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256r1>>>(
            cs,
            &self.secp256r1_double_config,
        );
        fixed.register_opcode_circuit::<Uint256MulInstruction<E>>(cs, &self.uint256_mul_config);

        // table
        fixed.register_table_circuit::<DynamicRangeTableCircuit<E, DYNAMIC_RANGE_MAX_BITS>>(
            cs,
            &self.dynamic_range_config,
            &(),
        );
        fixed.register_table_circuit::<DoubleU8TableCircuit<E>>(
            cs,
            &self.double_u8_range_config,
            &(),
        );
        fixed.register_table_circuit::<AndTableCircuit<E>>(cs, &self.and_table_config, &());
        fixed.register_table_circuit::<OrTableCircuit<E>>(cs, &self.or_table_config, &());
        fixed.register_table_circuit::<XorTableCircuit<E>>(cs, &self.xor_table_config, &());
        fixed.register_table_circuit::<LtuTableCircuit<E>>(cs, &self.ltu_config, &());
        #[cfg(not(feature = "u16limb_circuit"))]
        fixed.register_table_circuit::<PowTableCircuit<E>>(cs, &self.pow_config, &());
    }

    pub fn assign_opcode_circuit<'a>(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        shard_ctx: &mut ShardContext,
        witness: &mut ZKVMWitnesses<E>,
        steps: &'a [StepRecord],
    ) -> Result<GroupedSteps<'a>, ZKVMError> {
        let mut all_records: BTreeMap<InsnKind, Vec<&StepRecord>> = InsnKind::iter()
            .map(|insn_kind| (insn_kind, Vec::new()))
            .collect();
        let mut halt_records = Vec::new();
        let mut keccak_records = Vec::new();
        let mut bn254_add_records = Vec::new();
        let mut bn254_double_records = Vec::new();
        let mut secp256k1_add_records = Vec::new();
        let mut secp256k1_double_records = Vec::new();
        let mut secp256k1_decompress_records = Vec::new();
        let mut uint256_mul_records = Vec::new();
        let mut secp256k1_scalar_invert_records = Vec::new();
        let mut secp256r1_add_records = Vec::new();
        let mut secp256r1_double_records = Vec::new();
        let mut secp256r1_scalar_invert_records = Vec::new();
        steps.iter().for_each(|record| {
            let insn_kind = record.insn.kind;
            match insn_kind {
                // ecall / halt
                InsnKind::ECALL if record.rs1().unwrap().value == Platform::ecall_halt() => {
                    halt_records.push(record);
                }
                InsnKind::ECALL if record.rs1().unwrap().value == KeccakSpec::CODE => {
                    keccak_records.push(record);
                }
                InsnKind::ECALL if record.rs1().unwrap().value == Bn254AddSpec::CODE => {
                    bn254_add_records.push(record);
                }
                InsnKind::ECALL if record.rs1().unwrap().value == Bn254DoubleSpec::CODE => {
                    bn254_double_records.push(record);
                }
                InsnKind::ECALL if record.rs1().unwrap().value == Secp256k1AddSpec::CODE => {
                    secp256k1_add_records.push(record);
                }
                InsnKind::ECALL if record.rs1().unwrap().value == Secp256k1DoubleSpec::CODE => {
                    secp256k1_double_records.push(record);
                }
                InsnKind::ECALL if record.rs1().unwrap().value == Secp256r1AddSpec::CODE => {
                    secp256r1_add_records.push(record);
                }
                InsnKind::ECALL if record.rs1().unwrap().value == Secp256r1DoubleSpec::CODE => {
                    secp256r1_double_records.push(record);
                }
                InsnKind::ECALL
                    if record.rs1().unwrap().value == Secp256k1ScalarInvertSpec::CODE =>
                {
                    secp256k1_scalar_invert_records.push(record);
                }
                InsnKind::ECALL
                    if record.rs1().unwrap().value == Secp256r1ScalarInvertSpec::CODE =>
                {
                    secp256r1_scalar_invert_records.push(record);
                }
                InsnKind::ECALL if record.rs1().unwrap().value == Secp256k1DecompressSpec::CODE => {
                    secp256k1_decompress_records.push(record);
                }
                InsnKind::ECALL if record.rs1().unwrap().value == Uint256MulSpec::CODE => {
                    uint256_mul_records.push(record);
                }
                // other type of ecalls are handled by dummy ecall instruction
                _ => {
                    // it's safe to unwrap as all_records are initialized with Vec::new()
                    all_records.get_mut(&insn_kind).unwrap().push(record);
                }
            }
        });

        for (insn_kind, (_, records)) in
            izip!(InsnKind::iter(), &all_records).sorted_by_key(|(_, (_, a))| Reverse(a.len()))
        {
            tracing::debug!("tracer generated {:?} {} records", insn_kind, records.len());
        }
        tracing::debug!("tracer generated HALT {} records", halt_records.len());
        tracing::debug!("tracer generated KECCAK {} records", keccak_records.len());
        tracing::debug!(
            "tracer generated bn254_add_records {} records",
            bn254_add_records.len()
        );
        tracing::debug!(
            "tracer generated bn254_double_records {} records",
            bn254_double_records.len()
        );
        tracing::debug!(
            "tracer generated secp256k1_add_records {} records",
            secp256k1_add_records.len()
        );
        tracing::debug!(
            "tracer generated secp256k1_double_records {} records",
            secp256k1_double_records.len()
        );
        tracing::debug!(
            "tracer generated secp256k1_scalar_invert_records {} records",
            secp256k1_scalar_invert_records.len()
        );
        tracing::debug!(
            "tracer generated secp256k1_decompress_records {} records",
            secp256k1_decompress_records.len()
        );
        tracing::debug!(
            "tracer generated uint256_mul_records {} records",
            uint256_mul_records.len()
        );

        macro_rules! assign_opcode {
            ($insn_kind:ident,$instruction:ty,$config:ident) => {
                witness.assign_opcode_circuit::<$instruction>(
                    cs,
                    shard_ctx,
                    &self.$config,
                    all_records.remove(&($insn_kind)).unwrap(),
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
        assign_opcode!(DIVU, DivuInstruction<E>, divu_config);
        assign_opcode!(REMU, RemuInstruction<E>, remu_config);
        assign_opcode!(DIV, DivInstruction<E>, div_config);
        assign_opcode!(REM, RemInstruction<E>, rem_config);
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
        #[cfg(feature = "u16limb_circuit")]
        assign_opcode!(LUI, LuiInstruction<E>, lui_config);
        #[cfg(feature = "u16limb_circuit")]
        assign_opcode!(AUIPC, AuipcInstruction<E>, auipc_config);
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
        witness.assign_opcode_circuit::<HaltInstruction<E>>(
            cs,
            shard_ctx,
            &self.halt_config,
            halt_records,
        )?;
        witness.assign_opcode_circuit::<KeccakInstruction<E>>(
            cs,
            shard_ctx,
            &self.keccak_config,
            keccak_records,
        )?;
        witness.assign_opcode_circuit::<WeierstrassAddAssignInstruction<E, SwCurve<Bn254>>>(
            cs,
            shard_ctx,
            &self.bn254_add_config,
            bn254_add_records,
        )?;
        witness.assign_opcode_circuit::<WeierstrassDoubleAssignInstruction<E, SwCurve<Bn254>>>(
            cs,
            shard_ctx,
            &self.bn254_double_config,
            bn254_double_records,
        )?;
        witness.assign_opcode_circuit::<WeierstrassAddAssignInstruction<E, SwCurve<Secp256k1>>>(
            cs,
            shard_ctx,
            &self.secp256k1_add_config,
            secp256k1_add_records,
        )?;
        witness
            .assign_opcode_circuit::<WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256k1>>>(
                cs,
                shard_ctx,
                &self.secp256k1_double_config,
                secp256k1_double_records,
            )?;
        witness.assign_opcode_circuit::<Secp256k1InvInstruction<E>>(
            cs,
            shard_ctx,
            &self.secp256k1_scalar_invert,
            secp256k1_scalar_invert_records,
        )?;
        witness.assign_opcode_circuit::<WeierstrassDecompressInstruction<E, SwCurve<Secp256k1>>>(
            cs,
            shard_ctx,
            &self.secp256k1_decompress_config,
            secp256k1_decompress_records,
        )?;
        witness.assign_opcode_circuit::<WeierstrassAddAssignInstruction<E, SwCurve<Secp256r1>>>(
            cs,
            shard_ctx,
            &self.secp256r1_add_config,
            secp256r1_add_records,
        )?;
        witness
            .assign_opcode_circuit::<WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256r1>>>(
                cs,
                shard_ctx,
                &self.secp256r1_double_config,
                secp256r1_double_records,
            )?;
        witness.assign_opcode_circuit::<Secp256r1InvInstruction<E>>(
            cs,
            shard_ctx,
            &self.secp256r1_scalar_invert,
            secp256r1_scalar_invert_records,
        )?;
        witness.assign_opcode_circuit::<Uint256MulInstruction<E>>(
            cs,
            shard_ctx,
            &self.uint256_mul_config,
            uint256_mul_records,
        )?;

        assert_eq!(
            all_records.keys().cloned().collect::<BTreeSet<_>>(),
            // these are opcodes that haven't been implemented
            [INVALID, ECALL].into_iter().collect::<BTreeSet<_>>(),
        );
        Ok(GroupedSteps(all_records))
    }

    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
    ) -> Result<(), ZKVMError> {
        witness.assign_table_circuit::<DynamicRangeTableCircuit<E, DYNAMIC_RANGE_MAX_BITS>>(
            cs,
            &self.dynamic_range_config,
            &(),
        )?;
        witness.assign_table_circuit::<DoubleU8TableCircuit<E>>(
            cs,
            &self.double_u8_range_config,
            &(),
        )?;
        witness.assign_table_circuit::<AndTableCircuit<E>>(cs, &self.and_table_config, &())?;
        witness.assign_table_circuit::<OrTableCircuit<E>>(cs, &self.or_table_config, &())?;
        witness.assign_table_circuit::<XorTableCircuit<E>>(cs, &self.xor_table_config, &())?;
        witness.assign_table_circuit::<LtuTableCircuit<E>>(cs, &self.ltu_config, &())?;
        #[cfg(not(feature = "u16limb_circuit"))]
        witness.assign_table_circuit::<PowTableCircuit<E>>(cs, &self.pow_config, &())?;

        Ok(())
    }
}

/// Opaque type to pass unimplemented instructions from Rv32imConfig to DummyExtraConfig.
pub struct GroupedSteps<'a>(BTreeMap<InsnKind, Vec<&'a StepRecord>>);

/// Fake version of what is missing in Rv32imConfig, for some tests.
pub struct DummyExtraConfig<E: ExtensionField> {
    ecall_config: <EcallDummy<E> as Instruction<E>>::InstructionConfig,

    sha256_extend_config:
        <LargeEcallDummy<E, Sha256ExtendSpec> as Instruction<E>>::InstructionConfig,
    bn254_fp_add_config: <LargeEcallDummy<E, Bn254FpAddSpec> as Instruction<E>>::InstructionConfig,
    bn254_fp_mul_config: <LargeEcallDummy<E, Bn254FpMulSpec> as Instruction<E>>::InstructionConfig,
    bn254_fp2_add_config:
        <LargeEcallDummy<E, Bn254Fp2AddSpec> as Instruction<E>>::InstructionConfig,
    bn254_fp2_mul_config:
        <LargeEcallDummy<E, Bn254Fp2MulSpec> as Instruction<E>>::InstructionConfig,

    phantom_log_pc_cycle: <LargeEcallDummy<E, LogPcCycleSpec> as Instruction<E>>::InstructionConfig,
}

impl<E: ExtensionField> DummyExtraConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let ecall_config = cs.register_opcode_circuit::<EcallDummy<E>>();
        let sha256_extend_config =
            cs.register_opcode_circuit::<LargeEcallDummy<E, Sha256ExtendSpec>>();
        let bn254_fp_add_config =
            cs.register_opcode_circuit::<LargeEcallDummy<E, Bn254FpAddSpec>>();
        let bn254_fp_mul_config =
            cs.register_opcode_circuit::<LargeEcallDummy<E, Bn254FpMulSpec>>();
        let bn254_fp2_add_config =
            cs.register_opcode_circuit::<LargeEcallDummy<E, Bn254Fp2AddSpec>>();
        let bn254_fp2_mul_config =
            cs.register_opcode_circuit::<LargeEcallDummy<E, Bn254Fp2MulSpec>>();
        let phantom_log_pc_cycle =
            cs.register_opcode_circuit::<LargeEcallDummy<E, LogPcCycleSpec>>();

        Self {
            ecall_config,
            sha256_extend_config,
            bn254_fp_add_config,
            bn254_fp_mul_config,
            bn254_fp2_add_config,
            bn254_fp2_mul_config,
            phantom_log_pc_cycle,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
    ) {
        fixed.register_opcode_circuit::<EcallDummy<E>>(cs, &self.ecall_config);
        fixed.register_opcode_circuit::<LargeEcallDummy<E, Sha256ExtendSpec>>(
            cs,
            &self.sha256_extend_config,
        );
        fixed.register_opcode_circuit::<LargeEcallDummy<E, Bn254FpAddSpec>>(
            cs,
            &self.bn254_fp_add_config,
        );
        fixed.register_opcode_circuit::<LargeEcallDummy<E, Bn254FpMulSpec>>(
            cs,
            &self.bn254_fp_add_config,
        );
        fixed.register_opcode_circuit::<LargeEcallDummy<E, Bn254Fp2AddSpec>>(
            cs,
            &self.bn254_fp2_add_config,
        );
        fixed.register_opcode_circuit::<LargeEcallDummy<E, Bn254Fp2MulSpec>>(
            cs,
            &self.bn254_fp2_mul_config,
        );
        fixed.register_opcode_circuit::<LargeEcallDummy<E, LogPcCycleSpec>>(
            cs,
            &self.phantom_log_pc_cycle,
        );
    }

    pub fn assign_opcode_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        shard_ctx: &mut ShardContext,
        witness: &mut ZKVMWitnesses<E>,
        steps: GroupedSteps,
    ) -> Result<(), ZKVMError> {
        let mut steps = steps.0;

        let mut sha256_extend_steps = Vec::new();
        let mut bn254_fp_add_steps = Vec::new();
        let mut bn254_fp_mul_steps = Vec::new();
        let mut bn254_fp2_add_steps = Vec::new();
        let mut bn254_fp2_mul_steps = Vec::new();
        let mut phantom_log_pc_cycle_spec = Vec::new();
        let mut other_steps = Vec::new();

        if let Some(ecall_steps) = steps.remove(&ECALL) {
            for step in ecall_steps {
                match step.rs1().unwrap().value {
                    Sha256ExtendSpec::CODE => sha256_extend_steps.push(step),
                    Bn254FpAddSpec::CODE => bn254_fp_add_steps.push(step),
                    Bn254FpMulSpec::CODE => bn254_fp_mul_steps.push(step),
                    Bn254Fp2AddSpec::CODE => bn254_fp2_add_steps.push(step),
                    Bn254Fp2MulSpec::CODE => bn254_fp2_mul_steps.push(step),
                    LogPcCycleSpec::CODE => phantom_log_pc_cycle_spec.push(step),
                    _ => other_steps.push(step),
                }
            }
        }

        witness.assign_opcode_circuit::<LargeEcallDummy<E, Sha256ExtendSpec>>(
            cs,
            shard_ctx,
            &self.sha256_extend_config,
            sha256_extend_steps,
        )?;
        witness.assign_opcode_circuit::<LargeEcallDummy<E, Bn254FpAddSpec>>(
            cs,
            shard_ctx,
            &self.bn254_fp_add_config,
            bn254_fp_add_steps,
        )?;
        witness.assign_opcode_circuit::<LargeEcallDummy<E, Bn254FpMulSpec>>(
            cs,
            shard_ctx,
            &self.bn254_fp_mul_config,
            bn254_fp_mul_steps,
        )?;
        witness.assign_opcode_circuit::<LargeEcallDummy<E, Bn254Fp2AddSpec>>(
            cs,
            shard_ctx,
            &self.bn254_fp2_add_config,
            bn254_fp2_add_steps,
        )?;
        witness.assign_opcode_circuit::<LargeEcallDummy<E, Bn254Fp2MulSpec>>(
            cs,
            shard_ctx,
            &self.bn254_fp2_mul_config,
            bn254_fp2_mul_steps,
        )?;
        witness.assign_opcode_circuit::<LargeEcallDummy<E, LogPcCycleSpec>>(
            cs,
            shard_ctx,
            &self.phantom_log_pc_cycle,
            phantom_log_pc_cycle_spec,
        )?;
        witness.assign_opcode_circuit::<EcallDummy<E>>(
            cs,
            shard_ctx,
            &self.ecall_config,
            other_steps,
        )?;

        let _ = steps.remove(&INVALID);
        let keys: Vec<&InsnKind> = steps.keys().collect::<Vec<_>>();
        assert!(steps.is_empty(), "unimplemented opcodes: {:?}", keys);
        Ok(())
    }
}

impl<E: ExtensionField> StepCellExtractor for &Rv32imConfig<E> {
    #[inline(always)]
    fn extract_cells(&self, record: &StepRecord) -> u64 {
        let insn_kind = record.insn.kind;
        if !matches!(insn_kind, InsnKind::ECALL) {
            // quick match for opcode and return
            return self.inst_cells_map[insn_kind as usize];
        }
        // deal with ecall logic
        match record.rs1().unwrap().value {
            // ecall / halt
            ECALL_HALT => *self
                .ecall_cells_map
                .get(&HaltInstruction::<E>::name())
                .expect("unable to find name"),
            KeccakSpec::CODE => *self
                .ecall_cells_map
                .get(&KeccakInstruction::<E>::name())
                .expect("unable to find name"),
            Bn254AddSpec::CODE => *self
                .ecall_cells_map
                .get(&WeierstrassAddAssignInstruction::<E, SwCurve<Bn254>>::name())
                .expect("unable to find name"),
            Bn254DoubleSpec::CODE => *self
                .ecall_cells_map
                .get(&WeierstrassDoubleAssignInstruction::<E, SwCurve<Bn254>>::name())
                .expect("unable to find name"),
            Secp256k1AddSpec::CODE => *self
                .ecall_cells_map
                .get(&WeierstrassAddAssignInstruction::<E, SwCurve<Secp256k1>>::name())
                .expect("unable to find name"),
            Secp256k1DoubleSpec::CODE => *self
                .ecall_cells_map
                .get(&WeierstrassDoubleAssignInstruction::<E, SwCurve<Secp256k1>>::name())
                .expect("unable to find name"),
            Secp256k1ScalarInvertSpec::CODE => *self
                .ecall_cells_map
                .get(&Secp256k1InvInstruction::<E>::name())
                .expect("unable to find name"),
            Secp256k1DecompressSpec::CODE => *self
                .ecall_cells_map
                .get(&WeierstrassDecompressInstruction::<E, SwCurve<Secp256k1>>::name())
                .expect("unable to find name"),
            Secp256r1AddSpec::CODE => *self
                .ecall_cells_map
                .get(&WeierstrassAddAssignInstruction::<E, SwCurve<Secp256r1>>::name())
                .expect("unable to find name"),
            Secp256r1DoubleSpec::CODE => *self
                .ecall_cells_map
                .get(&WeierstrassDoubleAssignInstruction::<E, SwCurve<Secp256r1>>::name())
                .expect("unable to find name"),
            Secp256r1ScalarInvertSpec::CODE => *self
                .ecall_cells_map
                .get(&Secp256r1InvInstruction::<E>::name())
                .expect("unable to find name"),
            Uint256MulSpec::CODE => *self
                .ecall_cells_map
                .get(&Uint256MulInstruction::<E>::name())
                .expect("unable to find name"),
            // phantom
            LogPcCycleSpec::CODE => 0,
            ceno_emul::BN254_FP_ADD
            | ceno_emul::BN254_FP_MUL
            | ceno_emul::BN254_FP2_ADD
            | ceno_emul::BN254_FP2_MUL
            | ceno_emul::SHA_EXTEND => 0,
            // other type of ecalls are handled by dummy ecall instruction
            _ => unreachable!("unknow match record {:?}", record),
        }
    }
}
