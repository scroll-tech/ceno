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
    e2e::ShardContext,
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
                Fp2AddInstruction, Fp2MulInstruction, FpAddInstruction, FpMulInstruction,
                KeccakCoreInstruction, KeccakEcallInstruction, KeccakXorinInstruction,
                PubIoCommitInstruction, Secp256k1InvInstruction, Secp256r1InvInstruction,
                ShaExtendInstruction, Uint256MulInstruction, WeierstrassAddAssignInstruction,
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
    state::GlobalState,
    structs::{
        ComposedConstrainSystem, RAMType, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses,
    },
    tables::{
        AndTableCircuit, DoubleU8TableCircuit, DynamicRangeTableCircuit, LtuTableCircuit,
        OrTableCircuit, TableCircuit, XorTableCircuit,
    },
};
use ceno_emul::{
    Bn254AddSpec, Bn254DoubleSpec, Bn254Fp2AddSpec, Bn254Fp2MulSpec, Bn254FpAddSpec,
    Bn254FpMulSpec, ChipCostSpec, FullTracer as Tracer,
    InsnKind::{self, *},
    KeccakSpec, KeccakXorinSpec, LogPcCycleSpec, Platform, PubIoCommitSpec, STATE_CONTINUATION,
    Secp256k1AddSpec, Secp256k1DecompressSpec, Secp256k1DoubleSpec, Secp256k1ScalarInvertSpec,
    Secp256r1AddSpec, Secp256r1DoubleSpec, Secp256r1ScalarInvertSpec, Sha256ExtendSpec,
    ShardCostModel, StepCellExtractor, StepIndex, StepRecord, SyscallSpec, Uint256MulSpec, Word,
};
use dummy::LargeEcallDummy;
use ff_ext::ExtensionField;
use itertools::Itertools;
use mulh::{MulInstruction, MulhInstruction, MulhsuInstruction};
use shift::SraInstruction;
use slt::{SltInstruction, SltuInstruction};
use slti::SltiuInstruction;
use sp1_curves::weierstrass::{
    SwCurve,
    bn254::{Bn254, Bn254BaseField},
    secp256k1::Secp256k1,
    secp256r1::Secp256r1,
};
use std::{
    any::{TypeId, type_name},
    cmp::Reverse,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use strum::{EnumCount, IntoEnumIterator};
use tracing::info_span;

pub mod mmu;

const ECALL_HALT: u32 = Platform::ecall_halt();
const ECALL_PUB_IO_COMMIT: u32 = PubIoCommitSpec::CODE;

fn chip_cost_spec<E: ExtensionField>(circuit_cs: &ComposedConstrainSystem<E>) -> ChipCostSpec {
    let cs = &circuit_cs.zkvm_v1_css;
    let trace_cells_per_row =
        cs.num_witin as u64 + cs.num_structural_witin as u64 + cs.num_fixed as u64;
    let rotation = circuit_cs.rotation_vars().unwrap_or(0) as u8;

    #[cfg(feature = "gpu")]
    let tower_peak_cells_by_bucket = Some(
        (0..ceno_emul::SHARD_COST_BUCKETS)
            .map(|bucket| match bucket {
                0 => 0,
                bucket if bucket == ceno_emul::SHARD_COST_BUCKETS - 1 => u64::MAX,
                bucket => {
                    let padded_instances = 1u64 << (bucket - 1);
                    padded_instances
                        .checked_shl(rotation.into())
                        .and_then(|rows| usize::try_from(rows).ok())
                        // The final sentinel buckets are unreachable for a VM
                        // trace and can exceed the estimator's shift domain.
                        .filter(|&rows| rows <= (usize::MAX >> 16))
                        .map_or(u64::MAX, |rows| {
                            crate::scheme::gpu::estimate_tower_peak_cells_for_rows(circuit_cs, rows)
                        })
                }
            })
            .collect(),
    );
    #[cfg(not(feature = "gpu"))]
    let tower_peak_cells_by_bucket = None;

    ChipCostSpec {
        rotation,
        trace_cells_per_row,
        // GPU builds use the scheduler's exact bucket table. Keep the old
        // linear estimate only as a feature-independent compatibility fallback.
        tower_peak_cells_per_row: trace_cells_per_row,
        tower_peak_cells_by_bucket,
    }
}

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
    pub pubio_commit_config: <PubIoCommitInstruction<E> as Instruction<E>>::InstructionConfig,
    pub state_continuation_config: <GlobalState<E> as Instruction<E>>::InstructionConfig,
    pub keccak_ecall_config:
        <KeccakEcallInstruction<E> as Instruction<E>>::InstructionConfig,
    pub keccak_core_config:
        <KeccakCoreInstruction<E> as Instruction<E>>::InstructionConfig,
    pub keccak_xorin_config:
        <KeccakXorinInstruction<E> as Instruction<E>>::InstructionConfig,
    pub sha_extend_config: <ShaExtendInstruction<E> as Instruction<E>>::InstructionConfig,
    pub bn254_add_config:
        <WeierstrassAddAssignInstruction<E, SwCurve<Bn254>> as Instruction<E>>::InstructionConfig,
    pub bn254_double_config:
        <WeierstrassDoubleAssignInstruction<E, SwCurve<Bn254>> as Instruction<E>>::InstructionConfig,
    pub bn254_fp_add_config:
        <FpAddInstruction<E, Bn254BaseField> as Instruction<E>>::InstructionConfig,
    pub bn254_fp_mul_config:
        <FpMulInstruction<E, Bn254BaseField> as Instruction<E>>::InstructionConfig,
    pub bn254_fp2_add_config:
        <Fp2AddInstruction<E, Bn254BaseField> as Instruction<E>>::InstructionConfig,
    pub bn254_fp2_mul_config:
        <Fp2MulInstruction<E, Bn254BaseField> as Instruction<E>>::InstructionConfig,
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
    pub shard_cost_model: Arc<ShardCostModel>,
}

#[derive(Clone)]
pub struct InstructionDispatchBuilder {
    record_buffer_count: usize,
    insn_to_record_buffer: Vec<Option<usize>>,
    type_to_record_buffer: HashMap<TypeId, usize>,
}

impl InstructionDispatchBuilder {
    fn new() -> Self {
        Self {
            record_buffer_count: 0,
            insn_to_record_buffer: vec![None; InsnKind::COUNT],
            type_to_record_buffer: HashMap::new(),
        }
    }

    fn register_instruction_kinds<E: ExtensionField, I: Instruction<E> + 'static>(
        &mut self,
        kinds: &[InsnKind],
    ) {
        assert!(
            kinds.iter().all(|kind| *kind != InsnKind::ECALL),
            "ecall dispatch via function code"
        );
        let record_buffer_index = self.record_buffer_count;
        self.record_buffer_count += 1;
        for &kind in kinds {
            if let Some(existing) = self.insn_to_record_buffer[kind as usize] {
                panic!(
                    "Instruction kind {:?} registered multiple times: existing buffer {}, new buffer {} (instruction type: {})",
                    kind,
                    existing,
                    record_buffer_index,
                    type_name::<I>()
                );
            }
            self.insn_to_record_buffer[kind as usize] = Some(record_buffer_index);
        }
        assert!(
            self.type_to_record_buffer
                .insert(TypeId::of::<I>(), record_buffer_index)
                .is_none(),
            "Instruction circuit {} registered more than once",
            type_name::<I>()
        );
    }

    pub fn to_dispatch_ctx(&self) -> InstructionDispatchCtx {
        InstructionDispatchCtx::new(
            self.record_buffer_count,
            self.insn_to_record_buffer.clone(),
            self.type_to_record_buffer.clone(),
        )
    }
}

impl<E: ExtensionField> Rv32imConfig<E> {
    pub fn construct_circuits(
        cs: &mut ZKVMConstraintSystem<E>,
    ) -> (Self, InstructionDispatchBuilder) {
        let mut inst_cells_map = vec![0; InsnKind::COUNT];
        let mut ecall_cells_map = HashMap::new();
        let mut opcode_chips = vec![Vec::new(); InsnKind::COUNT];
        let mut ecall_chips = BTreeMap::new();
        let mut chip_specs = Vec::new();
        let mut ecall_name_to_chips = HashMap::new();

        let mut inst_dispatch_builder = InstructionDispatchBuilder::new();

        macro_rules! register_opcode_circuit {
            ($insn_kind:ident, $instruction:ty, $inst_cells_map:ident) => {{
                inst_dispatch_builder.register_instruction_kinds::<E, $instruction>(
                    <$instruction as Instruction<E>>::inst_kinds(),
                );
                let config = cs.register_opcode_circuit::<$instruction>();
                let circuit_cs = cs.get_cs(&<$instruction>::name());

                // update estimated cell
                $inst_cells_map[$insn_kind as usize] = circuit_cs
                    .as_ref()
                    .map(|cs| {
                        (cs.zkvm_v1_css.num_witin as u64
                            + cs.zkvm_v1_css.num_structural_witin as u64
                            + cs.zkvm_v1_css.num_fixed as u64)
                            * (1 << cs.rotation_vars().unwrap_or(0))
                    })
                    .unwrap_or_default();
                let chip = chip_specs.len();
                let spec = circuit_cs.as_ref().map_or(
                    ChipCostSpec {
                        rotation: 0,
                        trace_cells_per_row: 0,
                        tower_peak_cells_per_row: 0,
                        tower_peak_cells_by_bucket: None,
                    },
                    |circuit_cs| chip_cost_spec(circuit_cs),
                );
                chip_specs.push(spec);
                for &kind in <$instruction as Instruction<E>>::inst_kinds() {
                    opcode_chips[kind as usize] = vec![chip];
                }

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
                let circuit_cs = cs.get_cs(&<$instruction>::name());

                // update estimated cell
                assert!(
                    $ecall_cells_map
                        .insert(
                            <$instruction>::name(),
                            circuit_cs
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
                let chip = chip_specs.len();
                chip_specs.push(circuit_cs.as_ref().map_or(
                    ChipCostSpec {
                        rotation: 0,
                        trace_cells_per_row: 0,
                        tower_peak_cells_per_row: 0,
                        tower_peak_cells_by_bucket: None,
                    },
                    |circuit_cs| chip_cost_spec(circuit_cs),
                ));
                ecall_name_to_chips.insert(<$instruction>::name(), vec![chip]);

                config
            }};
        }
        let halt_config = register_ecall_circuit!(HaltInstruction<E>, ecall_cells_map);
        let pubio_commit_config =
            register_ecall_circuit!(PubIoCommitInstruction<E>, ecall_cells_map);
        let state_continuation_config = register_ecall_circuit!(GlobalState<E>, ecall_cells_map);

        let keccak_ecall_config = cs.register_opcode_circuit::<KeccakEcallInstruction<E>>();
        let keccak_core_config = cs.register_opcode_circuit::<KeccakCoreInstruction<E>>();
        assert!(
            ecall_cells_map
                .insert(
                    <KeccakCoreInstruction<E>>::name(),
                    [
                        <KeccakEcallInstruction<E>>::name(),
                        <KeccakCoreInstruction<E>>::name(),
                    ]
                    .into_iter()
                    .map(|name| {
                        cs.get_cs(&name)
                            .as_ref()
                            .map(|cs| {
                                (cs.zkvm_v1_css.num_witin as u64
                                    + cs.zkvm_v1_css.num_structural_witin as u64
                                    + cs.zkvm_v1_css.num_fixed as u64)
                                    * (1 << cs.rotation_vars().unwrap_or(0))
                            })
                            .unwrap_or_default()
                    })
                    .sum::<u64>(),
                )
                .is_none()
        );
        let mut keccak_chips = Vec::new();
        for name in [
            <KeccakEcallInstruction<E>>::name(),
            <KeccakCoreInstruction<E>>::name(),
        ] {
            let circuit_cs = cs.get_cs(&name).expect("keccak circuit missing");
            keccak_chips.push(chip_specs.len());
            chip_specs.push(chip_cost_spec(circuit_cs));
        }
        ecall_name_to_chips.insert(<KeccakCoreInstruction<E>>::name(), keccak_chips);
        let keccak_xorin_config =
            register_ecall_circuit!(KeccakXorinInstruction<E>, ecall_cells_map);
        let bn254_add_config = register_ecall_circuit!(WeierstrassAddAssignInstruction<E, SwCurve<Bn254>>, ecall_cells_map);
        let sha_extend_config = register_ecall_circuit!(ShaExtendInstruction<E>, ecall_cells_map);
        let bn254_double_config = register_ecall_circuit!(WeierstrassDoubleAssignInstruction<E, SwCurve<Bn254>>, ecall_cells_map);
        let bn254_fp_add_config =
            register_ecall_circuit!(FpAddInstruction<E, Bn254BaseField>, ecall_cells_map);
        let bn254_fp_mul_config =
            register_ecall_circuit!(FpMulInstruction<E, Bn254BaseField>, ecall_cells_map);
        let bn254_fp2_add_config =
            register_ecall_circuit!(Fp2AddInstruction<E, Bn254BaseField>, ecall_cells_map);
        let bn254_fp2_mul_config =
            register_ecall_circuit!(Fp2MulInstruction<E, Bn254BaseField>, ecall_cells_map);
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

        let mut map_ecall = |code, name: String| {
            let chips = ecall_name_to_chips
                .get(&name)
                .unwrap_or_else(|| panic!("missing shard cost chip for {name}"))
                .clone();
            assert!(ecall_chips.insert(code, chips).is_none());
        };
        map_ecall(ECALL_HALT, HaltInstruction::<E>::name());
        map_ecall(ECALL_PUB_IO_COMMIT, PubIoCommitInstruction::<E>::name());
        map_ecall(STATE_CONTINUATION, GlobalState::<E>::name());
        map_ecall(KeccakSpec::CODE, KeccakCoreInstruction::<E>::name());
        map_ecall(KeccakXorinSpec::CODE, KeccakXorinInstruction::<E>::name());
        map_ecall(
            Bn254AddSpec::CODE,
            WeierstrassAddAssignInstruction::<E, SwCurve<Bn254>>::name(),
        );
        map_ecall(
            Bn254DoubleSpec::CODE,
            WeierstrassDoubleAssignInstruction::<E, SwCurve<Bn254>>::name(),
        );
        map_ecall(
            Bn254FpAddSpec::CODE,
            FpAddInstruction::<E, Bn254BaseField>::name(),
        );
        map_ecall(
            Bn254FpMulSpec::CODE,
            FpMulInstruction::<E, Bn254BaseField>::name(),
        );
        map_ecall(
            Bn254Fp2AddSpec::CODE,
            Fp2AddInstruction::<E, Bn254BaseField>::name(),
        );
        map_ecall(
            Bn254Fp2MulSpec::CODE,
            Fp2MulInstruction::<E, Bn254BaseField>::name(),
        );
        map_ecall(
            Secp256k1AddSpec::CODE,
            WeierstrassAddAssignInstruction::<E, SwCurve<Secp256k1>>::name(),
        );
        map_ecall(
            Secp256k1DoubleSpec::CODE,
            WeierstrassDoubleAssignInstruction::<E, SwCurve<Secp256k1>>::name(),
        );
        map_ecall(
            Secp256k1ScalarInvertSpec::CODE,
            Secp256k1InvInstruction::<E>::name(),
        );
        map_ecall(
            Secp256k1DecompressSpec::CODE,
            WeierstrassDecompressInstruction::<E, SwCurve<Secp256k1>>::name(),
        );
        map_ecall(
            Secp256r1AddSpec::CODE,
            WeierstrassAddAssignInstruction::<E, SwCurve<Secp256r1>>::name(),
        );
        map_ecall(
            Secp256r1DoubleSpec::CODE,
            WeierstrassDoubleAssignInstruction::<E, SwCurve<Secp256r1>>::name(),
        );
        map_ecall(
            Secp256r1ScalarInvertSpec::CODE,
            Secp256r1InvInstruction::<E>::name(),
        );
        map_ecall(Uint256MulSpec::CODE, Uint256MulInstruction::<E>::name());
        map_ecall(Sha256ExtendSpec::CODE, ShaExtendInstruction::<E>::name());
        let shard_cost_model = Arc::new(ShardCostModel::new(
            opcode_chips,
            ecall_chips,
            chip_specs,
            E::DEGREE,
        ));

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

        let config = Self {
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
            pubio_commit_config,
            state_continuation_config,
            keccak_ecall_config,
            keccak_core_config,
            keccak_xorin_config,
            sha_extend_config,
            bn254_add_config,
            bn254_double_config,
            bn254_fp_add_config,
            bn254_fp_mul_config,
            bn254_fp2_add_config,
            bn254_fp2_mul_config,
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
            shard_cost_model,
        };

        (config, inst_dispatch_builder)
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
        fixed.register_opcode_circuit::<PubIoCommitInstruction<E>>(cs, &self.pubio_commit_config);
        fixed.register_opcode_circuit::<GlobalState<E>>(cs, &self.state_continuation_config);
        fixed.register_opcode_circuit::<KeccakEcallInstruction<E>>(cs, &self.keccak_ecall_config);
        fixed.register_opcode_circuit::<KeccakCoreInstruction<E>>(cs, &self.keccak_core_config);
        fixed.register_opcode_circuit::<KeccakXorinInstruction<E>>(cs, &self.keccak_xorin_config);
        fixed.register_opcode_circuit::<ShaExtendInstruction<E>>(cs, &self.sha_extend_config);
        fixed.register_opcode_circuit::<WeierstrassAddAssignInstruction<E, SwCurve<Bn254>>>(
            cs,
            &self.bn254_add_config,
        );
        fixed.register_opcode_circuit::<WeierstrassDoubleAssignInstruction<E, SwCurve<Bn254>>>(
            cs,
            &self.bn254_double_config,
        );
        fixed.register_opcode_circuit::<FpAddInstruction<E, Bn254BaseField>>(
            cs,
            &self.bn254_fp_add_config,
        );
        fixed.register_opcode_circuit::<FpMulInstruction<E, Bn254BaseField>>(
            cs,
            &self.bn254_fp_mul_config,
        );
        fixed.register_opcode_circuit::<Fp2AddInstruction<E, Bn254BaseField>>(
            cs,
            &self.bn254_fp2_add_config,
        );
        fixed.register_opcode_circuit::<Fp2MulInstruction<E, Bn254BaseField>>(
            cs,
            &self.bn254_fp2_mul_config,
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

    pub fn assign_opcode_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        shard_ctx: &mut ShardContext,
        instrunction_dispatch_ctx: &mut InstructionDispatchCtx,
        shard_steps: &[StepRecord],
        witness: &mut ZKVMWitnesses<E>,
    ) -> Result<(), ZKVMError> {
        instrunction_dispatch_ctx.trace_opcode_stats();

        macro_rules! log_ecall {
            ($desc:literal, $code:expr) => {
                tracing::debug!(
                    "tracer generated {} {} records",
                    $desc,
                    instrunction_dispatch_ctx.count_ecall_code($code)
                );
            };
        }

        log_ecall!("HALT", ECALL_HALT);
        log_ecall!("PUB_IO_COMMIT", ECALL_PUB_IO_COMMIT);
        log_ecall!("STATE_CONTINUATION", STATE_CONTINUATION);
        log_ecall!("KECCAK", KeccakSpec::CODE);
        log_ecall!("KECCAK_XORIN", KeccakXorinSpec::CODE);
        log_ecall!("bn254_add_records", Bn254AddSpec::CODE);
        log_ecall!("bn254_double_records", Bn254DoubleSpec::CODE);
        log_ecall!("bn254_fp_add_records", Bn254FpAddSpec::CODE);
        log_ecall!("bn254_fp_mul_records", Bn254FpMulSpec::CODE);
        log_ecall!("bn254_fp2_add_records", Bn254Fp2AddSpec::CODE);
        log_ecall!("bn254_fp2_mul_records", Bn254Fp2MulSpec::CODE);
        log_ecall!("secp256k1_add_records", Secp256k1AddSpec::CODE);
        log_ecall!("secp256k1_double_records", Secp256k1DoubleSpec::CODE);
        log_ecall!(
            "secp256k1_scalar_invert_records",
            Secp256k1ScalarInvertSpec::CODE
        );
        log_ecall!(
            "secp256k1_decompress_records",
            Secp256k1DecompressSpec::CODE
        );
        log_ecall!("secp256r1_add_records", Secp256r1AddSpec::CODE);
        log_ecall!("secp256r1_double_records", Secp256r1DoubleSpec::CODE);
        log_ecall!(
            "secp256r1_scalar_invert_records",
            Secp256r1ScalarInvertSpec::CODE
        );
        log_ecall!("uint256_mul_records", Uint256MulSpec::CODE);
        log_ecall!("sha_extend_records", Sha256ExtendSpec::CODE);

        macro_rules! assign_opcode {
            ($instruction:ty, $config:ident) => {{
                let records = instrunction_dispatch_ctx
                    .records_for_kinds::<E, $instruction>()
                    .unwrap_or(&[]);
                let n = records.len();
                info_span!("assign_chip", chip = %<$instruction>::name(), n)
                    .in_scope(|| {
                        witness.assign_opcode_circuit::<$instruction>(
                            cs,
                            shard_ctx,
                            &self.$config,
                            shard_steps,
                            records,
                        )
                    })?;
            }};
        }

        macro_rules! assign_ecall {
            ($instruction:ty, $config:ident, $code:expr) => {{
                let records = instrunction_dispatch_ctx
                    .records_for_ecall_code($code)
                    .unwrap_or(&[]);
                let n = records.len();
                info_span!("assign_chip", chip = %<$instruction>::name(), n)
                    .in_scope(|| {
                        witness.assign_opcode_circuit::<$instruction>(
                            cs,
                            shard_ctx,
                            &self.$config,
                            shard_steps,
                            records,
                        )
                    })?;
            }};
        }

        // alu
        assign_opcode!(AddInstruction<E>, add_config);
        assign_opcode!(SubInstruction<E>, sub_config);
        assign_opcode!(AndInstruction<E>, and_config);
        assign_opcode!(OrInstruction<E>, or_config);
        assign_opcode!(XorInstruction<E>, xor_config);
        assign_opcode!(SllInstruction<E>, sll_config);
        assign_opcode!(SrlInstruction<E>, srl_config);
        assign_opcode!(SraInstruction<E>, sra_config);
        assign_opcode!(SltInstruction<E>, slt_config);
        assign_opcode!(SltuInstruction<E>, sltu_config);
        assign_opcode!(MulInstruction<E>, mul_config);
        assign_opcode!(MulhInstruction<E>, mulh_config);
        assign_opcode!(MulhsuInstruction<E>, mulhsu_config);
        assign_opcode!(MulhuInstruction<E>, mulhu_config);
        assign_opcode!(DivuInstruction<E>, divu_config);
        assign_opcode!(RemuInstruction<E>, remu_config);
        assign_opcode!(DivInstruction<E>, div_config);
        assign_opcode!(RemInstruction<E>, rem_config);
        // alu with imm
        assign_opcode!(AddiInstruction<E>, addi_config);
        assign_opcode!(AndiInstruction<E>, andi_config);
        assign_opcode!(OriInstruction<E>, ori_config);
        assign_opcode!(XoriInstruction<E>, xori_config);
        assign_opcode!(SlliInstruction<E>, slli_config);
        assign_opcode!(SrliInstruction<E>, srli_config);
        assign_opcode!(SraiInstruction<E>, srai_config);
        assign_opcode!(SltiInstruction<E>, slti_config);
        assign_opcode!(SltiuInstruction<E>, sltiu_config);
        #[cfg(feature = "u16limb_circuit")]
        assign_opcode!(LuiInstruction<E>, lui_config);
        #[cfg(feature = "u16limb_circuit")]
        assign_opcode!(AuipcInstruction<E>, auipc_config);
        // branching
        assign_opcode!(BeqInstruction<E>, beq_config);
        assign_opcode!(BneInstruction<E>, bne_config);
        assign_opcode!(BltInstruction<E>, blt_config);
        assign_opcode!(BltuInstruction<E>, bltu_config);
        assign_opcode!(BgeInstruction<E>, bge_config);
        assign_opcode!(BgeuInstruction<E>, bgeu_config);
        // jump
        assign_opcode!(JalInstruction<E>, jal_config);
        assign_opcode!(JalrInstruction<E>, jalr_config);
        // memory
        assign_opcode!(LwInstruction<E>, lw_config);
        assign_opcode!(LbInstruction<E>, lb_config);
        assign_opcode!(LbuInstruction<E>, lbu_config);
        assign_opcode!(LhInstruction<E>, lh_config);
        assign_opcode!(LhuInstruction<E>, lhu_config);
        assign_opcode!(SwInstruction<E>, sw_config);
        assign_opcode!(ShInstruction<E>, sh_config);
        assign_opcode!(SbInstruction<E>, sb_config);

        // ecall / halt
        assign_ecall!(HaltInstruction<E>, halt_config, ECALL_HALT);
        assign_ecall!(
            PubIoCommitInstruction<E>,
            pubio_commit_config,
            ECALL_PUB_IO_COMMIT
        );
        assign_ecall!(
            GlobalState<E>,
            state_continuation_config,
            STATE_CONTINUATION
        );
        assign_ecall!(
            KeccakEcallInstruction<E>,
            keccak_ecall_config,
            KeccakSpec::CODE
        );
        assign_ecall!(
            KeccakCoreInstruction<E>,
            keccak_core_config,
            KeccakSpec::CODE
        );
        assign_ecall!(
            KeccakXorinInstruction<E>,
            keccak_xorin_config,
            KeccakXorinSpec::CODE
        );
        assign_ecall!(
            WeierstrassAddAssignInstruction<E, SwCurve<Bn254>>,
            bn254_add_config,
            Bn254AddSpec::CODE
        );
        assign_ecall!(
            WeierstrassDoubleAssignInstruction<E, SwCurve<Bn254>>,
            bn254_double_config,
            Bn254DoubleSpec::CODE
        );
        assign_ecall!(
            FpAddInstruction<E, Bn254BaseField>,
            bn254_fp_add_config,
            Bn254FpAddSpec::CODE
        );
        assign_ecall!(
            FpMulInstruction<E, Bn254BaseField>,
            bn254_fp_mul_config,
            Bn254FpMulSpec::CODE
        );
        assign_ecall!(
            Fp2AddInstruction<E, Bn254BaseField>,
            bn254_fp2_add_config,
            Bn254Fp2AddSpec::CODE
        );
        assign_ecall!(
            Fp2MulInstruction<E, Bn254BaseField>,
            bn254_fp2_mul_config,
            Bn254Fp2MulSpec::CODE
        );
        assign_ecall!(
            WeierstrassAddAssignInstruction<E, SwCurve<Secp256k1>>,
            secp256k1_add_config,
            Secp256k1AddSpec::CODE
        );
        assign_ecall!(
            WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256k1>>,
            secp256k1_double_config,
            Secp256k1DoubleSpec::CODE
        );
        assign_ecall!(
            Secp256k1InvInstruction<E>,
            secp256k1_scalar_invert,
            Secp256k1ScalarInvertSpec::CODE
        );
        assign_ecall!(
            WeierstrassDecompressInstruction<E, SwCurve<Secp256k1>>,
            secp256k1_decompress_config,
            Secp256k1DecompressSpec::CODE
        );
        assign_ecall!(
            WeierstrassAddAssignInstruction<E, SwCurve<Secp256r1>>,
            secp256r1_add_config,
            Secp256r1AddSpec::CODE
        );
        assign_ecall!(
            WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256r1>>,
            secp256r1_double_config,
            Secp256r1DoubleSpec::CODE
        );
        assign_ecall!(
            Secp256r1InvInstruction<E>,
            secp256r1_scalar_invert,
            Secp256r1ScalarInvertSpec::CODE
        );
        assign_ecall!(
            Uint256MulInstruction<E>,
            uint256_mul_config,
            Uint256MulSpec::CODE
        );
        assign_ecall!(
            ShaExtendInstruction<E>,
            sha_extend_config,
            Sha256ExtendSpec::CODE
        );

        Ok(())
    }

    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
    ) -> Result<(), ZKVMError> {
        macro_rules! assign_table {
            ($table:ty, $config:expr) => {
                info_span!("assign_table", table = %<$table>::name())
                    .in_scope(|| witness.assign_table_circuit::<$table>(cs, $config, &()))?;
            };
        }
        assign_table!(DynamicRangeTableCircuit<E, DYNAMIC_RANGE_MAX_BITS>, &self.dynamic_range_config);
        assign_table!(DoubleU8TableCircuit<E>, &self.double_u8_range_config);
        assign_table!(AndTableCircuit<E>, &self.and_table_config);
        assign_table!(OrTableCircuit<E>, &self.or_table_config);
        assign_table!(XorTableCircuit<E>, &self.xor_table_config);
        assign_table!(LtuTableCircuit<E>, &self.ltu_config);
        #[cfg(not(feature = "u16limb_circuit"))]
        assign_table!(PowTableCircuit<E>, &self.pow_config);

        Ok(())
    }

    pub fn collect_step_shardram(
        &self,
        shard_ctx: &mut ShardContext,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let mut lk_multiplicity = crate::witness::LkMultiplicity::default();

        macro_rules! collect {
            ($instruction:ty, $config:ident) => {{
                <$instruction>::collect_lk_and_shardram(
                    &self.$config,
                    shard_ctx,
                    &mut lk_multiplicity,
                    step,
                )?;
            }};
        }

        macro_rules! collect_ecall {
            ($instruction:ty, $config:ident) => {{
                if let Err(err) = <$instruction>::collect_lk_and_shardram(
                    &self.$config,
                    shard_ctx,
                    &mut lk_multiplicity,
                    step,
                ) {
                    if is_missing_lightweight_collector(&err) {
                        collect_generic_ecall_shardram(shard_ctx, step);
                    } else {
                        return Err(err);
                    }
                }
            }};
        }

        match step.insn.kind {
            ADD => collect!(AddInstruction<E>, add_config),
            SUB => collect!(SubInstruction<E>, sub_config),
            AND => collect!(AndInstruction<E>, and_config),
            OR => collect!(OrInstruction<E>, or_config),
            XOR => collect!(XorInstruction<E>, xor_config),
            SLL => collect!(SllInstruction<E>, sll_config),
            SRL => collect!(SrlInstruction<E>, srl_config),
            SRA => collect!(SraInstruction<E>, sra_config),
            SLT => collect!(SltInstruction<E>, slt_config),
            SLTU => collect!(SltuInstruction<E>, sltu_config),
            MUL => collect!(MulInstruction<E>, mul_config),
            MULH => collect!(MulhInstruction<E>, mulh_config),
            MULHSU => collect!(MulhsuInstruction<E>, mulhsu_config),
            MULHU => collect!(MulhuInstruction<E>, mulhu_config),
            DIVU => collect!(DivuInstruction<E>, divu_config),
            REMU => collect!(RemuInstruction<E>, remu_config),
            DIV => collect!(DivInstruction<E>, div_config),
            REM => collect!(RemInstruction<E>, rem_config),
            ADDI => collect!(AddiInstruction<E>, addi_config),
            ANDI => collect!(AndiInstruction<E>, andi_config),
            ORI => collect!(OriInstruction<E>, ori_config),
            XORI => collect!(XoriInstruction<E>, xori_config),
            SLLI => collect!(SlliInstruction<E>, slli_config),
            SRLI => collect!(SrliInstruction<E>, srli_config),
            SRAI => collect!(SraiInstruction<E>, srai_config),
            SLTI => collect!(SltiInstruction<E>, slti_config),
            SLTIU => collect!(SltiuInstruction<E>, sltiu_config),
            #[cfg(feature = "u16limb_circuit")]
            LUI => collect!(LuiInstruction<E>, lui_config),
            #[cfg(feature = "u16limb_circuit")]
            AUIPC => collect!(AuipcInstruction<E>, auipc_config),
            BEQ => collect!(BeqInstruction<E>, beq_config),
            BNE => collect!(BneInstruction<E>, bne_config),
            BLT => collect!(BltInstruction<E>, blt_config),
            BLTU => collect!(BltuInstruction<E>, bltu_config),
            BGE => collect!(BgeInstruction<E>, bge_config),
            BGEU => collect!(BgeuInstruction<E>, bgeu_config),
            JAL => collect!(JalInstruction<E>, jal_config),
            JALR => collect!(JalrInstruction<E>, jalr_config),
            LW => collect!(LwInstruction<E>, lw_config),
            LB => collect!(LbInstruction<E>, lb_config),
            LBU => collect!(LbuInstruction<E>, lbu_config),
            LH => collect!(LhInstruction<E>, lh_config),
            LHU => collect!(LhuInstruction<E>, lhu_config),
            SW => collect!(SwInstruction<E>, sw_config),
            SH => collect!(ShInstruction<E>, sh_config),
            SB => collect!(SbInstruction<E>, sb_config),
            ECALL => {
                let code = step
                    .rs1()
                    .expect("ecall requires rs1 to determine syscall code")
                    .value;
                match code {
                    ECALL_HALT => collect_ecall!(HaltInstruction<E>, halt_config),
                    ECALL_PUB_IO_COMMIT => {
                        collect_ecall!(PubIoCommitInstruction<E>, pubio_commit_config)
                    }
                    STATE_CONTINUATION => collect_ecall!(GlobalState<E>, state_continuation_config),
                    KeccakSpec::CODE => {
                        collect_ecall!(KeccakEcallInstruction<E>, keccak_ecall_config);
                    }
                    KeccakXorinSpec::CODE => {
                        collect_ecall!(KeccakXorinInstruction<E>, keccak_xorin_config)
                    }
                    Bn254AddSpec::CODE => collect_ecall!(
                        WeierstrassAddAssignInstruction<E, SwCurve<Bn254>>,
                        bn254_add_config
                    ),
                    Bn254DoubleSpec::CODE => collect_ecall!(
                        WeierstrassDoubleAssignInstruction<E, SwCurve<Bn254>>,
                        bn254_double_config
                    ),
                    Bn254FpAddSpec::CODE => {
                        collect_ecall!(FpAddInstruction<E, Bn254BaseField>, bn254_fp_add_config)
                    }
                    Bn254FpMulSpec::CODE => {
                        collect_ecall!(FpMulInstruction<E, Bn254BaseField>, bn254_fp_mul_config)
                    }
                    Bn254Fp2AddSpec::CODE => {
                        collect_ecall!(Fp2AddInstruction<E, Bn254BaseField>, bn254_fp2_add_config)
                    }
                    Bn254Fp2MulSpec::CODE => {
                        collect_ecall!(Fp2MulInstruction<E, Bn254BaseField>, bn254_fp2_mul_config)
                    }
                    Secp256k1AddSpec::CODE => collect_ecall!(
                        WeierstrassAddAssignInstruction<E, SwCurve<Secp256k1>>,
                        secp256k1_add_config
                    ),
                    Secp256k1DoubleSpec::CODE => collect_ecall!(
                        WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256k1>>,
                        secp256k1_double_config
                    ),
                    Secp256k1ScalarInvertSpec::CODE => {
                        collect_ecall!(Secp256k1InvInstruction<E>, secp256k1_scalar_invert)
                    }
                    Secp256k1DecompressSpec::CODE => collect_ecall!(
                        WeierstrassDecompressInstruction<E, SwCurve<Secp256k1>>,
                        secp256k1_decompress_config
                    ),
                    Secp256r1AddSpec::CODE => collect_ecall!(
                        WeierstrassAddAssignInstruction<E, SwCurve<Secp256r1>>,
                        secp256r1_add_config
                    ),
                    Secp256r1DoubleSpec::CODE => collect_ecall!(
                        WeierstrassDoubleAssignInstruction<E, SwCurve<Secp256r1>>,
                        secp256r1_double_config
                    ),
                    Secp256r1ScalarInvertSpec::CODE => {
                        collect_ecall!(Secp256r1InvInstruction<E>, secp256r1_scalar_invert)
                    }
                    Uint256MulSpec::CODE => {
                        collect_ecall!(Uint256MulInstruction<E>, uint256_mul_config)
                    }
                    Sha256ExtendSpec::CODE => {
                        collect_ecall!(ShaExtendInstruction<E>, sha_extend_config)
                    }
                    _ => collect_generic_ecall_shardram(shard_ctx, step),
                }
            }
            _ => {}
        }

        Ok(())
    }
}

fn is_missing_lightweight_collector(err: &ZKVMError) -> bool {
    matches!(err, ZKVMError::InvalidWitness(message) if message.contains("does not implement"))
}

fn collect_generic_ecall_shardram(shard_ctx: &mut ShardContext, step: &StepRecord) {
    let Some(rs1) = step.rs1() else {
        return;
    };
    shard_ctx.send(
        RAMType::Register,
        Platform::register_vma(Platform::reg_ecall()).into(),
        Platform::reg_ecall() as u64,
        step.cycle() + Tracer::SUBCYCLE_RS1,
        rs1.previous_cycle,
        rs1.value,
        None,
    );

    let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
    let Some(syscall) = step.syscall(&syscall_witnesses) else {
        return;
    };
    for op in &syscall.reg_ops {
        shard_ctx.send(
            RAMType::Register,
            op.addr,
            op.register_index() as u64,
            step.cycle() + Tracer::SUBCYCLE_RD,
            op.previous_cycle,
            op.value.after,
            None,
        );
    }
    for op in &syscall.mem_ops {
        shard_ctx.send(
            RAMType::Memory,
            op.addr,
            op.addr.baddr().0 as u64,
            step.cycle() + Tracer::SUBCYCLE_MEM,
            op.previous_cycle,
            op.value.after,
            Some(op.value.before),
        );
    }
}

pub struct InstructionDispatchCtx {
    insn_to_record_buffer: Vec<Option<usize>>,
    type_to_record_buffer: HashMap<TypeId, usize>,
    insn_kinds: Vec<InsnKind>,
    circuit_record_buffers: Vec<Vec<StepIndex>>,
    fallback_record_buffers: Vec<Vec<StepIndex>>,
    ecall_record_buffers: BTreeMap<u32, Vec<StepIndex>>,
}

impl InstructionDispatchCtx {
    fn new(
        record_buffer_count: usize,
        insn_to_record_buffer: Vec<Option<usize>>,
        type_to_record_buffer: HashMap<TypeId, usize>,
    ) -> Self {
        Self {
            insn_to_record_buffer,
            type_to_record_buffer,
            insn_kinds: InsnKind::iter().collect(),
            circuit_record_buffers: (0..record_buffer_count).map(|_| Vec::new()).collect(),
            fallback_record_buffers: (0..InsnKind::COUNT).map(|_| Vec::new()).collect(),
            ecall_record_buffers: BTreeMap::new(),
        }
    }

    pub fn begin_shard(&mut self) {
        self.reset_record_buffers();
    }

    #[inline(always)]
    pub fn ingest_step(&mut self, step_idx: StepIndex, step: &StepRecord) {
        let kind = step.insn.kind;
        if kind == InsnKind::ECALL {
            let code = step
                .rs1()
                .expect("ecall requires rs1 to determine syscall code")
                .value;
            self.ecall_record_buffers
                .entry(code)
                .or_default()
                .push(step_idx);
        } else if let Some(record_buffer_idx) = self.insn_to_record_buffer[kind as usize] {
            self.circuit_record_buffers[record_buffer_idx].push(step_idx);
        } else {
            self.fallback_record_buffers[kind as usize].push(step_idx);
        }
    }

    fn reset_record_buffers(&mut self) {
        for record_buffer in &mut self.circuit_record_buffers {
            record_buffer.clear();
        }
        for record_buffer in &mut self.fallback_record_buffers {
            record_buffer.clear();
        }
        for record_buffer in self.ecall_record_buffers.values_mut() {
            record_buffer.clear();
        }
    }

    fn trace_opcode_stats(&self) {
        let mut counts = self
            .insn_kinds
            .iter()
            .map(|kind| (*kind, self.count_kind(*kind)))
            .collect_vec();
        counts.sort_by_key(|(_, count)| Reverse(*count));
        for (kind, count) in counts {
            tracing::debug!("tracer generated {:?} {} records", kind, count);
        }
    }

    fn count_kind(&self, kind: InsnKind) -> usize {
        if kind == InsnKind::ECALL {
            return self
                .ecall_record_buffers
                .values()
                .map(|record_buffer| record_buffer.len())
                .sum();
        }
        if let Some(idx) = self.insn_to_record_buffer[kind as usize] {
            self.circuit_record_buffers[idx].len()
        } else {
            self.fallback_record_buffers[kind as usize].len()
        }
    }

    fn count_ecall_code(&self, code: u32) -> usize {
        self.ecall_record_buffers
            .get(&code)
            .map(|record_buffer| record_buffer.len())
            .unwrap_or_default()
    }

    fn records_for_kinds<E: ExtensionField, I: Instruction<E> + 'static>(
        &self,
    ) -> Option<&[StepIndex]> {
        let record_buffer_id = self
            .type_to_record_buffer
            .get(&TypeId::of::<I>())
            .expect("un-registered instruction circuit");
        self.circuit_record_buffers
            .get(*record_buffer_id)
            .map(|records| records.as_slice())
    }

    fn records_for_ecall_code(&self, code: u32) -> Option<&[StepIndex]> {
        self.ecall_record_buffers
            .get(&code)
            .map(|records| records.as_slice())
    }
}
/// Fake version of what is missing in Rv32imConfig, for some tests.
pub struct DummyExtraConfig<E: ExtensionField> {
    phantom_log_pc_cycle: <LargeEcallDummy<E, LogPcCycleSpec> as Instruction<E>>::InstructionConfig,
}

impl<E: ExtensionField> DummyExtraConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let phantom_log_pc_cycle =
            cs.register_opcode_circuit::<LargeEcallDummy<E, LogPcCycleSpec>>();

        Self {
            phantom_log_pc_cycle,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
    ) {
        fixed.register_opcode_circuit::<LargeEcallDummy<E, LogPcCycleSpec>>(
            cs,
            &self.phantom_log_pc_cycle,
        );
    }

    pub fn assign_opcode_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        shard_ctx: &mut ShardContext,
        instrunction_dispatch_ctx: &InstructionDispatchCtx,
        shard_steps: &[StepRecord],
        witness: &mut ZKVMWitnesses<E>,
    ) -> Result<(), ZKVMError> {
        let phantom_log_pc_cycle_records = instrunction_dispatch_ctx
            .records_for_ecall_code(LogPcCycleSpec::CODE)
            .unwrap_or(&[]);
        let n = phantom_log_pc_cycle_records.len();
        info_span!("assign_chip", chip = %LargeEcallDummy::<E, LogPcCycleSpec>::name(), n)
            .in_scope(|| {
                witness.assign_opcode_circuit::<LargeEcallDummy<E, LogPcCycleSpec>>(
                    cs,
                    shard_ctx,
                    &self.phantom_log_pc_cycle,
                    shard_steps,
                    phantom_log_pc_cycle_records,
                )
            })?;
        Ok(())
    }
}

impl<E: ExtensionField> Rv32imConfig<E> {
    #[inline(always)]
    pub fn cells_for(&self, kind: InsnKind, rs1_value: Option<Word>) -> u64 {
        if !matches!(kind, InsnKind::ECALL) {
            return self.inst_cells_map[kind as usize];
        }

        // deal with ecall logic
        let code = rs1_value.unwrap_or_default();
        match code {
            // ecall / halt
            ECALL_HALT => *self
                .ecall_cells_map
                .get(&HaltInstruction::<E>::name())
                .expect("unable to find name"),
            ECALL_PUB_IO_COMMIT => *self
                .ecall_cells_map
                .get(&PubIoCommitInstruction::<E>::name())
                .expect("unable to find name"),
            STATE_CONTINUATION => *self
                .ecall_cells_map
                .get(&GlobalState::<E>::name())
                .expect("unable to find name"),
            KeccakSpec::CODE => *self
                .ecall_cells_map
                .get(&KeccakCoreInstruction::<E>::name())
                .expect("unable to find name"),
            KeccakXorinSpec::CODE => *self
                .ecall_cells_map
                .get(&KeccakXorinInstruction::<E>::name())
                .expect("unable to find name"),
            Bn254AddSpec::CODE => *self
                .ecall_cells_map
                .get(&WeierstrassAddAssignInstruction::<E, SwCurve<Bn254>>::name())
                .expect("unable to find name"),
            Bn254DoubleSpec::CODE => *self
                .ecall_cells_map
                .get(&WeierstrassDoubleAssignInstruction::<E, SwCurve<Bn254>>::name())
                .expect("unable to find name"),
            Bn254FpAddSpec::CODE => *self
                .ecall_cells_map
                .get(&FpAddInstruction::<E, Bn254BaseField>::name())
                .expect("unable to find name"),
            Bn254FpMulSpec::CODE => *self
                .ecall_cells_map
                .get(&FpMulInstruction::<E, Bn254BaseField>::name())
                .expect("unable to find name"),
            Bn254Fp2AddSpec::CODE => *self
                .ecall_cells_map
                .get(&Fp2AddInstruction::<E, Bn254BaseField>::name())
                .expect("unable to find name"),
            Bn254Fp2MulSpec::CODE => *self
                .ecall_cells_map
                .get(&Fp2MulInstruction::<E, Bn254BaseField>::name())
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
            Sha256ExtendSpec::CODE => *self
                .ecall_cells_map
                .get(&ShaExtendInstruction::<E>::name())
                .expect("unable to find name"),
            // phantom
            LogPcCycleSpec::CODE => 0,
            _ => panic!("unknown ecall code {code:#x}"),
        }
    }
}

impl<E: ExtensionField> StepCellExtractor for &Rv32imConfig<E> {
    #[inline(always)]
    fn cells_for_kind(&self, kind: InsnKind, rs1_value: Option<Word>) -> u64 {
        self.cells_for(kind, rs1_value)
    }

    fn shard_cost_model(&self) -> Option<Arc<ShardCostModel>> {
        Some(self.shard_cost_model.clone())
    }
}

impl<E: ExtensionField> StepCellExtractor for Rv32imConfig<E> {
    #[inline(always)]
    fn cells_for_kind(&self, kind: InsnKind, rs1_value: Option<Word>) -> u64 {
        self.cells_for(kind, rs1_value)
    }

    fn shard_cost_model(&self) -> Option<Arc<ShardCostModel>> {
        Some(self.shard_cost_model.clone())
    }
}
