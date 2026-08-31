use super::{
    arith::AddInstruction, branch::BltuInstruction, ecall::HaltInstruction, jump::JalInstruction,
    memory::LwInstruction,
};
#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::auipc::AuipcInstruction;
#[cfg(not(feature = "llama-tiny"))]
use crate::instructions::riscv::ecall::{
    TensorProductionAttentionAnchorInstruction, TensorProductionBoundaryContextInstruction,
    TensorProductionBoundaryKInstruction, TensorProductionBoundaryQInstruction,
    TensorProductionBoundaryVInstruction, TensorProductionExportAnchorInstruction,
    TensorProductionImportAnchorInstruction, TensorProductionPvCoreInstruction,
    TensorProductionQkCoreInstruction, TensorProductionSoftmaxCoreInstruction,
    collect_production_boundary_replay_descriptors,
};
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
                ShaExtendInstruction, TensorAttentionBlockReducedCoreInstruction,
                TensorAttentionBlockReducedEcallInstruction, TensorAttentionReducedCoreInstruction,
                TensorAttentionReducedEcallInstruction, TensorBusExportEndEcallInstruction,
                TensorBusHandleAttentionEcallInstruction, TensorBusHandleFfnEcallInstruction,
                TensorBusImportBeginEcallInstruction, TensorFfnBlockReducedCoreInstruction,
                TensorFfnBlockReducedEcallInstruction, TensorMatMulCoreInstruction,
                TensorMatMulEcallInstruction, TensorMatMulGate5SmallHiddenEcallInstruction,
                TensorMatMulGate5SmallHiddenFinalizeInstruction,
                TensorMatMulHiddenEcallInstruction, TensorMatMulHiddenFinalizeInstruction,
                TensorMatMulIntermediateEcallInstruction,
                TensorMatMulIntermediateFinalizeInstruction, TensorProductionTileInstruction,
                TensorProductionTileK64Instruction, TensorRmsLookupCoreInstruction,
                TensorRmsLookupEcallInstruction, Uint256MulInstruction,
                WeierstrassAddAssignInstruction, WeierstrassDecompressInstruction,
                WeierstrassDoubleAssignInstruction,
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
    ShardCostModel, StepCellExtractor, StepIndex, StepRecord, SyscallSpec,
    TensorAttentionBlockReducedV1Spec, TensorAttentionReducedV1Spec, TensorExportEndV1Spec,
    TensorFfnBlockReducedV1Spec, TensorHandleAttentionV1Spec, TensorHandleFfnV1Spec,
    TensorImportBeginV1Spec, TensorMatMulV1Spec, TensorRmsLookupV1Spec, Uint256MulSpec, Word,
};
#[cfg(not(feature = "llama-tiny"))]
use ceno_emul::{
    TensorProductionAttentionV2Spec, TensorProductionExportEndV2Spec,
    TensorProductionImportBeginV2Spec,
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

#[cfg(feature = "llama-tiny")]
use crate::instructions::riscv::ecall::{
    LlamaTinyMatMulBridgeCore, LlamaTinyResidualCore, LlamaTinyRmsArithmeticCore,
    LlamaTinyRmsLookupCore, LlamaTinyRoPECore, LlamaTinySoftmaxArithmeticCore,
    LlamaTinySoftmaxExp3Core, LlamaTinySoftmaxExp4Core, LlamaTinySoftmaxLowDigitCore,
    LlamaTinySwiGluArithmeticCore, LlamaTinySwiGluLookupCore,
    TensorBatchedMatMul2x2EcallInstruction, TensorBatchedMatMulCoreInstruction,
    TensorHintRefCoreInstruction,
    tensor_llama_tiny::{audit_layer_graph, collect_layer_sections},
};
#[cfg(feature = "llama-tiny")]
use crate::tables::{
    RmsInvTableCircuit, SoftmaxExp3TableCircuit, SoftmaxExp4TableCircuit, SwiGluTableCircuit,
};
#[cfg(feature = "llama-tiny")]
use ceno_emul::TensorBatchedMatMul2x2V1Spec;

#[cfg(feature = "gpu")]
macro_rules! for_each_fused_opcode {
    ($m:ident) => {
        $m!(AddInstruction<E>, add_config, K::Add);
        $m!(SubInstruction<E>, sub_config, K::Sub);
        $m!(AndInstruction<E>, and_config, K::LogicR(0));
        $m!(OrInstruction<E>, or_config, K::LogicR(1));
        $m!(XorInstruction<E>, xor_config, K::LogicR(2));
        $m!(SllInstruction<E>, sll_config, K::ShiftR(0));
        $m!(SrlInstruction<E>, srl_config, K::ShiftR(1));
        $m!(SraInstruction<E>, sra_config, K::ShiftR(2));
        $m!(SltInstruction<E>, slt_config, K::Slt(1));
        $m!(SltuInstruction<E>, sltu_config, K::Slt(0));
        $m!(MulInstruction<E>, mul_config, K::Mul(0));
        $m!(MulhInstruction<E>, mulh_config, K::Mul(1));
        $m!(MulhsuInstruction<E>, mulhsu_config, K::Mul(3));
        $m!(MulhuInstruction<E>, mulhu_config, K::Mul(2));
        $m!(DivuInstruction<E>, divu_config, K::Div(1));
        $m!(RemuInstruction<E>, remu_config, K::Div(3));
        $m!(DivInstruction<E>, div_config, K::Div(0));
        $m!(RemInstruction<E>, rem_config, K::Div(2));
        $m!(AddiInstruction<E>, addi_config, K::Addi);
        $m!(AndiInstruction<E>, andi_config, K::LogicI(0));
        $m!(OriInstruction<E>, ori_config, K::LogicI(1));
        $m!(XoriInstruction<E>, xori_config, K::LogicI(2));
        $m!(SlliInstruction<E>, slli_config, K::ShiftI(0));
        $m!(SrliInstruction<E>, srli_config, K::ShiftI(1));
        $m!(SraiInstruction<E>, srai_config, K::ShiftI(2));
        $m!(SltiInstruction<E>, slti_config, K::Slti(1));
        $m!(SltiuInstruction<E>, sltiu_config, K::Slti(0));
        #[cfg(feature = "u16limb_circuit")]
        $m!(LuiInstruction<E>, lui_config, K::Lui);
        #[cfg(feature = "u16limb_circuit")]
        $m!(AuipcInstruction<E>, auipc_config, K::Auipc);
        $m!(BeqInstruction<E>, beq_config, K::BranchEq(1));
        $m!(BneInstruction<E>, bne_config, K::BranchEq(0));
        $m!(BltInstruction<E>, blt_config, K::BranchCmp(1));
        $m!(BltuInstruction<E>, bltu_config, K::BranchCmp(0));
        $m!(BgeInstruction<E>, bge_config, K::BranchCmp(1));
        $m!(BgeuInstruction<E>, bgeu_config, K::BranchCmp(0));
        $m!(JalInstruction<E>, jal_config, K::Jal);
        $m!(JalrInstruction<E>, jalr_config, K::Jalr);
        $m!(LwInstruction<E>, lw_config, K::Lw);
        $m!(
            LbInstruction<E>,
            lb_config,
            K::LoadSub {
                load_width: 8,
                is_signed: 1
            }
        );
        $m!(
            LbuInstruction<E>,
            lbu_config,
            K::LoadSub {
                load_width: 8,
                is_signed: 0
            }
        );
        $m!(
            LhInstruction<E>,
            lh_config,
            K::LoadSub {
                load_width: 16,
                is_signed: 1
            }
        );
        $m!(
            LhuInstruction<E>,
            lhu_config,
            K::LoadSub {
                load_width: 16,
                is_signed: 0
            }
        );
        $m!(SwInstruction<E>, sw_config, K::Sw);
        $m!(ShInstruction<E>, sh_config, K::Sh);
        $m!(SbInstruction<E>, sb_config, K::Sb);
    };
}

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
    /// TensorBus ABI circuits use the feature-selected fixed transfer width.
    pub tensor_bus_import_config:
        <TensorBusImportBeginEcallInstruction<E> as Instruction<E>>::InstructionConfig,
    pub tensor_bus_export_config:
        <TensorBusExportEndEcallInstruction<E> as Instruction<E>>::InstructionConfig,
    pub tensor_bus_handle_attention_config:
        <TensorBusHandleAttentionEcallInstruction<E> as Instruction<E>>::InstructionConfig,
    pub tensor_bus_handle_ffn_config:
        <TensorBusHandleFfnEcallInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_import_anchor_config:
        <TensorProductionImportAnchorInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_attention_anchor_config:
        <TensorProductionAttentionAnchorInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_export_anchor_config:
        <TensorProductionExportAnchorInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_boundary_q_config:
        <TensorProductionBoundaryQInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_boundary_k_config:
        <TensorProductionBoundaryKInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_boundary_v_config:
        <TensorProductionBoundaryVInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_boundary_context_config:
        <TensorProductionBoundaryContextInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_qk_configs: [
        <TensorProductionQkCoreInstruction<E, 0> as Instruction<E>>::InstructionConfig;
        8
    ],
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_softmax_configs: [
        <TensorProductionSoftmaxCoreInstruction<E, 0> as Instruction<E>>::InstructionConfig;
        8
    ],
    #[cfg(not(feature = "llama-tiny"))]
    pub tensor_production_pv_configs: [
        <TensorProductionPvCoreInstruction<E, 0> as Instruction<E>>::InstructionConfig;
        8
    ],
    // These are optional only in the compile-time Llama-tiny Tensor profile.
    // Keeping the inactive pairs out of construction matters: their fixed
    // domains dominate setup even though the selected guest cannot call them.
    pub tensor_matmul_ecall_config:
        Option<<TensorMatMulEcallInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_matmul_core_config:
        Option<<TensorMatMulCoreInstruction<E> as Instruction<E>>::InstructionConfig>,
    #[cfg(feature = "llama-tiny")]
    pub tensor_batched_matmul_ecall_config:
        <TensorBatchedMatMul2x2EcallInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub tensor_batched_matmul_core_config:
        <TensorBatchedMatMulCoreInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub tensor_hint_ref_core_config:
        <TensorHintRefCoreInstruction<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_rms_arithmetic_config:
        <LlamaTinyRmsArithmeticCore<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_rms_lookup_config:
        <LlamaTinyRmsLookupCore<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_matmul_bridge_config:
        <LlamaTinyMatMulBridgeCore<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_rope_config: <LlamaTinyRoPECore<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_softmax_arithmetic_config:
        <LlamaTinySoftmaxArithmeticCore<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_softmax_low_digit_config:
        <LlamaTinySoftmaxLowDigitCore<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_softmax_exp3_config:
        <LlamaTinySoftmaxExp3Core<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_softmax_exp4_config:
        <LlamaTinySoftmaxExp4Core<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_residual_config:
        <LlamaTinyResidualCore<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_swiglu_lookup_config:
        <LlamaTinySwiGluLookupCore<E> as Instruction<E>>::InstructionConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_tiny_swiglu_arithmetic_config:
        <LlamaTinySwiGluArithmeticCore<E> as Instruction<E>>::InstructionConfig,
    pub tensor_hidden_ecall_config:
        Option<<TensorMatMulHiddenEcallInstruction<E> as Instruction<E>>::InstructionConfig>,
    /// The production K1024 tile circuit is deliberately absent from
    /// `llama-tiny`, whose fixed topology uses only reduced attention and FFN
    /// blocks.
    pub tensor_production_tile_config:
        Option<<TensorProductionTileInstruction<E> as Instruction<E>>::InstructionConfig>,
    /// Reserved for the compact K64 physical tile profile. The production K1024
    /// tile remains the default.
    pub tensor_gate5_small_hidden_tile_config:
        Option<<TensorProductionTileK64Instruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_hidden_finalize_config:
        Option<<TensorMatMulHiddenFinalizeInstruction<E> as Instruction<E>>::InstructionConfig>,
    /// Reserved for the compact K64 production topology.
    pub tensor_gate5_small_hidden_ecall_config: Option<<TensorMatMulGate5SmallHiddenEcallInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_gate5_small_hidden_finalize_config: Option<<TensorMatMulGate5SmallHiddenFinalizeInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_intermediate_ecall_config: Option<<TensorMatMulIntermediateEcallInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_intermediate_finalize_config: Option<<TensorMatMulIntermediateFinalizeInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_rms_ecall_config:
        Option<<TensorRmsLookupEcallInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_rms_core_config:
        Option<<TensorRmsLookupCoreInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_attention_ecall_config:
        Option<<TensorAttentionReducedEcallInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_attention_core_config:
        Option<<TensorAttentionReducedCoreInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_attention_block_ecall_config:
        <TensorAttentionBlockReducedEcallInstruction<E> as Instruction<E>>::InstructionConfig,
    pub tensor_attention_block_core_config:
        <TensorAttentionBlockReducedCoreInstruction<E> as Instruction<E>>::InstructionConfig,
    pub tensor_ffn_block_ecall_config:
        Option<<TensorFfnBlockReducedEcallInstruction<E> as Instruction<E>>::InstructionConfig>,
    pub tensor_ffn_block_core_config:
        Option<<TensorFfnBlockReducedCoreInstruction<E> as Instruction<E>>::InstructionConfig>,
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
    #[cfg(feature = "llama-tiny")]
    pub llama_softmax_exp3_config: <SoftmaxExp3TableCircuit<E> as TableCircuit<E>>::TableConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_softmax_exp4_config: <SoftmaxExp4TableCircuit<E> as TableCircuit<E>>::TableConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_rms_inv_config: <RmsInvTableCircuit<E> as TableCircuit<E>>::TableConfig,
    #[cfg(feature = "llama-tiny")]
    pub llama_swiglu_config: <SwiGluTableCircuit<E> as TableCircuit<E>>::TableConfig,
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
        // `llama-tiny` is a deterministic compile-time registry for the
        // reduced 32-layer topology. Runtime environment variables remain
        // diagnostic-only and cannot change the circuit registry.
        let minimal_tensor_e2e_registry = cfg!(feature = "llama-tiny");
        let minimal_tensor_e2e_needs_ffn = minimal_tensor_e2e_registry;
        let minimal_tensor_e2e_needs_matmul = false;
        let minimal_tensor_e2e_needs_rms = false;
        let minimal_tensor_e2e_needs_attention_reduced = false;
        let minimal_tensor_e2e_needs_hidden = false;
        let minimal_tensor_e2e_needs_small_hidden = false;
        if minimal_tensor_e2e_registry {
            tracing::info!(
                profile = "llama-tiny",
                retained = "TensorAttentionBlockReducedEcall,TensorAttentionBlockReducedCore,TensorFfnBlockReducedEcall,TensorFfnBlockReducedCore",
                omitted =
                    "TensorMatMul*,TensorRmsLookup*,TensorAttentionReduced*,TensorProductionTile*",
                "Llama-tiny tensor registry enabled"
            );
        }

        // Symbolic circuit construction has no registry side effects.  Build
        // independent Tensor artifacts concurrently, but insert them below in
        // the unchanged source order so circuit IDs and fixed-trace ordering
        // remain deterministic.
        #[cfg(feature = "parallel")]
        let (
            (tensor_bus_import_artifact, tensor_bus_export_artifact),
            (tensor_bus_handle_attention_artifact, tensor_bus_handle_ffn_artifact),
        ) = rayon::join(
            || {
                rayon::join(
                    || cs.build_opcode_circuit::<TensorBusImportBeginEcallInstruction<E>>(),
                    || cs.build_opcode_circuit::<TensorBusExportEndEcallInstruction<E>>(),
                )
            },
            || {
                rayon::join(
                    || cs.build_opcode_circuit::<TensorBusHandleAttentionEcallInstruction<E>>(),
                    || cs.build_opcode_circuit::<TensorBusHandleFfnEcallInstruction<E>>(),
                )
            },
        );
        #[cfg(all(feature = "parallel", not(feature = "llama-tiny")))]
        let (
            (tensor_hidden_ecall_artifact, tensor_production_tile_artifact),
            (tensor_hidden_finalize_artifact, tensor_intermediate_ecall_artifact),
        ) = rayon::join(
            || {
                rayon::join(
                    || cs.build_opcode_circuit::<TensorMatMulHiddenEcallInstruction<E>>(),
                    || cs.build_opcode_circuit::<TensorProductionTileInstruction<E>>(),
                )
            },
            || {
                rayon::join(
                    || cs.build_opcode_circuit::<TensorMatMulHiddenFinalizeInstruction<E>>(),
                    || cs.build_opcode_circuit::<TensorMatMulIntermediateEcallInstruction<E>>(),
                )
            },
        );
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
        let tensor_bus_import_config = {
            #[cfg(feature = "parallel")]
            let config = cs
                .register_opcode_circuit_artifact::<TensorBusImportBeginEcallInstruction<E>>(
                    tensor_bus_import_artifact,
                );
            #[cfg(not(feature = "parallel"))]
            let config = cs.register_opcode_circuit::<TensorBusImportBeginEcallInstruction<E>>();
            let circuit_cs = cs.get_cs(&TensorBusImportBeginEcallInstruction::<E>::name());
            assert!(
                ecall_cells_map
                    .insert(
                        TensorBusImportBeginEcallInstruction::<E>::name(),
                        circuit_cs
                            .map(|c| (c.zkvm_v1_css.num_witin as u64
                                + c.zkvm_v1_css.num_structural_witin as u64
                                + c.zkvm_v1_css.num_fixed as u64)
                                * (1 << c.rotation_vars().unwrap_or(0)))
                            .unwrap_or_default()
                    )
                    .is_none()
            );
            let chip = chip_specs.len();
            chip_specs.push(circuit_cs.map_or(
                ChipCostSpec {
                    rotation: 0,
                    trace_cells_per_row: 0,
                    tower_peak_cells_per_row: 0,
                    tower_peak_cells_by_bucket: None,
                },
                chip_cost_spec,
            ));
            ecall_name_to_chips.insert(
                TensorBusImportBeginEcallInstruction::<E>::name(),
                vec![chip],
            );
            config
        };
        let tensor_bus_export_config = {
            #[cfg(feature = "parallel")]
            let config = cs
                .register_opcode_circuit_artifact::<TensorBusExportEndEcallInstruction<E>>(
                    tensor_bus_export_artifact,
                );
            #[cfg(not(feature = "parallel"))]
            let config = cs.register_opcode_circuit::<TensorBusExportEndEcallInstruction<E>>();
            let circuit_cs = cs.get_cs(&TensorBusExportEndEcallInstruction::<E>::name());
            assert!(
                ecall_cells_map
                    .insert(
                        TensorBusExportEndEcallInstruction::<E>::name(),
                        circuit_cs
                            .map(|c| (c.zkvm_v1_css.num_witin as u64
                                + c.zkvm_v1_css.num_structural_witin as u64
                                + c.zkvm_v1_css.num_fixed as u64)
                                * (1 << c.rotation_vars().unwrap_or(0)))
                            .unwrap_or_default()
                    )
                    .is_none()
            );
            let chip = chip_specs.len();
            chip_specs.push(circuit_cs.map_or(
                ChipCostSpec {
                    rotation: 0,
                    trace_cells_per_row: 0,
                    tower_peak_cells_per_row: 0,
                    tower_peak_cells_by_bucket: None,
                },
                chip_cost_spec,
            ));
            ecall_name_to_chips.insert(TensorBusExportEndEcallInstruction::<E>::name(), vec![chip]);
            config
        };
        let tensor_bus_handle_attention_config = {
            #[cfg(feature = "parallel")]
            let config = cs
                .register_opcode_circuit_artifact::<TensorBusHandleAttentionEcallInstruction<E>>(
                    tensor_bus_handle_attention_artifact,
                );
            #[cfg(not(feature = "parallel"))]
            let config =
                cs.register_opcode_circuit::<TensorBusHandleAttentionEcallInstruction<E>>();
            let circuit_cs = cs.get_cs(&TensorBusHandleAttentionEcallInstruction::<E>::name());
            assert!(
                ecall_cells_map
                    .insert(
                        TensorBusHandleAttentionEcallInstruction::<E>::name(),
                        circuit_cs
                            .map(|c| (c.zkvm_v1_css.num_witin as u64
                                + c.zkvm_v1_css.num_structural_witin as u64
                                + c.zkvm_v1_css.num_fixed as u64)
                                * (1 << c.rotation_vars().unwrap_or(0)))
                            .unwrap_or_default()
                    )
                    .is_none()
            );
            let chip = chip_specs.len();
            chip_specs.push(circuit_cs.map_or(
                ChipCostSpec {
                    rotation: 0,
                    trace_cells_per_row: 0,
                    tower_peak_cells_per_row: 0,
                    tower_peak_cells_by_bucket: None,
                },
                chip_cost_spec,
            ));
            ecall_name_to_chips.insert(
                TensorBusHandleAttentionEcallInstruction::<E>::name(),
                vec![chip],
            );
            config
        };
        let tensor_bus_handle_ffn_config = {
            #[cfg(feature = "parallel")]
            let config = cs
                .register_opcode_circuit_artifact::<TensorBusHandleFfnEcallInstruction<E>>(
                    tensor_bus_handle_ffn_artifact,
                );
            #[cfg(not(feature = "parallel"))]
            let config = cs.register_opcode_circuit::<TensorBusHandleFfnEcallInstruction<E>>();
            let circuit_cs = cs.get_cs(&TensorBusHandleFfnEcallInstruction::<E>::name());
            assert!(
                ecall_cells_map
                    .insert(
                        TensorBusHandleFfnEcallInstruction::<E>::name(),
                        circuit_cs
                            .map(|c| (c.zkvm_v1_css.num_witin as u64
                                + c.zkvm_v1_css.num_structural_witin as u64
                                + c.zkvm_v1_css.num_fixed as u64)
                                * (1 << c.rotation_vars().unwrap_or(0)))
                            .unwrap_or_default()
                    )
                    .is_none()
            );
            let chip = chip_specs.len();
            chip_specs.push(circuit_cs.map_or(
                ChipCostSpec {
                    rotation: 0,
                    trace_cells_per_row: 0,
                    tower_peak_cells_per_row: 0,
                    tower_peak_cells_by_bucket: None,
                },
                chip_cost_spec,
            ));
            ecall_name_to_chips.insert(TensorBusHandleFfnEcallInstruction::<E>::name(), vec![chip]);
            config
        };

        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_import_anchor_config =
            register_ecall_circuit!(TensorProductionImportAnchorInstruction<E>, ecall_cells_map);
        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_attention_anchor_config = register_ecall_circuit!(
            TensorProductionAttentionAnchorInstruction<E>,
            ecall_cells_map
        );
        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_export_anchor_config =
            register_ecall_circuit!(TensorProductionExportAnchorInstruction<E>, ecall_cells_map);
        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_boundary_q_config =
            cs.register_opcode_circuit::<TensorProductionBoundaryQInstruction<E>>();
        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_boundary_k_config =
            cs.register_opcode_circuit::<TensorProductionBoundaryKInstruction<E>>();
        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_boundary_v_config =
            cs.register_opcode_circuit::<TensorProductionBoundaryVInstruction<E>>();
        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_boundary_context_config =
            cs.register_opcode_circuit::<TensorProductionBoundaryContextInstruction<E>>();
        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_qk_configs = [
            cs.register_opcode_circuit::<TensorProductionQkCoreInstruction<E, 0>>(),
            cs.register_opcode_circuit::<TensorProductionQkCoreInstruction<E, 1>>(),
            cs.register_opcode_circuit::<TensorProductionQkCoreInstruction<E, 2>>(),
            cs.register_opcode_circuit::<TensorProductionQkCoreInstruction<E, 3>>(),
            cs.register_opcode_circuit::<TensorProductionQkCoreInstruction<E, 4>>(),
            cs.register_opcode_circuit::<TensorProductionQkCoreInstruction<E, 5>>(),
            cs.register_opcode_circuit::<TensorProductionQkCoreInstruction<E, 6>>(),
            cs.register_opcode_circuit::<TensorProductionQkCoreInstruction<E, 7>>(),
        ];
        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_softmax_configs = [
            cs.register_opcode_circuit::<TensorProductionSoftmaxCoreInstruction<E, 0>>(),
            cs.register_opcode_circuit::<TensorProductionSoftmaxCoreInstruction<E, 1>>(),
            cs.register_opcode_circuit::<TensorProductionSoftmaxCoreInstruction<E, 2>>(),
            cs.register_opcode_circuit::<TensorProductionSoftmaxCoreInstruction<E, 3>>(),
            cs.register_opcode_circuit::<TensorProductionSoftmaxCoreInstruction<E, 4>>(),
            cs.register_opcode_circuit::<TensorProductionSoftmaxCoreInstruction<E, 5>>(),
            cs.register_opcode_circuit::<TensorProductionSoftmaxCoreInstruction<E, 6>>(),
            cs.register_opcode_circuit::<TensorProductionSoftmaxCoreInstruction<E, 7>>(),
        ];
        #[cfg(not(feature = "llama-tiny"))]
        let tensor_production_pv_configs = [
            cs.register_opcode_circuit::<TensorProductionPvCoreInstruction<E, 0>>(),
            cs.register_opcode_circuit::<TensorProductionPvCoreInstruction<E, 1>>(),
            cs.register_opcode_circuit::<TensorProductionPvCoreInstruction<E, 2>>(),
            cs.register_opcode_circuit::<TensorProductionPvCoreInstruction<E, 3>>(),
            cs.register_opcode_circuit::<TensorProductionPvCoreInstruction<E, 4>>(),
            cs.register_opcode_circuit::<TensorProductionPvCoreInstruction<E, 5>>(),
            cs.register_opcode_circuit::<TensorProductionPvCoreInstruction<E, 6>>(),
            cs.register_opcode_circuit::<TensorProductionPvCoreInstruction<E, 7>>(),
        ];
        #[cfg(not(feature = "llama-tiny"))]
        for (anchor, boundary) in [
            (
                TensorProductionImportAnchorInstruction::<E>::name(),
                TensorProductionBoundaryQInstruction::<E>::name(),
            ),
            (
                TensorProductionImportAnchorInstruction::<E>::name(),
                TensorProductionBoundaryKInstruction::<E>::name(),
            ),
            (
                TensorProductionImportAnchorInstruction::<E>::name(),
                TensorProductionBoundaryVInstruction::<E>::name(),
            ),
            (
                TensorProductionExportAnchorInstruction::<E>::name(),
                TensorProductionBoundaryContextInstruction::<E>::name(),
            ),
        ] {
            let boundary_cs = cs
                .get_cs(&boundary)
                .expect("production boundary circuit missing");
            let chip = chip_specs.len();
            chip_specs.push(chip_cost_spec(boundary_cs));
            ecall_name_to_chips
                .get_mut(&anchor)
                .expect("production anchor cost entry missing")
                .push(chip);
            let boundary_cells = (boundary_cs.zkvm_v1_css.num_witin as u64
                + boundary_cs.zkvm_v1_css.num_structural_witin as u64
                + boundary_cs.zkvm_v1_css.num_fixed as u64)
                * (1 << boundary_cs.rotation_vars().unwrap_or(0));
            *ecall_cells_map
                .get_mut(&anchor)
                .expect("production anchor cell entry missing") += boundary_cells;
        }
        #[cfg(not(feature = "llama-tiny"))]
        for name in [
            TensorProductionQkCoreInstruction::<E, 0>::name(),
            TensorProductionQkCoreInstruction::<E, 1>::name(),
            TensorProductionQkCoreInstruction::<E, 2>::name(),
            TensorProductionQkCoreInstruction::<E, 3>::name(),
            TensorProductionQkCoreInstruction::<E, 4>::name(),
            TensorProductionQkCoreInstruction::<E, 5>::name(),
            TensorProductionQkCoreInstruction::<E, 6>::name(),
            TensorProductionQkCoreInstruction::<E, 7>::name(),
            TensorProductionSoftmaxCoreInstruction::<E, 0>::name(),
            TensorProductionSoftmaxCoreInstruction::<E, 1>::name(),
            TensorProductionSoftmaxCoreInstruction::<E, 2>::name(),
            TensorProductionSoftmaxCoreInstruction::<E, 3>::name(),
            TensorProductionSoftmaxCoreInstruction::<E, 4>::name(),
            TensorProductionSoftmaxCoreInstruction::<E, 5>::name(),
            TensorProductionSoftmaxCoreInstruction::<E, 6>::name(),
            TensorProductionSoftmaxCoreInstruction::<E, 7>::name(),
            TensorProductionPvCoreInstruction::<E, 0>::name(),
            TensorProductionPvCoreInstruction::<E, 1>::name(),
            TensorProductionPvCoreInstruction::<E, 2>::name(),
            TensorProductionPvCoreInstruction::<E, 3>::name(),
            TensorProductionPvCoreInstruction::<E, 4>::name(),
            TensorProductionPvCoreInstruction::<E, 5>::name(),
            TensorProductionPvCoreInstruction::<E, 6>::name(),
            TensorProductionPvCoreInstruction::<E, 7>::name(),
        ] {
            let matrix_cs = cs.get_cs(&name).expect("production matrix circuit missing");
            let chip = chip_specs.len();
            chip_specs.push(chip_cost_spec(matrix_cs));
            ecall_name_to_chips
                .get_mut(&TensorProductionAttentionAnchorInstruction::<E>::name())
                .expect("production attention cost entry missing")
                .push(chip);
            let matrix_cells = (matrix_cs.zkvm_v1_css.num_witin as u64
                + matrix_cs.zkvm_v1_css.num_structural_witin as u64
                + matrix_cs.zkvm_v1_css.num_fixed as u64)
                * (1 << matrix_cs.rotation_vars().unwrap_or(0));
            *ecall_cells_map
                .get_mut(&TensorProductionAttentionAnchorInstruction::<E>::name())
                .expect("production attention cell entry missing") += matrix_cells;
        }

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
        let tensor_matmul_ecall_config = (!minimal_tensor_e2e_registry
            || minimal_tensor_e2e_needs_matmul)
            .then(|| cs.register_opcode_circuit::<TensorMatMulEcallInstruction<E>>());
        let tensor_matmul_core_config = (!minimal_tensor_e2e_registry
            || minimal_tensor_e2e_needs_matmul)
            .then(|| cs.register_opcode_circuit::<TensorMatMulCoreInstruction<E>>());
        #[cfg(feature = "llama-tiny")]
        let tensor_batched_matmul_ecall_config =
            cs.register_opcode_circuit::<TensorBatchedMatMul2x2EcallInstruction<E>>();
        #[cfg(feature = "llama-tiny")]
        let tensor_batched_matmul_core_config =
            cs.register_opcode_circuit::<TensorBatchedMatMulCoreInstruction<E>>();
        #[cfg(feature = "llama-tiny")]
        let tensor_hint_ref_core_config =
            cs.register_opcode_circuit::<TensorHintRefCoreInstruction<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_rms_arithmetic_config =
            cs.register_opcode_circuit::<LlamaTinyRmsArithmeticCore<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_rms_lookup_config =
            cs.register_opcode_circuit::<LlamaTinyRmsLookupCore<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_matmul_bridge_config =
            cs.register_opcode_circuit::<LlamaTinyMatMulBridgeCore<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_rope_config = cs.register_opcode_circuit::<LlamaTinyRoPECore<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_softmax_arithmetic_config =
            cs.register_opcode_circuit::<LlamaTinySoftmaxArithmeticCore<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_softmax_low_digit_config =
            cs.register_opcode_circuit::<LlamaTinySoftmaxLowDigitCore<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_softmax_exp3_config =
            cs.register_opcode_circuit::<LlamaTinySoftmaxExp3Core<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_softmax_exp4_config =
            cs.register_opcode_circuit::<LlamaTinySoftmaxExp4Core<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_residual_config = cs.register_opcode_circuit::<LlamaTinyResidualCore<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_swiglu_lookup_config =
            cs.register_opcode_circuit::<LlamaTinySwiGluLookupCore<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_tiny_swiglu_arithmetic_config =
            cs.register_opcode_circuit::<LlamaTinySwiGluArithmeticCore<E>>();
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_matmul {
            assert!(
                ecall_cells_map
                    .insert(
                        <TensorMatMulCoreInstruction<E>>::name(),
                        [
                            <TensorMatMulEcallInstruction<E>>::name(),
                            <TensorMatMulCoreInstruction<E>>::name()
                        ]
                        .into_iter()
                        .map(|name| cs
                            .get_cs(&name)
                            .as_ref()
                            .map(|cs| {
                                (cs.zkvm_v1_css.num_witin as u64
                                    + cs.zkvm_v1_css.num_structural_witin as u64
                                    + cs.zkvm_v1_css.num_fixed as u64)
                                    * (1 << cs.rotation_vars().unwrap_or(0))
                            })
                            .unwrap_or_default())
                        .sum(),
                    )
                    .is_none()
            );
        }
        let mut tensor_chips = Vec::new();
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_matmul {
            for name in [
                <TensorMatMulEcallInstruction<E>>::name(),
                <TensorMatMulCoreInstruction<E>>::name(),
            ] {
                let circuit_cs = cs.get_cs(&name).expect("tensor circuit missing");
                tensor_chips.push(chip_specs.len());
                chip_specs.push(chip_cost_spec(circuit_cs));
            }
            ecall_name_to_chips.insert(<TensorMatMulCoreInstruction<E>>::name(), tensor_chips);
        }
        #[cfg(feature = "llama-tiny")]
        {
            let names = [
                <TensorBatchedMatMul2x2EcallInstruction<E>>::name(),
                <TensorBatchedMatMulCoreInstruction<E>>::name(),
            ];
            assert!(
                ecall_cells_map
                    .insert(
                        <TensorBatchedMatMulCoreInstruction<E>>::name(),
                        names
                            .iter()
                            .map(|name| {
                                let c = cs.get_cs(name).expect("tiny batched MatMul circuit");
                                (c.zkvm_v1_css.num_witin as u64
                                    + c.zkvm_v1_css.num_structural_witin as u64
                                    + c.zkvm_v1_css.num_fixed as u64)
                                    * (1 << c.rotation_vars().unwrap_or(0))
                            })
                            .sum(),
                    )
                    .is_none()
            );
            let chips = names
                .iter()
                .map(|name| {
                    let circuit_cs = cs.get_cs(name).expect("tiny batched MatMul circuit");
                    let index = chip_specs.len();
                    chip_specs.push(chip_cost_spec(circuit_cs));
                    index
                })
                .collect();
            ecall_name_to_chips.insert(<TensorBatchedMatMulCoreInstruction<E>>::name(), chips);

            let hint_name = <TensorHintRefCoreInstruction<E>>::name();
            let hint_cs = cs.get_cs(&hint_name).expect("tiny HintRef circuit");
            let hint_cells = (hint_cs.zkvm_v1_css.num_witin as u64
                + hint_cs.zkvm_v1_css.num_structural_witin as u64
                + hint_cs.zkvm_v1_css.num_fixed as u64)
                * (1 << hint_cs.rotation_vars().unwrap_or(0));
            assert!(
                ecall_cells_map
                    .insert(hint_name.clone(), hint_cells)
                    .is_none()
            );
            let hint_chip = chip_specs.len();
            chip_specs.push(chip_cost_spec(hint_cs));
            ecall_name_to_chips.insert(hint_name, vec![hint_chip]);

            let matrix_name = <TensorBatchedMatMulCoreInstruction<E>>::name();
            let matrix_cs = cs.get_cs(&matrix_name).expect("tiny matrix Core circuit");
            let matrix_cells = (matrix_cs.zkvm_v1_css.num_witin as u64
                + matrix_cs.zkvm_v1_css.num_structural_witin as u64
                + matrix_cs.zkvm_v1_css.num_fixed as u64)
                * (1 << matrix_cs.rotation_vars().unwrap_or(0));
            let matrix_chip = *ecall_name_to_chips
                .get(&matrix_name)
                .and_then(|chips| chips.last())
                .expect("tiny matrix Core cost chip");
            for handle_name in [
                <TensorBusHandleAttentionEcallInstruction<E>>::name(),
                <TensorBusHandleFfnEcallInstruction<E>>::name(),
            ] {
                *ecall_cells_map
                    .get_mut(&handle_name)
                    .expect("TensorBus handle cost missing") += matrix_cells + hint_cells;
                let chips = ecall_name_to_chips
                    .get_mut(&handle_name)
                    .expect("TensorBus handle cost chips missing");
                chips.push(matrix_chip);
                chips.push(hint_chip);
            }

            let attention_family_names = [
                <LlamaTinyRmsArithmeticCore<E>>::name(),
                <LlamaTinyRmsLookupCore<E>>::name(),
                <LlamaTinyMatMulBridgeCore<E>>::name(),
                <LlamaTinyRoPECore<E>>::name(),
                <LlamaTinySoftmaxArithmeticCore<E>>::name(),
                <LlamaTinySoftmaxLowDigitCore<E>>::name(),
                <LlamaTinySoftmaxExp3Core<E>>::name(),
                <LlamaTinySoftmaxExp4Core<E>>::name(),
                <LlamaTinyResidualCore<E>>::name(),
            ];
            let ffn_family_names = [
                <LlamaTinySwiGluLookupCore<E>>::name(),
                <LlamaTinySwiGluArithmeticCore<E>>::name(),
            ];
            for (handle_name, family_names) in [
                (
                    <TensorBusHandleAttentionEcallInstruction<E>>::name(),
                    attention_family_names.as_slice(),
                ),
                (
                    <TensorBusHandleFfnEcallInstruction<E>>::name(),
                    ffn_family_names.as_slice(),
                ),
            ] {
                for family_name in family_names {
                    let family_cs = cs
                        .get_cs(family_name)
                        .expect("llama-tiny family Core circuit");
                    let family_cells = (family_cs.zkvm_v1_css.num_witin as u64
                        + family_cs.zkvm_v1_css.num_structural_witin as u64
                        + family_cs.zkvm_v1_css.num_fixed as u64)
                        * (1 << family_cs.rotation_vars().unwrap_or(0));
                    assert!(
                        ecall_cells_map
                            .insert(family_name.clone(), family_cells)
                            .is_none()
                    );
                    *ecall_cells_map
                        .get_mut(&handle_name)
                        .expect("TensorBus handle cost missing") += family_cells;
                    let chip = chip_specs.len();
                    chip_specs.push(chip_cost_spec(family_cs));
                    ecall_name_to_chips.insert(family_name.clone(), vec![chip]);
                    ecall_name_to_chips
                        .get_mut(&handle_name)
                        .expect("TensorBus handle cost chips missing")
                        .push(chip);
                }
            }
        }
        let tensor_hidden_ecall_config =
            (!minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_hidden).then(|| {
                #[cfg(all(feature = "parallel", not(feature = "llama-tiny")))]
                {
                    cs.register_opcode_circuit_artifact::<TensorMatMulHiddenEcallInstruction<E>>(
                        tensor_hidden_ecall_artifact,
                    )
                }
                #[cfg(not(all(feature = "parallel", not(feature = "llama-tiny"))))]
                {
                    cs.register_opcode_circuit::<TensorMatMulHiddenEcallInstruction<E>>()
                }
            });
        let tensor_production_tile_config =
            (!minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_hidden).then(|| {
                #[cfg(all(feature = "parallel", not(feature = "llama-tiny")))]
                {
                    cs.register_opcode_circuit_artifact::<TensorProductionTileInstruction<E>>(
                        tensor_production_tile_artifact,
                    )
                }
                #[cfg(not(all(feature = "parallel", not(feature = "llama-tiny"))))]
                {
                    cs.register_opcode_circuit::<TensorProductionTileInstruction<E>>()
                }
            });
        let tensor_gate5_small_hidden_tile_config = minimal_tensor_e2e_needs_small_hidden
            .then(|| cs.register_opcode_circuit::<TensorProductionTileK64Instruction<E>>());
        let tensor_hidden_finalize_config =
            (!minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_hidden).then(|| {
                #[cfg(all(feature = "parallel", not(feature = "llama-tiny")))]
                {
                    cs.register_opcode_circuit_artifact::<TensorMatMulHiddenFinalizeInstruction<E>>(
                        tensor_hidden_finalize_artifact,
                    )
                }
                #[cfg(not(all(feature = "parallel", not(feature = "llama-tiny"))))]
                {
                    cs.register_opcode_circuit::<TensorMatMulHiddenFinalizeInstruction<E>>()
                }
            });
        let tensor_gate5_small_hidden_ecall_config =
            minimal_tensor_e2e_needs_small_hidden.then(|| {
                cs.register_opcode_circuit::<TensorMatMulGate5SmallHiddenEcallInstruction<E>>()
            });
        let tensor_gate5_small_hidden_finalize_config =
            minimal_tensor_e2e_needs_small_hidden.then(|| {
                cs.register_opcode_circuit::<TensorMatMulGate5SmallHiddenFinalizeInstruction<E>>()
            });
        let tensor_intermediate_ecall_config = (!minimal_tensor_e2e_registry).then(|| {
            #[cfg(all(feature = "parallel", not(feature = "llama-tiny")))]
            {
                cs.register_opcode_circuit_artifact::<TensorMatMulIntermediateEcallInstruction<E>>(
                    tensor_intermediate_ecall_artifact,
                )
            }
            #[cfg(not(all(feature = "parallel", not(feature = "llama-tiny"))))]
            {
                cs.register_opcode_circuit::<TensorMatMulIntermediateEcallInstruction<E>>()
            }
        });
        let tensor_intermediate_finalize_config = (!minimal_tensor_e2e_registry).then(|| {
            cs.register_opcode_circuit::<TensorMatMulIntermediateFinalizeInstruction<E>>()
        });
        let circuit_cells = |name: &String| {
            let c = cs.get_cs(name).expect("production tensor circuit missing");
            (c.zkvm_v1_css.num_witin as u64
                + c.zkvm_v1_css.num_structural_witin as u64
                + c.zkvm_v1_css.num_fixed as u64)
                * (1 << c.rotation_vars().unwrap_or(0))
        };
        if tensor_production_tile_config.is_some() {
            let hidden_ecall_name = <TensorMatMulHiddenEcallInstruction<E>>::name();
            let production_tile_name = <TensorProductionTileInstruction<E>>::name();
            let hidden_finalize_name = <TensorMatMulHiddenFinalizeInstruction<E>>::name();
            let tensor_hidden_cells = circuit_cells(&hidden_ecall_name)
                + 4 * circuit_cells(&production_tile_name)
                + circuit_cells(&hidden_finalize_name);
            assert!(
                ecall_cells_map
                    .insert(
                        <TensorMatMulHiddenFinalizeInstruction<E>>::name(),
                        tensor_hidden_cells
                    )
                    .is_none()
            );
            let hidden_ecall_chip = chip_specs.len();
            chip_specs.push(chip_cost_spec(cs.get_cs(&hidden_ecall_name).unwrap()));
            let production_tile_chip = chip_specs.len();
            chip_specs.push(chip_cost_spec(cs.get_cs(&production_tile_name).unwrap()));
            let hidden_finalize_chip = chip_specs.len();
            chip_specs.push(chip_cost_spec(cs.get_cs(&hidden_finalize_name).unwrap()));
            let mut tensor_hidden_chips = vec![hidden_ecall_chip];
            tensor_hidden_chips.extend(std::iter::repeat_n(production_tile_chip, 4));
            tensor_hidden_chips.push(hidden_finalize_chip);
            ecall_name_to_chips.insert(
                <TensorMatMulHiddenFinalizeInstruction<E>>::name(),
                tensor_hidden_chips,
            );
            if tensor_intermediate_ecall_config.is_some() {
                let intermediate_ecall_name = <TensorMatMulIntermediateEcallInstruction<E>>::name();
                let intermediate_finalize_name =
                    <TensorMatMulIntermediateFinalizeInstruction<E>>::name();
                let tensor_intermediate_cells = circuit_cells(&intermediate_ecall_name)
                    + 11 * circuit_cells(&production_tile_name)
                    + circuit_cells(&intermediate_finalize_name);
                assert!(
                    ecall_cells_map
                        .insert(
                            <TensorMatMulIntermediateFinalizeInstruction<E>>::name(),
                            tensor_intermediate_cells
                        )
                        .is_none()
                );
                let intermediate_ecall_chip = chip_specs.len();
                chip_specs.push(chip_cost_spec(cs.get_cs(&intermediate_ecall_name).unwrap()));
                let intermediate_finalize_chip = chip_specs.len();
                chip_specs.push(chip_cost_spec(
                    cs.get_cs(&intermediate_finalize_name).unwrap(),
                ));
                let mut tensor_intermediate_chips = vec![intermediate_ecall_chip];
                tensor_intermediate_chips.extend(std::iter::repeat_n(production_tile_chip, 11));
                tensor_intermediate_chips.push(intermediate_finalize_chip);
                ecall_name_to_chips.insert(
                    <TensorMatMulIntermediateFinalizeInstruction<E>>::name(),
                    tensor_intermediate_chips,
                );
            }
        }
        if tensor_gate5_small_hidden_ecall_config.is_some() {
            let raw_name = <TensorMatMulGate5SmallHiddenEcallInstruction<E>>::name();
            let tile_name = <TensorProductionTileK64Instruction<E>>::name();
            let finalize_name = <TensorMatMulGate5SmallHiddenFinalizeInstruction<E>>::name();
            let cells = circuit_cells(&raw_name)
                + circuit_cells(&tile_name)
                + circuit_cells(&finalize_name);
            assert!(
                ecall_cells_map
                    .insert(finalize_name.clone(), cells)
                    .is_none()
            );
            let raw_chip = chip_specs.len();
            chip_specs.push(chip_cost_spec(cs.get_cs(&raw_name).unwrap()));
            let tile_chip = chip_specs.len();
            chip_specs.push(chip_cost_spec(cs.get_cs(&tile_name).unwrap()));
            let finalize_chip = chip_specs.len();
            chip_specs.push(chip_cost_spec(cs.get_cs(&finalize_name).unwrap()));
            ecall_name_to_chips.insert(finalize_name, vec![raw_chip, tile_chip, finalize_chip]);
        }
        let tensor_rms_ecall_config = (!minimal_tensor_e2e_registry
            || minimal_tensor_e2e_needs_rms)
            .then(|| cs.register_opcode_circuit::<TensorRmsLookupEcallInstruction<E>>());
        let tensor_rms_core_config = (!minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_rms)
            .then(|| cs.register_opcode_circuit::<TensorRmsLookupCoreInstruction<E>>());
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_rms {
            assert!(
                ecall_cells_map
                    .insert(
                        <TensorRmsLookupCoreInstruction<E>>::name(),
                        [
                            <TensorRmsLookupEcallInstruction<E>>::name(),
                            <TensorRmsLookupCoreInstruction<E>>::name(),
                        ]
                        .into_iter()
                        .map(|name| cs
                            .get_cs(&name)
                            .as_ref()
                            .map(|cs| {
                                (cs.zkvm_v1_css.num_witin as u64
                                    + cs.zkvm_v1_css.num_structural_witin as u64
                                    + cs.zkvm_v1_css.num_fixed as u64)
                                    * (1 << cs.rotation_vars().unwrap_or(0))
                            })
                            .unwrap_or_default())
                        .sum(),
                    )
                    .is_none()
            );
        }
        let mut tensor_rms_chips = Vec::new();
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_rms {
            for name in [
                <TensorRmsLookupEcallInstruction<E>>::name(),
                <TensorRmsLookupCoreInstruction<E>>::name(),
            ] {
                let circuit_cs = cs.get_cs(&name).expect("RMS tensor circuit missing");
                tensor_rms_chips.push(chip_specs.len());
                chip_specs.push(chip_cost_spec(circuit_cs));
            }
            ecall_name_to_chips.insert(
                <TensorRmsLookupCoreInstruction<E>>::name(),
                tensor_rms_chips,
            );
        }
        let tensor_attention_ecall_config = (!minimal_tensor_e2e_registry
            || minimal_tensor_e2e_needs_attention_reduced)
            .then(|| cs.register_opcode_circuit::<TensorAttentionReducedEcallInstruction<E>>());
        let tensor_attention_core_config = (!minimal_tensor_e2e_registry
            || minimal_tensor_e2e_needs_attention_reduced)
            .then(|| cs.register_opcode_circuit::<TensorAttentionReducedCoreInstruction<E>>());
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_attention_reduced {
            assert!(
                ecall_cells_map
                    .insert(
                        <TensorAttentionReducedCoreInstruction<E>>::name(),
                        [
                            <TensorAttentionReducedEcallInstruction<E>>::name(),
                            <TensorAttentionReducedCoreInstruction<E>>::name(),
                        ]
                        .into_iter()
                        .map(|name| cs
                            .get_cs(&name)
                            .as_ref()
                            .map(|cs| {
                                (cs.zkvm_v1_css.num_witin as u64
                                    + cs.zkvm_v1_css.num_structural_witin as u64
                                    + cs.zkvm_v1_css.num_fixed as u64)
                                    * (1 << cs.rotation_vars().unwrap_or(0))
                            })
                            .unwrap_or_default())
                        .sum(),
                    )
                    .is_none()
            );
        }
        let mut tensor_attention_chips = Vec::new();
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_attention_reduced {
            for name in [
                <TensorAttentionReducedEcallInstruction<E>>::name(),
                <TensorAttentionReducedCoreInstruction<E>>::name(),
            ] {
                let circuit_cs = cs.get_cs(&name).expect("attention tensor circuit missing");
                tensor_attention_chips.push(chip_specs.len());
                chip_specs.push(chip_cost_spec(circuit_cs));
            }
            ecall_name_to_chips.insert(
                <TensorAttentionReducedCoreInstruction<E>>::name(),
                tensor_attention_chips,
            );
        }
        // These two configs are stored non-optionally in `Rv32imConfig`.
        // Keeping them registered in every diagnostic profile avoids changing
        // normal configuration ownership; the MatMul profile still omits every
        // large production/hidden/RMS circuit and executes only MatMul.
        let tensor_attention_block_ecall_config =
            cs.register_opcode_circuit::<TensorAttentionBlockReducedEcallInstruction<E>>();
        let tensor_attention_block_core_config =
            cs.register_opcode_circuit::<TensorAttentionBlockReducedCoreInstruction<E>>();
        let tensor_ffn_block_ecall_config = (!minimal_tensor_e2e_registry
            || minimal_tensor_e2e_needs_ffn)
            .then(|| cs.register_opcode_circuit::<TensorFfnBlockReducedEcallInstruction<E>>());
        let tensor_ffn_block_core_config = (!minimal_tensor_e2e_registry
            || minimal_tensor_e2e_needs_ffn)
            .then(|| cs.register_opcode_circuit::<TensorFfnBlockReducedCoreInstruction<E>>());
        let mut register_fused_pair = |core: String, pair: [String; 2]| {
            let cells = pair
                .iter()
                .map(|name| {
                    let circuit = cs.get_cs(name).expect("fused tensor circuit missing");
                    (circuit.zkvm_v1_css.num_witin as u64
                        + circuit.zkvm_v1_css.num_structural_witin as u64
                        + circuit.zkvm_v1_css.num_fixed as u64)
                        * (1 << circuit.rotation_vars().unwrap_or(0))
                })
                .sum();
            assert!(ecall_cells_map.insert(core.clone(), cells).is_none());
            let mut chips = Vec::new();
            for name in pair {
                let circuit = cs.get_cs(&name).expect("fused tensor circuit missing");
                chips.push(chip_specs.len());
                chip_specs.push(chip_cost_spec(circuit));
            }
            ecall_name_to_chips.insert(core, chips);
        };
        register_fused_pair(
            <TensorAttentionBlockReducedCoreInstruction<E>>::name(),
            [
                <TensorAttentionBlockReducedEcallInstruction<E>>::name(),
                <TensorAttentionBlockReducedCoreInstruction<E>>::name(),
            ],
        );
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_ffn {
            register_fused_pair(
                <TensorFfnBlockReducedCoreInstruction<E>>::name(),
                [
                    <TensorFfnBlockReducedEcallInstruction<E>>::name(),
                    <TensorFfnBlockReducedCoreInstruction<E>>::name(),
                ],
            );
        }
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
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_matmul {
            map_ecall(
                TensorMatMulV1Spec::CODE,
                TensorMatMulCoreInstruction::<E>::name(),
            );
        }
        #[cfg(feature = "llama-tiny")]
        map_ecall(
            TensorBatchedMatMul2x2V1Spec::CODE,
            TensorBatchedMatMulCoreInstruction::<E>::name(),
        );
        #[cfg(feature = "llama-tiny")]
        map_ecall(
            TensorHandleAttentionV1Spec::CODE,
            TensorBusHandleAttentionEcallInstruction::<E>::name(),
        );
        #[cfg(feature = "llama-tiny")]
        map_ecall(
            TensorHandleFfnV1Spec::CODE,
            TensorBusHandleFfnEcallInstruction::<E>::name(),
        );
        #[cfg(not(feature = "llama-tiny"))]
        map_ecall(
            TensorProductionImportBeginV2Spec::CODE,
            TensorProductionImportAnchorInstruction::<E>::name(),
        );
        #[cfg(not(feature = "llama-tiny"))]
        map_ecall(
            TensorProductionAttentionV2Spec::CODE,
            TensorProductionAttentionAnchorInstruction::<E>::name(),
        );
        #[cfg(not(feature = "llama-tiny"))]
        map_ecall(
            TensorProductionExportEndV2Spec::CODE,
            TensorProductionExportAnchorInstruction::<E>::name(),
        );
        if !minimal_tensor_e2e_registry {
            map_ecall(
                ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1,
                TensorMatMulHiddenFinalizeInstruction::<E>::name(),
            );
            map_ecall(
                ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1,
                TensorMatMulIntermediateFinalizeInstruction::<E>::name(),
            );
            map_ecall(
                TensorAttentionReducedV1Spec::CODE,
                TensorAttentionReducedCoreInstruction::<E>::name(),
            );
        }
        if minimal_tensor_e2e_needs_hidden {
            map_ecall(
                ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1,
                TensorMatMulHiddenFinalizeInstruction::<E>::name(),
            );
        }
        if minimal_tensor_e2e_needs_small_hidden {
            map_ecall(
                ceno_emul::tensor::TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1,
                TensorMatMulGate5SmallHiddenFinalizeInstruction::<E>::name(),
            );
        }
        if minimal_tensor_e2e_needs_attention_reduced {
            map_ecall(
                TensorAttentionReducedV1Spec::CODE,
                TensorAttentionReducedCoreInstruction::<E>::name(),
            );
        }
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_rms {
            map_ecall(
                TensorRmsLookupV1Spec::CODE,
                TensorRmsLookupCoreInstruction::<E>::name(),
            );
        }
        map_ecall(
            TensorAttentionBlockReducedV1Spec::CODE,
            TensorAttentionBlockReducedCoreInstruction::<E>::name(),
        );
        if !minimal_tensor_e2e_registry || minimal_tensor_e2e_needs_ffn {
            map_ecall(
                TensorFfnBlockReducedV1Spec::CODE,
                TensorFfnBlockReducedCoreInstruction::<E>::name(),
            );
        }
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
        let shard_cost_model = Arc::new(
            ShardCostModel::new(opcode_chips, ecall_chips, chip_specs, E::DEGREE)
                .with_atomic_ecalls([
                    TensorMatMulV1Spec::CODE,
                    #[cfg(feature = "llama-tiny")]
                    TensorBatchedMatMul2x2V1Spec::CODE,
                    ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1,
                    ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1,
                    TensorRmsLookupV1Spec::CODE,
                    TensorAttentionReducedV1Spec::CODE,
                    TensorAttentionBlockReducedV1Spec::CODE,
                    TensorFfnBlockReducedV1Spec::CODE,
                    #[cfg(not(feature = "llama-tiny"))]
                    TensorProductionImportBeginV2Spec::CODE,
                    #[cfg(not(feature = "llama-tiny"))]
                    TensorProductionAttentionV2Spec::CODE,
                    #[cfg(not(feature = "llama-tiny"))]
                    TensorProductionExportEndV2Spec::CODE,
                ]),
        );

        // tables
        let dynamic_range_config =
            cs.register_table_circuit::<DynamicRangeTableCircuit<E, DYNAMIC_RANGE_MAX_BITS>>();
        let double_u8_range_config = cs.register_table_circuit::<DoubleU8TableCircuit<E>>();
        let and_table_config = cs.register_table_circuit::<AndTableCircuit<E>>();
        let or_table_config = cs.register_table_circuit::<OrTableCircuit<E>>();
        let xor_table_config = cs.register_table_circuit::<XorTableCircuit<E>>();
        let ltu_config = cs.register_table_circuit::<LtuTableCircuit<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_softmax_exp3_config = cs.register_table_circuit::<SoftmaxExp3TableCircuit<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_softmax_exp4_config = cs.register_table_circuit::<SoftmaxExp4TableCircuit<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_rms_inv_config = cs.register_table_circuit::<RmsInvTableCircuit<E>>();
        #[cfg(feature = "llama-tiny")]
        let llama_swiglu_config = cs.register_table_circuit::<SwiGluTableCircuit<E>>();
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
            tensor_bus_import_config,
            tensor_bus_export_config,
            tensor_bus_handle_attention_config,
            tensor_bus_handle_ffn_config,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_import_anchor_config,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_attention_anchor_config,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_export_anchor_config,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_boundary_q_config,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_boundary_k_config,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_boundary_v_config,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_boundary_context_config,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_qk_configs,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_softmax_configs,
            #[cfg(not(feature = "llama-tiny"))]
            tensor_production_pv_configs,
            tensor_matmul_ecall_config,
            tensor_matmul_core_config,
            #[cfg(feature = "llama-tiny")]
            tensor_batched_matmul_ecall_config,
            #[cfg(feature = "llama-tiny")]
            tensor_batched_matmul_core_config,
            #[cfg(feature = "llama-tiny")]
            tensor_hint_ref_core_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_rms_arithmetic_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_rms_lookup_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_matmul_bridge_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_rope_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_softmax_arithmetic_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_softmax_low_digit_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_softmax_exp3_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_softmax_exp4_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_residual_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_swiglu_lookup_config,
            #[cfg(feature = "llama-tiny")]
            llama_tiny_swiglu_arithmetic_config,
            tensor_hidden_ecall_config,
            tensor_production_tile_config,
            tensor_gate5_small_hidden_tile_config,
            tensor_hidden_finalize_config,
            tensor_gate5_small_hidden_ecall_config,
            tensor_gate5_small_hidden_finalize_config,
            tensor_intermediate_ecall_config,
            tensor_intermediate_finalize_config,
            tensor_rms_ecall_config,
            tensor_rms_core_config,
            tensor_attention_ecall_config,
            tensor_attention_core_config,
            tensor_attention_block_ecall_config,
            tensor_attention_block_core_config,
            tensor_ffn_block_ecall_config,
            tensor_ffn_block_core_config,
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
            #[cfg(feature = "llama-tiny")]
            llama_softmax_exp3_config,
            #[cfg(feature = "llama-tiny")]
            llama_softmax_exp4_config,
            #[cfg(feature = "llama-tiny")]
            llama_rms_inv_config,
            #[cfg(feature = "llama-tiny")]
            llama_swiglu_config,
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
        fixed.register_opcode_circuit::<TensorBusImportBeginEcallInstruction<E>>(
            cs,
            &self.tensor_bus_import_config,
        );
        fixed.register_opcode_circuit::<TensorBusExportEndEcallInstruction<E>>(
            cs,
            &self.tensor_bus_export_config,
        );
        fixed.register_opcode_circuit::<TensorBusHandleAttentionEcallInstruction<E>>(
            cs,
            &self.tensor_bus_handle_attention_config,
        );
        fixed.register_opcode_circuit::<TensorBusHandleFfnEcallInstruction<E>>(
            cs,
            &self.tensor_bus_handle_ffn_config,
        );
        #[cfg(not(feature = "llama-tiny"))]
        fixed.register_opcode_circuit::<TensorProductionImportAnchorInstruction<E>>(
            cs,
            &self.tensor_production_import_anchor_config,
        );
        #[cfg(not(feature = "llama-tiny"))]
        fixed.register_opcode_circuit::<TensorProductionAttentionAnchorInstruction<E>>(
            cs,
            &self.tensor_production_attention_anchor_config,
        );
        #[cfg(not(feature = "llama-tiny"))]
        fixed.register_opcode_circuit::<TensorProductionExportAnchorInstruction<E>>(
            cs,
            &self.tensor_production_export_anchor_config,
        );
        #[cfg(not(feature = "llama-tiny"))]
        fixed.register_opcode_circuit::<TensorProductionBoundaryQInstruction<E>>(
            cs,
            &self.tensor_production_boundary_q_config,
        );
        #[cfg(not(feature = "llama-tiny"))]
        fixed.register_opcode_circuit::<TensorProductionBoundaryKInstruction<E>>(
            cs,
            &self.tensor_production_boundary_k_config,
        );
        #[cfg(not(feature = "llama-tiny"))]
        fixed.register_opcode_circuit::<TensorProductionBoundaryVInstruction<E>>(
            cs,
            &self.tensor_production_boundary_v_config,
        );
        #[cfg(not(feature = "llama-tiny"))]
        fixed.register_opcode_circuit::<TensorProductionBoundaryContextInstruction<E>>(
            cs,
            &self.tensor_production_boundary_context_config,
        );
        #[cfg(not(feature = "llama-tiny"))]
        {
            macro_rules! register_production_matrix {
                ($instruction:ty, $configs:ident, $group:expr) => {
                    fixed.register_opcode_circuit::<$instruction>(cs, &self.$configs[$group]);
                };
            }
            register_production_matrix!(TensorProductionQkCoreInstruction<E, 0>, tensor_production_qk_configs, 0);
            register_production_matrix!(TensorProductionQkCoreInstruction<E, 1>, tensor_production_qk_configs, 1);
            register_production_matrix!(TensorProductionQkCoreInstruction<E, 2>, tensor_production_qk_configs, 2);
            register_production_matrix!(TensorProductionQkCoreInstruction<E, 3>, tensor_production_qk_configs, 3);
            register_production_matrix!(TensorProductionQkCoreInstruction<E, 4>, tensor_production_qk_configs, 4);
            register_production_matrix!(TensorProductionQkCoreInstruction<E, 5>, tensor_production_qk_configs, 5);
            register_production_matrix!(TensorProductionQkCoreInstruction<E, 6>, tensor_production_qk_configs, 6);
            register_production_matrix!(TensorProductionQkCoreInstruction<E, 7>, tensor_production_qk_configs, 7);
            register_production_matrix!(TensorProductionSoftmaxCoreInstruction<E, 0>, tensor_production_softmax_configs, 0);
            register_production_matrix!(TensorProductionSoftmaxCoreInstruction<E, 1>, tensor_production_softmax_configs, 1);
            register_production_matrix!(TensorProductionSoftmaxCoreInstruction<E, 2>, tensor_production_softmax_configs, 2);
            register_production_matrix!(TensorProductionSoftmaxCoreInstruction<E, 3>, tensor_production_softmax_configs, 3);
            register_production_matrix!(TensorProductionSoftmaxCoreInstruction<E, 4>, tensor_production_softmax_configs, 4);
            register_production_matrix!(TensorProductionSoftmaxCoreInstruction<E, 5>, tensor_production_softmax_configs, 5);
            register_production_matrix!(TensorProductionSoftmaxCoreInstruction<E, 6>, tensor_production_softmax_configs, 6);
            register_production_matrix!(TensorProductionSoftmaxCoreInstruction<E, 7>, tensor_production_softmax_configs, 7);
            register_production_matrix!(TensorProductionPvCoreInstruction<E, 0>, tensor_production_pv_configs, 0);
            register_production_matrix!(TensorProductionPvCoreInstruction<E, 1>, tensor_production_pv_configs, 1);
            register_production_matrix!(TensorProductionPvCoreInstruction<E, 2>, tensor_production_pv_configs, 2);
            register_production_matrix!(TensorProductionPvCoreInstruction<E, 3>, tensor_production_pv_configs, 3);
            register_production_matrix!(TensorProductionPvCoreInstruction<E, 4>, tensor_production_pv_configs, 4);
            register_production_matrix!(TensorProductionPvCoreInstruction<E, 5>, tensor_production_pv_configs, 5);
            register_production_matrix!(TensorProductionPvCoreInstruction<E, 6>, tensor_production_pv_configs, 6);
            register_production_matrix!(TensorProductionPvCoreInstruction<E, 7>, tensor_production_pv_configs, 7);
        }
        if let Some(config) = &self.tensor_matmul_ecall_config {
            fixed.register_opcode_circuit::<TensorMatMulEcallInstruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_matmul_core_config {
            fixed.register_opcode_circuit::<TensorMatMulCoreInstruction<E>>(cs, config);
        }
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<TensorBatchedMatMul2x2EcallInstruction<E>>(
            cs,
            &self.tensor_batched_matmul_ecall_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<TensorBatchedMatMulCoreInstruction<E>>(
            cs,
            &self.tensor_batched_matmul_core_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<TensorHintRefCoreInstruction<E>>(
            cs,
            &self.tensor_hint_ref_core_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinyRmsArithmeticCore<E>>(
            cs,
            &self.llama_tiny_rms_arithmetic_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinyRmsLookupCore<E>>(
            cs,
            &self.llama_tiny_rms_lookup_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinyMatMulBridgeCore<E>>(
            cs,
            &self.llama_tiny_matmul_bridge_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinyRoPECore<E>>(cs, &self.llama_tiny_rope_config);
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinySoftmaxArithmeticCore<E>>(
            cs,
            &self.llama_tiny_softmax_arithmetic_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinySoftmaxLowDigitCore<E>>(
            cs,
            &self.llama_tiny_softmax_low_digit_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinySoftmaxExp3Core<E>>(
            cs,
            &self.llama_tiny_softmax_exp3_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinySoftmaxExp4Core<E>>(
            cs,
            &self.llama_tiny_softmax_exp4_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinyResidualCore<E>>(
            cs,
            &self.llama_tiny_residual_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinySwiGluLookupCore<E>>(
            cs,
            &self.llama_tiny_swiglu_lookup_config,
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_opcode_circuit::<LlamaTinySwiGluArithmeticCore<E>>(
            cs,
            &self.llama_tiny_swiglu_arithmetic_config,
        );
        if let Some(config) = &self.tensor_hidden_ecall_config {
            fixed.register_opcode_circuit::<TensorMatMulHiddenEcallInstruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_production_tile_config {
            fixed.register_opcode_circuit::<TensorProductionTileInstruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_gate5_small_hidden_tile_config {
            fixed.register_opcode_circuit::<TensorProductionTileK64Instruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_hidden_finalize_config {
            fixed.register_opcode_circuit::<TensorMatMulHiddenFinalizeInstruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_gate5_small_hidden_ecall_config {
            fixed.register_opcode_circuit::<TensorMatMulGate5SmallHiddenEcallInstruction<E>>(
                cs, config,
            );
        }
        if let Some(config) = &self.tensor_gate5_small_hidden_finalize_config {
            fixed.register_opcode_circuit::<TensorMatMulGate5SmallHiddenFinalizeInstruction<E>>(
                cs, config,
            );
        }
        if let Some(config) = &self.tensor_intermediate_ecall_config {
            fixed
                .register_opcode_circuit::<TensorMatMulIntermediateEcallInstruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_intermediate_finalize_config {
            fixed.register_opcode_circuit::<TensorMatMulIntermediateFinalizeInstruction<E>>(
                cs, config,
            );
        }
        if let Some(config) = &self.tensor_rms_ecall_config {
            fixed.register_opcode_circuit::<TensorRmsLookupEcallInstruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_rms_core_config {
            fixed.register_opcode_circuit::<TensorRmsLookupCoreInstruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_attention_ecall_config {
            fixed.register_opcode_circuit::<TensorAttentionReducedEcallInstruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_attention_core_config {
            fixed.register_opcode_circuit::<TensorAttentionReducedCoreInstruction<E>>(cs, config);
        }
        fixed.register_opcode_circuit::<TensorAttentionBlockReducedEcallInstruction<E>>(
            cs,
            &self.tensor_attention_block_ecall_config,
        );
        fixed.register_opcode_circuit::<TensorAttentionBlockReducedCoreInstruction<E>>(
            cs,
            &self.tensor_attention_block_core_config,
        );
        if let Some(config) = &self.tensor_ffn_block_ecall_config {
            fixed.register_opcode_circuit::<TensorFfnBlockReducedEcallInstruction<E>>(cs, config);
        }
        if let Some(config) = &self.tensor_ffn_block_core_config {
            fixed.register_opcode_circuit::<TensorFfnBlockReducedCoreInstruction<E>>(cs, config);
        }
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
        #[cfg(feature = "llama-tiny")]
        fixed.register_table_circuit::<SoftmaxExp3TableCircuit<E>>(
            cs,
            &self.llama_softmax_exp3_config,
            &(),
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_table_circuit::<SoftmaxExp4TableCircuit<E>>(
            cs,
            &self.llama_softmax_exp4_config,
            &(),
        );
        #[cfg(feature = "llama-tiny")]
        fixed.register_table_circuit::<RmsInvTableCircuit<E>>(cs, &self.llama_rms_inv_config, &());
        #[cfg(feature = "llama-tiny")]
        fixed.register_table_circuit::<SwiGluTableCircuit<E>>(cs, &self.llama_swiglu_config, &());
        #[cfg(not(feature = "u16limb_circuit"))]
        fixed.register_table_circuit::<PowTableCircuit<E>>(cs, &self.pow_config, &());
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn prepare_provisional_fused_assignments(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        family_counts: &[usize; InsnKind::COUNT],
    ) -> Result<(), ZKVMError> {
        use crate::instructions::gpu::dispatch::{self, GpuWitgenKind as K};
        macro_rules! prepare_opcode {
            ($instruction:ty, $config:ident, $kind:expr) => {{
                let chip_cs = cs.get_cs(&<$instruction>::name()).unwrap();
                let kind = <$instruction>::inst_kinds()[0];
                dispatch::prepare_fused_assignment::<E, $instruction>(
                    &self.$config,
                    chip_cs.zkvm_v1_css.num_witin as usize,
                    chip_cs.zkvm_v1_css.num_structural_witin as usize,
                    family_counts[kind as usize],
                    $kind,
                )?;
            }};
        }
        for_each_fused_opcode!(prepare_opcode);
        Ok(())
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
        log_ecall!("TENSOR_MATMUL_V1", TensorMatMulV1Spec::CODE);
        #[cfg(feature = "llama-tiny")]
        log_ecall!(
            "TENSOR_BATCHED_MATMUL_2X2_V1",
            TensorBatchedMatMul2x2V1Spec::CODE
        );
        log_ecall!("TENSOR_RMS_LOOKUP_V1", TensorRmsLookupV1Spec::CODE);
        log_ecall!(
            "TENSOR_ATTENTION_REDUCED_V1",
            TensorAttentionReducedV1Spec::CODE
        );
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
                let n = instrunction_dispatch_ctx
                    .record_count_for_kinds::<E, $instruction>();
                #[cfg(feature = "gpu")]
                let records = if instrunction_dispatch_ctx.compact_counts_active {
                    assert!(
                        crate::instructions::gpu::dispatch::is_fused_ingress_active(),
                        "compact counts require an active fused GPU assignment"
                    );
                    &[][..]
                } else {
                    instrunction_dispatch_ctx
                        .records_for_kinds::<E, $instruction>()
                        .unwrap_or(&[])
                };
                #[cfg(not(feature = "gpu"))]
                let records = instrunction_dispatch_ctx
                    .records_for_kinds::<E, $instruction>()
                    .unwrap_or(&[]);
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
        macro_rules! assign_ecall_with_config {
            ($instruction:ty, $config:expr, $code:expr) => {{
                let records = instrunction_dispatch_ctx
                    .records_for_ecall_code($code)
                    .unwrap_or(&[]);
                let n = records.len();
                info_span!("assign_chip", chip = %<$instruction>::name(), n)
                    .in_scope(|| {
                        witness.assign_opcode_circuit::<$instruction>(
                            cs,
                            shard_ctx,
                            $config,
                            shard_steps,
                            records,
                        )
                    })?;
            }};
        }

        #[cfg(feature = "gpu")]
        {
            use crate::instructions::gpu::dispatch::{self, GpuWitgenKind as K};
            macro_rules! prepare_opcode {
                ($instruction:ty, $config:ident, $kind:expr) => {{
                    let expected_rows =
                        instrunction_dispatch_ctx.record_count_for_kinds::<E, $instruction>();
                    let chip_cs = cs.get_cs(&<$instruction>::name()).unwrap();
                    dispatch::prepare_fused_assignment::<E, $instruction>(
                        &self.$config,
                        chip_cs.zkvm_v1_css.num_witin as usize,
                        chip_cs.zkvm_v1_css.num_structural_witin as usize,
                        expected_rows,
                        $kind,
                    )?;
                }};
            }
            for_each_fused_opcode!(prepare_opcode);
            dispatch::launch_fused_assignments(shard_ctx)?;
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
            TensorBusImportBeginEcallInstruction<E>,
            tensor_bus_import_config,
            TensorImportBeginV1Spec::CODE
        );
        assign_ecall!(
            TensorBusExportEndEcallInstruction<E>,
            tensor_bus_export_config,
            TensorExportEndV1Spec::CODE
        );
        assign_ecall!(
            TensorBusHandleAttentionEcallInstruction<E>,
            tensor_bus_handle_attention_config,
            TensorHandleAttentionV1Spec::CODE
        );
        assign_ecall!(
            TensorBusHandleFfnEcallInstruction<E>,
            tensor_bus_handle_ffn_config,
            TensorHandleFfnV1Spec::CODE
        );
        #[cfg(not(feature = "llama-tiny"))]
        assign_ecall!(
            TensorProductionImportAnchorInstruction<E>,
            tensor_production_import_anchor_config,
            TensorProductionImportBeginV2Spec::CODE
        );
        #[cfg(not(feature = "llama-tiny"))]
        assign_ecall!(
            TensorProductionAttentionAnchorInstruction<E>,
            tensor_production_attention_anchor_config,
            TensorProductionAttentionV2Spec::CODE
        );
        #[cfg(not(feature = "llama-tiny"))]
        assign_ecall!(
            TensorProductionExportAnchorInstruction<E>,
            tensor_production_export_anchor_config,
            TensorProductionExportEndV2Spec::CODE
        );
        #[cfg(all(not(feature = "llama-tiny"), feature = "gpu"))]
        {
            let mut boundary_records = instrunction_dispatch_ctx
                .records_for_ecall_code(TensorProductionImportBeginV2Spec::CODE)
                .unwrap_or(&[])
                .to_vec();
            boundary_records.extend_from_slice(
                instrunction_dispatch_ctx
                    .records_for_ecall_code(TensorProductionExportEndV2Spec::CODE)
                    .unwrap_or(&[]),
            );
            if !boundary_records.is_empty() {
                let descriptors = collect_production_boundary_replay_descriptors(
                    shard_ctx,
                    shard_steps,
                    &boundary_records,
                )?;
                macro_rules! assign_production_boundary {
                    ($part:expr, $instruction:ty, $config:ident) => {{
                        let descriptor = descriptors[$part];
                        let step = &shard_steps[descriptor.step_index];
                        let syscall = step
                            .syscall(&shard_ctx.syscall_witnesses)
                            .ok_or_else(|| {
                                ZKVMError::InvalidWitness(
                                    "production boundary syscall missing during device replay"
                                        .into(),
                                )
                            })?;
                        let end = descriptor
                            .mem_ops_start
                            .checked_add(descriptor.rows)
                            .ok_or_else(|| {
                                ZKVMError::InvalidWitness(
                                    "production boundary journal range overflow".into(),
                                )
                            })?;
                        let journal = syscall
                            .mem_ops
                            .get(descriptor.mem_ops_start..end)
                            .ok_or_else(|| {
                                ZKVMError::InvalidWitness(
                                    "production boundary journal range incomplete".into(),
                                )
                            })?;
                        let boundary_cs = cs
                            .get_cs(&<$instruction>::name())
                            .expect("production boundary circuit missing");
                        let (assignment, multiplicity) = crate::instructions::gpu::chips::production_attention_boundary::assign_production_boundary_device(
                            &self.$config,
                            shard_ctx,
                            boundary_cs.zkvm_v1_css.num_witin as usize,
                            boundary_cs.zkvm_v1_css.num_structural_witin as usize,
                            shard_steps,
                            descriptor,
                            journal,
                        )?;
                        witness.insert_opcode_assignment::<$instruction>(assignment, multiplicity);
                    }};
                }
                assign_production_boundary!(
                    0,
                    TensorProductionBoundaryQInstruction<E>,
                    tensor_production_boundary_q_config
                );
                assign_production_boundary!(
                    1,
                    TensorProductionBoundaryKInstruction<E>,
                    tensor_production_boundary_k_config
                );
                assign_production_boundary!(
                    2,
                    TensorProductionBoundaryVInstruction<E>,
                    tensor_production_boundary_v_config
                );
                assign_production_boundary!(
                    3,
                    TensorProductionBoundaryContextInstruction<E>,
                    tensor_production_boundary_context_config
                );
            }
        }
        #[cfg(all(not(feature = "llama-tiny"), feature = "gpu"))]
        {
            let attention_records = instrunction_dispatch_ctx
                .records_for_ecall_code(TensorProductionAttentionV2Spec::CODE)
                .unwrap_or(&[]);
            if !attention_records.is_empty() {
                if attention_records.len() != 1 {
                    return Err(ZKVMError::InvalidWitness(
                        "production QK replay requires exactly one atomic attention call".into(),
                    ));
                }
                let step = &shard_steps[attention_records[0]];
                let call = step
                    .syscall(&shard_ctx.syscall_witnesses)
                    .and_then(|syscall| syscall.tensor_production_attention)
                    .ok_or_else(|| {
                        ZKVMError::InvalidWitness(
                            "production attention call metadata missing during QK replay".into(),
                        )
                    })?;
                macro_rules! assign_production_qk {
                    ($group:expr) => {{
                        let qk_cs = cs
                            .get_cs(&TensorProductionQkCoreInstruction::<E, $group>::name())
                            .expect("production QK circuit missing");
                        let (assignment, multiplicity) = crate::instructions::gpu::chips::production_attention_matrix::assign_production_qk_device::<E, $group>(
                            &self.tensor_production_qk_configs[$group],
                            shard_ctx,
                            qk_cs.zkvm_v1_css.num_witin as usize,
                            qk_cs.zkvm_v1_css.num_structural_witin as usize,
                            shard_steps,
                            call,
                        )?;
                        witness.insert_opcode_assignment::<TensorProductionQkCoreInstruction<E, $group>>(assignment, multiplicity);
                    }};
                }
                assign_production_qk!(0);
                assign_production_qk!(1);
                assign_production_qk!(2);
                assign_production_qk!(3);
                assign_production_qk!(4);
                assign_production_qk!(5);
                assign_production_qk!(6);
                assign_production_qk!(7);
                macro_rules! assign_production_softmax {
                    ($group:expr) => {{
                        let softmax_cs = cs
                            .get_cs(&TensorProductionSoftmaxCoreInstruction::<E, $group>::name())
                            .expect("production softmax circuit missing");
                        let (assignment, multiplicity) = crate::instructions::gpu::chips::production_attention_softmax::assign_production_softmax_device::<E, $group>(
                            &self.tensor_production_softmax_configs[$group],
                            shard_ctx,
                            softmax_cs.zkvm_v1_css.num_witin as usize,
                            softmax_cs.zkvm_v1_css.num_structural_witin as usize,
                            shard_steps,
                            call,
                        )?;
                        witness.insert_opcode_assignment::<TensorProductionSoftmaxCoreInstruction<E, $group>>(assignment, multiplicity);
                    }};
                }
                assign_production_softmax!(0);
                assign_production_softmax!(1);
                assign_production_softmax!(2);
                assign_production_softmax!(3);
                assign_production_softmax!(4);
                assign_production_softmax!(5);
                assign_production_softmax!(6);
                assign_production_softmax!(7);
                macro_rules! assign_production_pv {
                    ($group:expr) => {{
                        let pv_cs = cs
                            .get_cs(&TensorProductionPvCoreInstruction::<E, $group>::name())
                            .expect("production PV circuit missing");
                        let (assignment, multiplicity) = crate::instructions::gpu::chips::production_attention_matrix::assign_production_pv_device::<E, $group>(
                            &self.tensor_production_pv_configs[$group],
                            shard_ctx,
                            pv_cs.zkvm_v1_css.num_witin as usize,
                            pv_cs.zkvm_v1_css.num_structural_witin as usize,
                            shard_steps,
                            call,
                        )?;
                        witness.insert_opcode_assignment::<TensorProductionPvCoreInstruction<E, $group>>(assignment, multiplicity);
                    }};
                }
                assign_production_pv!(0);
                assign_production_pv!(1);
                assign_production_pv!(2);
                assign_production_pv!(3);
                assign_production_pv!(4);
                assign_production_pv!(5);
                assign_production_pv!(6);
                assign_production_pv!(7);
            }
        }
        if let Some(tensor_matmul_ecall_config) = &self.tensor_matmul_ecall_config {
            assign_ecall_with_config!(
                TensorMatMulEcallInstruction<E>,
                tensor_matmul_ecall_config,
                TensorMatMulV1Spec::CODE
            );
        }
        if let Some(tensor_matmul_core_config) = &self.tensor_matmul_core_config {
            assign_ecall_with_config!(
                TensorMatMulCoreInstruction<E>,
                tensor_matmul_core_config,
                TensorMatMulV1Spec::CODE
            );
        }
        #[cfg(feature = "llama-tiny")]
        {
            let standalone_records = instrunction_dispatch_ctx
                .records_for_ecall_code(TensorBatchedMatMul2x2V1Spec::CODE)
                .unwrap_or(&[]);
            let n = standalone_records.len();
            info_span!(
                "assign_chip",
                chip = %<TensorBatchedMatMul2x2EcallInstruction<E>>::name(),
                n
            )
            .in_scope(|| {
                witness.assign_opcode_circuit::<TensorBatchedMatMul2x2EcallInstruction<E>>(
                    cs,
                    shard_ctx,
                    &self.tensor_batched_matmul_ecall_config,
                    shard_steps,
                    standalone_records,
                )
            })?;

            let resident_for = |code| {
                instrunction_dispatch_ctx
                    .records_for_ecall_code(code)
                    .unwrap_or(&[])
                    .iter()
                    .copied()
                    .filter(|index| {
                        shard_steps[*index]
                            .syscall(&shard_ctx.syscall_witnesses)
                            .is_some_and(|syscall| syscall.tensor_resident_matmul.is_some())
                    })
                    .collect_vec()
            };
            let attention_records = resident_for(TensorHandleAttentionV1Spec::CODE);
            let ffn_records = resident_for(TensorHandleFfnV1Spec::CODE);
            if !attention_records.is_empty() || !ffn_records.is_empty() {
                let layer_sections = collect_layer_sections(
                    shard_ctx,
                    shard_steps,
                    &attention_records,
                    &ffn_records,
                )?;
                audit_layer_graph(&layer_sections)?;
                let mut matrix_sections = layer_sections
                    .iter()
                    .flat_map(|section| section.matrices.iter().cloned())
                    .collect_vec();
                for index in standalone_records {
                    let step = &shard_steps[*index];
                    let syscall = step.syscall(&shard_ctx.syscall_witnesses).ok_or_else(|| {
                        ZKVMError::InvalidWitness("tiny batched MatMul syscall missing".into())
                    })?;
                    let payload = syscall.tensor_batched_matmul_2x2.ok_or_else(|| {
                        ZKVMError::InvalidWitness("tiny batched MatMul payload missing".into())
                    })?;
                    matrix_sections.push(
                        crate::instructions::riscv::ecall::tensor_batched_matmul::TensorBatchedMatMulSection {
                            cycle: step.cycle() - shard_ctx.current_shard_offset_cycle(),
                            call_id: syscall.reg_ops[0].value.after as u64,
                            a: payload.a,
                            w: payload.w,
                            resident: None,
                        },
                    );
                }
                let hints = layer_sections
                    .iter()
                    .flat_map(|section| section.hints)
                    .collect_vec();

                let matrix_cs = cs
                    .get_cs(&<TensorBatchedMatMulCoreInstruction<E>>::name())
                    .expect("llama-tiny matrix Core circuit");
                let (matrix_witness, matrix_lkm) =
                    TensorBatchedMatMulCoreInstruction::<E>::assign_sections(
                        &self.tensor_batched_matmul_core_config,
                        matrix_cs.zkvm_v1_css.num_witin as usize,
                        matrix_cs.zkvm_v1_css.num_structural_witin as usize,
                        &matrix_sections,
                    )?;
                witness.insert_opcode_assignment::<TensorBatchedMatMulCoreInstruction<E>>(
                    matrix_witness,
                    matrix_lkm,
                );

                let hint_cs = cs
                    .get_cs(&<TensorHintRefCoreInstruction<E>>::name())
                    .expect("llama-tiny HintRef Core circuit");
                let (hint_witness, hint_lkm) = TensorHintRefCoreInstruction::<E>::assign_hints(
                    &self.tensor_hint_ref_core_config,
                    hint_cs.zkvm_v1_css.num_witin as usize,
                    hint_cs.zkvm_v1_css.num_structural_witin as usize,
                    &hints,
                )?;
                witness.insert_opcode_assignment::<TensorHintRefCoreInstruction<E>>(
                    hint_witness,
                    hint_lkm,
                );

                macro_rules! assign_llama_family {
                    ($instruction:ty, $config:expr) => {{
                        let family_cs = cs
                            .get_cs(&<$instruction>::name())
                            .expect("llama-tiny family Core circuit");
                        let (family_witness, family_lkm) = <$instruction>::assign_layer_sections(
                            $config,
                            family_cs.zkvm_v1_css.num_witin as usize,
                            family_cs.zkvm_v1_css.num_structural_witin as usize,
                            &layer_sections,
                        )?;
                        witness
                            .insert_opcode_assignment::<$instruction>(family_witness, family_lkm);
                    }};
                }
                assign_llama_family!(
                    LlamaTinyRmsArithmeticCore<E>,
                    &self.llama_tiny_rms_arithmetic_config
                );
                assign_llama_family!(
                    LlamaTinyRmsLookupCore<E>,
                    &self.llama_tiny_rms_lookup_config
                );
                assign_llama_family!(
                    LlamaTinyMatMulBridgeCore<E>,
                    &self.llama_tiny_matmul_bridge_config
                );
                assign_llama_family!(LlamaTinyRoPECore<E>, &self.llama_tiny_rope_config);
                assign_llama_family!(
                    LlamaTinySoftmaxArithmeticCore<E>,
                    &self.llama_tiny_softmax_arithmetic_config
                );
                assign_llama_family!(
                    LlamaTinySoftmaxLowDigitCore<E>,
                    &self.llama_tiny_softmax_low_digit_config
                );
                assign_llama_family!(
                    LlamaTinySoftmaxExp3Core<E>,
                    &self.llama_tiny_softmax_exp3_config
                );
                assign_llama_family!(
                    LlamaTinySoftmaxExp4Core<E>,
                    &self.llama_tiny_softmax_exp4_config
                );
                assign_llama_family!(LlamaTinyResidualCore<E>, &self.llama_tiny_residual_config);
                assign_llama_family!(
                    LlamaTinySwiGluLookupCore<E>,
                    &self.llama_tiny_swiglu_lookup_config
                );
                assign_llama_family!(
                    LlamaTinySwiGluArithmeticCore<E>,
                    &self.llama_tiny_swiglu_arithmetic_config
                );
            } else if !standalone_records.is_empty() {
                witness.assign_opcode_circuit::<TensorBatchedMatMulCoreInstruction<E>>(
                    cs,
                    shard_ctx,
                    &self.tensor_batched_matmul_core_config,
                    shard_steps,
                    standalone_records,
                )?;
            }
        }
        if let Some(tensor_hidden_ecall_config) = &self.tensor_hidden_ecall_config {
            assign_ecall_with_config!(
                TensorMatMulHiddenEcallInstruction<E>,
                tensor_hidden_ecall_config,
                ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1
            );
        }
        if let Some(tensor_hidden_finalize_config) = &self.tensor_hidden_finalize_config {
            assign_ecall_with_config!(
                TensorMatMulHiddenFinalizeInstruction<E>,
                tensor_hidden_finalize_config,
                ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1
            );
        }
        if let Some(tensor_gate5_small_hidden_ecall_config) =
            &self.tensor_gate5_small_hidden_ecall_config
        {
            assign_ecall_with_config!(
                TensorMatMulGate5SmallHiddenEcallInstruction<E>,
                tensor_gate5_small_hidden_ecall_config,
                ceno_emul::tensor::TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1
            );
        }
        if let Some(tensor_gate5_small_hidden_finalize_config) =
            &self.tensor_gate5_small_hidden_finalize_config
        {
            assign_ecall_with_config!(
                TensorMatMulGate5SmallHiddenFinalizeInstruction<E>,
                tensor_gate5_small_hidden_finalize_config,
                ceno_emul::tensor::TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1
            );
        }
        if let Some(tensor_intermediate_ecall_config) = &self.tensor_intermediate_ecall_config {
            assign_ecall_with_config!(
                TensorMatMulIntermediateEcallInstruction<E>,
                tensor_intermediate_ecall_config,
                ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1
            );
        }
        let mut tensor_production_records = instrunction_dispatch_ctx
            .records_for_ecall_code(ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1)
            .unwrap_or(&[])
            .to_vec();
        tensor_production_records.extend_from_slice(
            instrunction_dispatch_ctx
                .records_for_ecall_code(ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1)
                .unwrap_or(&[]),
        );
        tensor_production_records.extend_from_slice(
            instrunction_dispatch_ctx
                .records_for_ecall_code(ceno_emul::tensor::TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1)
                .unwrap_or(&[]),
        );
        tensor_production_records.sort_unstable();
        let n = tensor_production_records.len();
        if std::env::var_os("CENO_TENSOR_E2E_RW_TRACE").is_some()
            && !tensor_production_records.is_empty()
        {
            tracing::info!(
                target: "ceno_gpu::tensor_record_path",
                records = ?tensor_production_records,
                hidden_records = instrunction_dispatch_ctx
                    .records_for_ecall_code(ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1)
                    .map_or(0, |records| records.len()),
                    intermediate_records = instrunction_dispatch_ctx
                    .records_for_ecall_code(ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1)
                        .map_or(0, |records| records.len()),
                    small_hidden_records = instrunction_dispatch_ctx
                        .records_for_ecall_code(ceno_emul::tensor::TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1)
                        .map_or(0, |records| records.len()),
                "Gate-5 production tile dispatch grouping"
            );
        }
        if let Some(config) = &self.tensor_production_tile_config {
            info_span!(
                "assign_chip",
                chip = %<TensorProductionTileInstruction<E>>::name(),
                n
            )
            .in_scope(|| {
                witness.assign_opcode_circuit::<TensorProductionTileInstruction<E>>(
                    cs,
                    shard_ctx,
                    config,
                    shard_steps,
                    &tensor_production_records,
                )
            })?;
        } else if let Some(config) = &self.tensor_gate5_small_hidden_tile_config {
            info_span!(
                "assign_chip",
                chip = %<TensorProductionTileK64Instruction<E>>::name(),
                n
            )
            .in_scope(|| {
                witness.assign_opcode_circuit::<TensorProductionTileK64Instruction<E>>(
                    cs,
                    shard_ctx,
                    config,
                    shard_steps,
                    &tensor_production_records,
                )
            })?;
        } else if !tensor_production_records.is_empty() {
            return Err(ZKVMError::InvalidWitness(
                "production tensor ecall is unavailable in the minimal E2E registry".into(),
            ));
        }
        if let Some(tensor_intermediate_finalize_config) = &self.tensor_intermediate_finalize_config
        {
            assign_ecall_with_config!(
                TensorMatMulIntermediateFinalizeInstruction<E>,
                tensor_intermediate_finalize_config,
                ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1
            );
        }
        if let Some(tensor_rms_ecall_config) = &self.tensor_rms_ecall_config {
            assign_ecall_with_config!(
                TensorRmsLookupEcallInstruction<E>,
                tensor_rms_ecall_config,
                TensorRmsLookupV1Spec::CODE
            );
        }
        if let Some(tensor_rms_core_config) = &self.tensor_rms_core_config {
            assign_ecall_with_config!(
                TensorRmsLookupCoreInstruction<E>,
                tensor_rms_core_config,
                TensorRmsLookupV1Spec::CODE
            );
        }
        if let Some(tensor_attention_ecall_config) = &self.tensor_attention_ecall_config {
            assign_ecall_with_config!(
                TensorAttentionReducedEcallInstruction<E>,
                tensor_attention_ecall_config,
                TensorAttentionReducedV1Spec::CODE
            );
        }
        if let Some(tensor_attention_core_config) = &self.tensor_attention_core_config {
            assign_ecall_with_config!(
                TensorAttentionReducedCoreInstruction<E>,
                tensor_attention_core_config,
                TensorAttentionReducedV1Spec::CODE
            );
        }
        assign_ecall!(
            TensorAttentionBlockReducedEcallInstruction<E>,
            tensor_attention_block_ecall_config,
            TensorAttentionBlockReducedV1Spec::CODE
        );
        assign_ecall!(
            TensorAttentionBlockReducedCoreInstruction<E>,
            tensor_attention_block_core_config,
            TensorAttentionBlockReducedV1Spec::CODE
        );
        if let Some(tensor_ffn_block_ecall_config) = &self.tensor_ffn_block_ecall_config {
            assign_ecall_with_config!(
                TensorFfnBlockReducedEcallInstruction<E>,
                tensor_ffn_block_ecall_config,
                TensorFfnBlockReducedV1Spec::CODE
            );
        }
        if let Some(tensor_ffn_block_core_config) = &self.tensor_ffn_block_core_config {
            assign_ecall_with_config!(
                TensorFfnBlockReducedCoreInstruction<E>,
                tensor_ffn_block_core_config,
                TensorFfnBlockReducedV1Spec::CODE
            );
        }
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
        #[cfg(feature = "llama-tiny")]
        assign_table!(SoftmaxExp3TableCircuit<E>, &self.llama_softmax_exp3_config);
        #[cfg(feature = "llama-tiny")]
        assign_table!(SoftmaxExp4TableCircuit<E>, &self.llama_softmax_exp4_config);
        #[cfg(feature = "llama-tiny")]
        assign_table!(RmsInvTableCircuit<E>, &self.llama_rms_inv_config);
        #[cfg(feature = "llama-tiny")]
        assign_table!(SwiGluTableCircuit<E>, &self.llama_swiglu_config);
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
        macro_rules! collect_optional_ecall {
            ($instruction:ty, $config:ident) => {{
                let config = self.$config.as_ref().ok_or_else(|| {
                    ZKVMError::InvalidWitness(
                        format!(
                            "{} is unavailable in the minimal Tensor E2E registry",
                            <$instruction>::name()
                        )
                        .into(),
                    )
                })?;
                if let Err(err) = <$instruction>::collect_lk_and_shardram(
                    config,
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
                    TensorImportBeginV1Spec::CODE => {
                        collect_ecall!(
                            TensorBusImportBeginEcallInstruction<E>,
                            tensor_bus_import_config
                        );
                    }
                    TensorExportEndV1Spec::CODE => {
                        collect_ecall!(
                            TensorBusExportEndEcallInstruction<E>,
                            tensor_bus_export_config
                        );
                    }
                    TensorHandleAttentionV1Spec::CODE => {
                        collect_ecall!(
                            TensorBusHandleAttentionEcallInstruction<E>,
                            tensor_bus_handle_attention_config
                        );
                    }
                    TensorHandleFfnV1Spec::CODE => {
                        collect_ecall!(
                            TensorBusHandleFfnEcallInstruction<E>,
                            tensor_bus_handle_ffn_config
                        );
                    }
                    #[cfg(not(feature = "llama-tiny"))]
                    TensorProductionImportBeginV2Spec::CODE => {
                        collect_ecall!(
                            TensorProductionImportAnchorInstruction<E>,
                            tensor_production_import_anchor_config
                        );
                    }
                    #[cfg(not(feature = "llama-tiny"))]
                    TensorProductionAttentionV2Spec::CODE => {
                        collect_ecall!(
                            TensorProductionAttentionAnchorInstruction<E>,
                            tensor_production_attention_anchor_config
                        );
                    }
                    #[cfg(not(feature = "llama-tiny"))]
                    TensorProductionExportEndV2Spec::CODE => {
                        collect_ecall!(
                            TensorProductionExportAnchorInstruction<E>,
                            tensor_production_export_anchor_config
                        );
                    }
                    TensorMatMulV1Spec::CODE => {
                        collect_optional_ecall!(
                            TensorMatMulEcallInstruction<E>,
                            tensor_matmul_ecall_config
                        );
                    }
                    #[cfg(feature = "llama-tiny")]
                    TensorBatchedMatMul2x2V1Spec::CODE => {
                        collect_ecall!(
                            TensorBatchedMatMul2x2EcallInstruction<E>,
                            tensor_batched_matmul_ecall_config
                        );
                    }
                    ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1 => {
                        collect_optional_ecall!(
                            TensorMatMulHiddenEcallInstruction<E>,
                            tensor_hidden_ecall_config
                        );
                    }
                    ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1 => {
                        collect_optional_ecall!(
                            TensorMatMulIntermediateEcallInstruction<E>,
                            tensor_intermediate_ecall_config
                        );
                    }
                    ceno_emul::tensor::TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1 => {
                        collect_optional_ecall!(
                            TensorMatMulGate5SmallHiddenEcallInstruction<E>,
                            tensor_gate5_small_hidden_ecall_config
                        );
                    }
                    TensorRmsLookupV1Spec::CODE => {
                        collect_optional_ecall!(
                            TensorRmsLookupEcallInstruction<E>,
                            tensor_rms_ecall_config
                        );
                    }
                    TensorAttentionReducedV1Spec::CODE => {
                        collect_optional_ecall!(
                            TensorAttentionReducedEcallInstruction<E>,
                            tensor_attention_ecall_config
                        );
                    }
                    TensorAttentionBlockReducedV1Spec::CODE => {
                        collect_ecall!(
                            TensorAttentionBlockReducedEcallInstruction<E>,
                            tensor_attention_block_ecall_config
                        );
                    }
                    TensorFfnBlockReducedV1Spec::CODE => {
                        collect_optional_ecall!(
                            TensorFfnBlockReducedEcallInstruction<E>,
                            tensor_ffn_block_ecall_config
                        );
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
        step.has_future_access(StepRecord::FUTURE_ACCESS_RS1),
    );

    let syscall_witnesses = shard_ctx.syscall_witnesses.clone();
    let Some(syscall) = step.syscall(&syscall_witnesses) else {
        return;
    };
    for (index, op) in syscall.reg_ops.iter().enumerate() {
        shard_ctx.send(
            RAMType::Register,
            op.addr,
            op.register_index() as u64,
            step.cycle() + Tracer::SUBCYCLE_RD,
            op.previous_cycle,
            op.value.after,
            None,
            syscall.reg_future_access[index] != 0,
        );
    }
    for (index, op) in syscall.mem_ops.iter().enumerate() {
        shard_ctx.send(
            RAMType::Memory,
            op.addr,
            op.addr.baddr().0 as u64,
            step.cycle() + Tracer::SUBCYCLE_MEM,
            op.previous_cycle,
            op.value.after,
            Some(op.value.before),
            syscall.mem_future_access[index] != 0,
        );
    }
}

pub struct InstructionDispatchCtx {
    insn_to_record_buffer: Vec<Option<usize>>,
    type_to_record_buffer: HashMap<TypeId, usize>,
    insn_kinds: Vec<InsnKind>,
    circuit_record_buffers: Vec<Vec<StepIndex>>,
    compact_record_counts: Vec<usize>,
    compact_counts_active: bool,
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
            compact_record_counts: vec![0; record_buffer_count],
            compact_counts_active: false,
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

    pub fn begin_compact_ingest(&mut self) {
        assert!(
            !self.compact_counts_active,
            "compact instruction counts started twice"
        );
        self.compact_counts_active = true;
    }

    #[inline]
    pub fn ingest_compact_count(&mut self, kind: InsnKind, count: usize) {
        assert!(
            self.compact_counts_active,
            "compact instruction count before compact ingest"
        );
        let record_buffer_idx = self.insn_to_record_buffer[kind as usize]
            .unwrap_or_else(|| panic!("ordinary instruction {kind:?} has no compact GPU circuit"));
        self.compact_record_counts[record_buffer_idx] = self.compact_record_counts
            [record_buffer_idx]
            .checked_add(count)
            .expect("compact instruction count overflow");
    }

    pub fn finish_compact_ingest(&mut self) {
        assert!(
            self.compact_counts_active,
            "compact instruction counts were not started"
        );
    }

    fn reset_record_buffers(&mut self) {
        for record_buffer in &mut self.circuit_record_buffers {
            record_buffer.clear();
        }
        self.compact_record_counts.fill(0);
        self.compact_counts_active = false;
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
            if self.compact_counts_active {
                self.compact_record_counts[idx]
            } else {
                self.circuit_record_buffers[idx].len()
            }
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

    fn record_count_for_kinds<E: ExtensionField, I: Instruction<E> + 'static>(&self) -> usize {
        let record_buffer_id = self
            .type_to_record_buffer
            .get(&TypeId::of::<I>())
            .expect("un-registered instruction circuit");
        if self.compact_counts_active {
            self.compact_record_counts[*record_buffer_id]
        } else {
            self.circuit_record_buffers[*record_buffer_id].len()
        }
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
            TensorImportBeginV1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorBusImportBeginEcallInstruction::<E>::name())
                .expect("unable to find TensorBus import"),
            TensorExportEndV1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorBusExportEndEcallInstruction::<E>::name())
                .expect("unable to find TensorBus export"),
            TensorHandleAttentionV1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorBusHandleAttentionEcallInstruction::<E>::name())
                .expect("unable to find TensorBus attention"),
            TensorHandleFfnV1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorBusHandleFfnEcallInstruction::<E>::name())
                .expect("unable to find TensorBus FFN"),
            #[cfg(not(feature = "llama-tiny"))]
            TensorProductionImportBeginV2Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorProductionImportAnchorInstruction::<E>::name())
                .expect("unable to find production import"),
            #[cfg(not(feature = "llama-tiny"))]
            TensorProductionAttentionV2Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorProductionAttentionAnchorInstruction::<E>::name())
                .expect("unable to find production attention"),
            #[cfg(not(feature = "llama-tiny"))]
            TensorProductionExportEndV2Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorProductionExportAnchorInstruction::<E>::name())
                .expect("unable to find production export"),
            TensorMatMulV1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorMatMulCoreInstruction::<E>::name())
                .expect("unable to find name"),
            #[cfg(feature = "llama-tiny")]
            TensorBatchedMatMul2x2V1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorBatchedMatMulCoreInstruction::<E>::name())
                .expect("unable to find tiny batched MatMul name"),
            ceno_emul::tensor::TENSOR_MATMUL_HIDDEN_V1 => *self
                .ecall_cells_map
                .get(&TensorMatMulHiddenFinalizeInstruction::<E>::name())
                .expect("unable to find production hidden name"),
            ceno_emul::tensor::TENSOR_MATMUL_INTERMEDIATE_V1 => *self
                .ecall_cells_map
                .get(&TensorMatMulIntermediateFinalizeInstruction::<E>::name())
                .expect("unable to find production intermediate name"),
            ceno_emul::tensor::TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1 => *self
                .ecall_cells_map
                .get(&TensorMatMulGate5SmallHiddenFinalizeInstruction::<E>::name())
                .expect("unable to find Gate-5 small production hidden name"),
            TensorRmsLookupV1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorRmsLookupCoreInstruction::<E>::name())
                .expect("unable to find name"),
            TensorAttentionReducedV1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorAttentionReducedCoreInstruction::<E>::name())
                .expect("unable to find name"),
            TensorAttentionBlockReducedV1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorAttentionBlockReducedCoreInstruction::<E>::name())
                .expect("unable to find fused attention name"),
            TensorFfnBlockReducedV1Spec::CODE => *self
                .ecall_cells_map
                .get(&TensorFfnBlockReducedCoreInstruction::<E>::name())
                .expect("unable to find fused FFN name"),
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

#[cfg(test)]
mod compact_dispatch_tests {
    use super::*;
    use ff_ext::BabyBearExt4;

    fn one_add_buffer() -> InstructionDispatchCtx {
        let mut kinds = vec![None; InsnKind::COUNT];
        kinds[InsnKind::ADD as usize] = Some(0);
        InstructionDispatchCtx::new(
            1,
            kinds,
            HashMap::from([(TypeId::of::<AddInstruction<BabyBearExt4>>(), 0)]),
        )
    }

    #[test]
    fn compact_counts_do_not_materialize_ordinals_and_reset_per_shard() {
        let mut dispatch = one_add_buffer();
        dispatch.begin_compact_ingest();
        dispatch.ingest_compact_count(InsnKind::ADD, 7);
        dispatch.ingest_compact_count(InsnKind::ADD, 5);
        dispatch.finish_compact_ingest();

        assert_eq!(dispatch.count_kind(InsnKind::ADD), 12);
        assert_eq!(
            dispatch.record_count_for_kinds::<BabyBearExt4, AddInstruction<BabyBearExt4>>(),
            12
        );
        assert!(dispatch.circuit_record_buffers[0].is_empty());

        dispatch.begin_shard();
        assert!(!dispatch.compact_counts_active);
        assert_eq!(dispatch.count_kind(InsnKind::ADD), 0);
    }

    #[test]
    #[should_panic(expected = "compact instruction counts started twice")]
    fn compact_counts_reject_duplicate_begin() {
        let mut dispatch = one_add_buffer();
        dispatch.begin_compact_ingest();
        dispatch.begin_compact_ingest();
    }

    #[test]
    #[should_panic(expected = "compact instruction count overflow")]
    fn compact_counts_reject_overflow() {
        let mut dispatch = one_add_buffer();
        dispatch.begin_compact_ingest();
        dispatch.compact_record_counts[0] = usize::MAX;
        dispatch.ingest_compact_count(InsnKind::ADD, 1);
    }
}
