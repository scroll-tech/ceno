use crate::{Cycle, RegIdx, Tracer, VMState, Word, WordAddr, WriteOp};
use anyhow::Result;

pub mod bn254;
pub mod keccak_permute;
pub mod keccak_xorin;
pub mod phantom;
mod prepass;
pub mod pubio_commit;
#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
pub(crate) mod pure;
pub mod secp256k1;
pub(crate) mod secp256r1;
pub mod sha256;
pub mod tensor;
pub mod uint256;
// Using the same function codes as sp1:
// https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/core/executor/src/syscalls/code.rs

pub use ceno_syscall::{
    BLS12381_ADD, BLS12381_DECOMPRESS, BLS12381_DOUBLE, BN254_ADD, BN254_DOUBLE, BN254_FP_ADD,
    BN254_FP_MUL, BN254_FP2_ADD, BN254_FP2_MUL, KECCAK_PERMUTE, KECCAK_XORIN, PHANTOM_LOG_PC_CYCLE,
    PUB_IO_COMMIT, SECP256K1_ADD, SECP256K1_DECOMPRESS, SECP256K1_DOUBLE, SECP256K1_SCALAR_INVERT,
    SECP256R1_ADD, SECP256R1_DECOMPRESS, SECP256R1_DOUBLE, SECP256R1_SCALAR_INVERT, SHA_EXTEND,
    STATE_CONTINUATION, UINT256_MUL,
};
pub use pubio_commit::PubIoCommitSpec;

pub trait SyscallSpec {
    const NAME: &'static str;

    const REG_OPS_COUNT: usize;
    const MEM_OPS_COUNT: usize;
    const CODE: u32;

    const HAS_LOOKUPS: bool = false;

    const GKR_OUTPUTS: usize = 0;
}

/// Trace the inputs and effects of a syscall.
pub fn handle_syscall<T: Tracer>(
    vm: &mut VMState<T>,
    function_code: u32,
) -> Result<SyscallEffects> {
    if vm.tracer().pure_aot_prepass()
        && let Some(result) = prepass::handle_heavy_syscall(vm, function_code)
    {
        return result;
    }
    match function_code {
        KECCAK_PERMUTE => Ok(keccak_permute::keccak_permute(vm)),
        KECCAK_XORIN => Ok(keccak_xorin::keccak_xorin(vm)),
        SECP256K1_ADD => Ok(secp256k1::secp256k1_add(vm)),
        SECP256K1_DOUBLE => Ok(secp256k1::secp256k1_double(vm)),
        SECP256K1_DECOMPRESS => Ok(secp256k1::secp256k1_decompress(vm)),
        SECP256K1_SCALAR_INVERT => Ok(secp256k1::secp256k1_invert(vm)),
        SECP256R1_ADD => Ok(secp256r1::secp256r1_add(vm)),
        SECP256R1_DOUBLE => Ok(secp256r1::secp256r1_double(vm)),
        SECP256R1_SCALAR_INVERT => Ok(secp256r1::secp256r1_invert(vm)),
        SHA_EXTEND => Ok(sha256::extend(vm)),
        BN254_ADD => Ok(bn254::bn254_add(vm)),
        BN254_DOUBLE => Ok(bn254::bn254_double(vm)),
        BN254_FP_ADD => Ok(bn254::bn254_fp_add(vm)),
        BN254_FP_MUL => Ok(bn254::bn254_fp_mul(vm)),
        BN254_FP2_ADD => Ok(bn254::bn254_fp2_add(vm)),
        BN254_FP2_MUL => Ok(bn254::bn254_fp2_mul(vm)),
        UINT256_MUL => Ok(uint256::uint256_mul(vm)),
        PUB_IO_COMMIT => Ok(pubio_commit::pubio_commit(vm)),
        crate::tensor::TENSOR_MATMUL_V1 => tensor::tensor_matmul_v1(vm),
        #[cfg(feature = "llama-tiny")]
        crate::tensor::TENSOR_BATCHED_MATMUL_2X2_V1 => tensor::tensor_batched_matmul_2x2_v1(vm),
        crate::tensor::TENSOR_MATMUL_HIDDEN_V1 => tensor::tensor_matmul_hidden_v1(vm),
        crate::tensor::TENSOR_MATMUL_INTERMEDIATE_V1 => tensor::tensor_matmul_intermediate_v1(vm),
        crate::tensor::TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1 => {
            tensor::tensor_matmul_gate5_small_hidden_v1(vm)
        }
        crate::tensor::TENSOR_RMS_LOOKUP_V1 => tensor::tensor_rms_lookup_v1(vm),
        crate::tensor::TENSOR_ATTENTION_REDUCED_V1 => tensor::tensor_attention_reduced_v1(vm),
        crate::tensor::TENSOR_ATTENTION_BLOCK_REDUCED_V1 => {
            tensor::tensor_attention_block_reduced_v1(vm)
        }
        crate::tensor::TENSOR_FFN_BLOCK_REDUCED_V1 => tensor::tensor_ffn_block_reduced_v1(vm),
        crate::tensor::TENSOR_IMPORT_BEGIN_V1 => tensor::tensor_import_begin_v1(vm),
        crate::tensor::TENSOR_EXPORT_END_V1 => tensor::tensor_export_end_v1(vm),
        crate::tensor::TENSOR_HANDLE_ATTENTION_V1 => tensor::tensor_handle_attention_v1(vm),
        crate::tensor::TENSOR_HANDLE_FFN_V1 => tensor::tensor_handle_ffn_v1(vm),
        crate::tensor::TENSOR_PRODUCTION_IMPORT_BEGIN_V2 => {
            tensor::tensor_production_import_begin_v2(vm)
        }
        crate::tensor::TENSOR_PRODUCTION_STAGE_V2 => tensor::tensor_production_stage_v2(vm),
        crate::tensor::TENSOR_PRODUCTION_EXPORT_END_V2 => {
            tensor::tensor_production_export_end_v2(vm)
        }

        // phantom syscall
        PHANTOM_LOG_PC_CYCLE => Ok(phantom::log_pc_cycle(vm)),
        // TODO: introduce error types.
        _ => Err(anyhow::anyhow!("Unknown syscall: {}", function_code)),
    }
}

/// A syscall event, available to the circuit witness generators.
/// TODO: separate mem_ops into two stages: reads-and-writes
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyscallWitness {
    pub mem_ops: Vec<WriteOp>,
    /// Real RAM ranges retained by metadata-only preflight syscalls. They are
    /// not part of the proof witness; full replay reconstructs `mem_ops`.
    pub(crate) mem_access_ranges: Vec<std::ops::Range<crate::WordAddr>>,
    pub reg_ops: Vec<WriteOp>,
    pub mem_future_access: Vec<u8>,
    pub reg_future_access: Vec<u8>,
    /// TensorBus is an independent offline relation; these compact records are
    /// deliberately not RAM accesses.
    pub tensor_bus_records: Vec<crate::tensor::bus::TensorBusRecord>,
    /// Canonical fixed-width ABI tuple for the proof-side TensorBus consumer.
    /// It deliberately mirrors the custom record emitted by the constrained
    /// ECALL chip: tag, syscall code, then twenty ABI fields.
    pub tensor_bus_event: Option<[u32; 25]>,
    /// Global cycle of `tensor_bus_event`.  Proof assignment normalizes this
    /// into the owning shard's local cycle before consuming the event.
    pub tensor_bus_event_cycle: Option<Cycle>,
    /// Tiny-only complete matrix payload consumed by the batched Core replay.
    #[cfg(feature = "llama-tiny")]
    pub tensor_batched_matmul_2x2: Option<crate::tensor::TensorBatchedMatMul2x2Witness>,
    /// V2 resident operator payload consumed by Tensor-space, HintRef, and the
    /// shared batched-matrix Core.
    #[cfg(feature = "llama-tiny")]
    pub tensor_resident_matmul: Option<crate::tensor::TensorResidentMatMulWitness>,
    /// Provider-recorded complete layer snapshot, attached to the second call
    /// of the descriptor-v2 attention/FFN pair.
    #[cfg(feature = "llama-tiny")]
    pub tensor_llama_tiny_layer: Option<crate::tensor::TensorLlamaTinyLayerWitness>,
    /// V2 import/export value boundary for the Tensor-space product relation.
    #[cfg(feature = "llama-tiny")]
    pub tensor_resident_boundary: Option<crate::tensor::TensorResidentBoundaryWitness>,
    pub tensor_production_boundary: Option<crate::tensor::TensorProductionBoundaryWitness>,
    pub tensor_production_full_layer: Option<crate::tensor::TensorProductionFullLayerWitness>,
}

impl SyscallWitness {
    fn new(mem_ops: Vec<WriteOp>, reg_ops: Vec<WriteOp>) -> SyscallWitness {
        SyscallWitness {
            mem_future_access: vec![0; mem_ops.len()],
            reg_future_access: vec![0; reg_ops.len()],
            mem_ops,
            mem_access_ranges: Vec::new(),
            reg_ops,
            tensor_bus_records: Vec::new(),
            tensor_bus_event: None,
            tensor_bus_event_cycle: None,
            #[cfg(feature = "llama-tiny")]
            tensor_batched_matmul_2x2: None,
            #[cfg(feature = "llama-tiny")]
            tensor_resident_matmul: None,
            #[cfg(feature = "llama-tiny")]
            tensor_llama_tiny_layer: None,
            #[cfg(feature = "llama-tiny")]
            tensor_resident_boundary: None,
            tensor_production_boundary: None,
            tensor_production_full_layer: None,
        }
    }
}

/// The effects of a syscall to apply on the VM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallEffects {
    /// The witness being built. Get it with `finalize`.
    witness: SyscallWitness,

    /// The next PC after the syscall. Defaults to the next instruction.
    pub next_pc: Option<u32>,
}

impl SyscallEffects {
    /// Iterate over the register values after the syscall.
    pub fn iter_reg_values(&self) -> impl Iterator<Item = (RegIdx, Word)> + '_ {
        self.witness
            .reg_ops
            .iter()
            .map(|op| (op.register_index(), op.value.after))
    }

    /// Iterate over the memory values after the syscall.
    pub fn iter_mem_values(&self) -> impl Iterator<Item = (WordAddr, Word)> + '_ {
        self.witness
            .mem_ops
            .iter()
            .map(|op| (op.addr, op.value.after))
    }

    pub(crate) fn iter_mem_ops_mut(&mut self) -> impl Iterator<Item = &mut WriteOp> {
        self.witness.mem_ops.iter_mut()
    }

    pub(crate) fn iter_mem_access_ranges(
        &self,
    ) -> impl Iterator<Item = &std::ops::Range<crate::WordAddr>> {
        self.witness.mem_access_ranges.iter()
    }

    pub(crate) fn push_mem_access_range(&mut self, range: std::ops::Range<crate::WordAddr>) {
        self.witness.mem_access_ranges.push(range);
    }

    /// Keep track of register cycles. Memory cycles are finalized by `VMState`
    /// while it updates the packed memory cells.
    pub fn finalize<T: Tracer>(mut self, tracer: &mut T) -> SyscallWitness {
        for op in &mut self.witness.reg_ops {
            op.previous_cycle = tracer.track_access(op.addr, T::SUBCYCLE_RD);
        }
        self.witness
    }
}
