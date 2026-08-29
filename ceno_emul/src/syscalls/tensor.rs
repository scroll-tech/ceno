//! Emulator implementation of the bounded Gate-2 tensor MatMul syscall.

use anyhow::{Result, ensure};

use crate::{
    ByteAddr, Change, EmuContext, Platform, Tracer, VMState, WriteOp,
    tensor::{TENSOR_ABI_V1, TensorMatMulDescV1, ZKLLM_FIXED_V1, execute_committed_matmul},
    utils::MemoryView,
};

use super::{SyscallEffects, SyscallSpec, SyscallWitness};

pub const TENSOR_DESC_WORDS: usize = 16;
pub const TENSOR_INPUT_WORDS: usize = 6;
pub const TENSOR_OUTPUT_WORDS: usize = 4;
pub const TENSOR_ROOT_WORDS: usize = 8;
pub const TENSOR_SIGNATURE_2X3X2: u32 = 7;
pub const TENSOR_RESCALE_SHIFT: u32 = 16;

const TENSOR_TRANSFER_DESC_WORDS: usize = 8;
const TENSOR_META_WORDS: usize = 4;
const TENSOR_HANDLE_WORDS: usize = 4;

fn tensor_bus_event(code: u32, fields: impl IntoIterator<Item = u32>) -> [u32; 25] {
    let mut event = [0; 25];
    event[0] = 3; // CustomRWTag::TensorBusEvent
    event[1] = code;
    for (slot, word) in event[2..].iter_mut().zip(fields) {
        *slot = word;
    }
    event
}

/// The reduced Llama topology carries one `[sequence=2, hidden=4]` activation
/// between its attention and FFN blocks. The default profile reserves one
/// Llama-2-7B hidden activation (4096 i32 words). The handle ABI has a
/// feature-selected fixed width so its import/export RAM effects can be
/// represented by fixed-size ECALL AIR traces.
#[cfg(feature = "llama-tiny")]
pub const TENSOR_BUS_FIXED_TRANSFER_WORDS: u32 = 4;
#[cfg(not(feature = "llama-tiny"))]
pub const TENSOR_BUS_FIXED_TRANSFER_WORDS: u32 = 4096;

fn require_fixed_tensor_bus_words(words: u32) -> Result<()> {
    ensure!(
        words == TENSOR_BUS_FIXED_TRANSFER_WORDS,
        "TensorBus transfer length must be {TENSOR_BUS_FIXED_TRANSFER_WORDS} words for the selected profile"
    );
    Ok(())
}

fn tensor_bus_reg_ops(desc_ptr: u32) -> Vec<WriteOp> {
    vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(desc_ptr, desc_ptr),
        0,
    )]
}

fn tensor_bus_meta(words: [u32; TENSOR_META_WORDS]) -> Result<crate::tensor::bus::TensorBusMeta> {
    ensure!(words[3] == 0, "TensorBus metadata reserved word is nonzero");
    ensure!(words[1] != 0, "TensorBus shape is empty");
    Ok(crate::tensor::bus::TensorBusMeta {
        byte_len: words[0] as usize,
        shape: vec![words[1]],
        quantization_id: words[2],
    })
}

fn tensor_bus_handle(
    words: [u32; TENSOR_HANDLE_WORDS],
) -> Result<crate::tensor::bus::TensorHandle> {
    ensure!(words[3] == 0, "TensorBus handle reserved word is nonzero");
    Ok(crate::tensor::bus::TensorHandle {
        tensor_id: u64::from(words[0]) | (u64::from(words[1]) << 32),
        version: words[2],
    })
}

fn tensor_bus_words<T: Tracer>(
    vm: &VMState<T>,
    ptr: u32,
    words: usize,
) -> Result<(Vec<u32>, Vec<WriteOp>)> {
    ensure!(
        ptr.is_multiple_of(4),
        "TensorBus pointer is not word aligned"
    );
    let start = ByteAddr(ptr).waddr();
    Ok((0..words)
        .map(|index| {
            let addr = start + index;
            let value = vm.peek_memory(addr);
            (
                value,
                WriteOp {
                    addr,
                    value: Change::new(value, value),
                    previous_cycle: 0,
                },
            )
        })
        .unzip())
}

pub fn tensor_import_begin_v1<T: Tracer>(vm: &mut VMState<T>) -> Result<SyscallEffects> {
    let desc_ptr = vm.peek_register(Platform::reg_arg0());
    let desc = MemoryView::<_, TENSOR_TRANSFER_DESC_WORDS>::new(vm, desc_ptr);
    let words = desc.words();
    let desc_ops = desc.mem_ops();
    ensure!(
        words[0] == TENSOR_ABI_V1 && words[1] == 0 && words[7] == 0,
        "invalid TensorBus import descriptor"
    );
    ensure!(
        words[5] == TENSOR_META_WORDS as u32,
        "unsupported TensorBus metadata length"
    );
    let meta_view = MemoryView::<_, TENSOR_META_WORDS>::new(vm, words[4]);
    let meta_words = meta_view.words();
    let meta = tensor_bus_meta(meta_words)?;
    let meta_ops = meta_view.mem_ops();
    ensure!(
        meta.byte_len == words[3] as usize * 4,
        "TensorBus import length mismatch"
    );
    require_fixed_tensor_bus_words(words[3])?;
    let (input, input_ops) = tensor_bus_words(vm, words[2], words[3] as usize)?;
    let input = input
        .into_iter()
        .map(|word| word as i32)
        .collect::<Vec<_>>();
    let (handle, records) = vm.tensor_bus_import_begin(meta, input.clone())?;
    #[cfg(feature = "tensor-cuda")]
    vm.tensor_bus_resident_import(handle, &input)?;
    let mut handle_view = MemoryView::<_, TENSOR_HANDLE_WORDS>::new(vm, words[6]);
    handle_view.write([
        handle.tensor_id as u32,
        (handle.tensor_id >> 32) as u32,
        handle.version,
        0,
    ]);
    let mut witness = SyscallWitness::new(
        desc_ops
            .into_iter()
            .chain(meta_ops)
            .chain(input_ops)
            .chain(handle_view.mem_ops())
            .collect(),
        tensor_bus_reg_ops(desc_ptr),
    );
    witness.tensor_bus_records = records;
    witness.tensor_bus_event = Some(tensor_bus_event(
        TensorImportBeginV1Spec::CODE,
        words
            .into_iter()
            .chain(meta_words)
            .chain([
                handle.tensor_id as u32,
                (handle.tensor_id >> 32) as u32,
                handle.version,
                0,
            ])
            .chain(std::iter::repeat_n(0, 4)),
    ));
    witness.tensor_bus_event_cycle = Some(vm.tracer().cycle());
    Ok(SyscallEffects {
        witness,
        next_pc: None,
    })
}

pub fn tensor_export_end_v1<T: Tracer>(vm: &mut VMState<T>) -> Result<SyscallEffects> {
    let desc_ptr = vm.peek_register(Platform::reg_arg0());
    let desc = MemoryView::<_, TENSOR_TRANSFER_DESC_WORDS>::new(vm, desc_ptr);
    let words = desc.words();
    let desc_ops = desc.mem_ops();
    ensure!(
        words[0] == TENSOR_ABI_V1 && words[1] == 0 && words[7] == 0,
        "invalid TensorBus export descriptor"
    );
    ensure!(
        words[6] == TENSOR_META_WORDS as u32,
        "unsupported TensorBus metadata length"
    );
    let handle_view = MemoryView::<_, TENSOR_HANDLE_WORDS>::new(vm, words[2]);
    let handle = tensor_bus_handle(handle_view.words())?;
    let handle_ops = handle_view.mem_ops();
    let meta_view = MemoryView::<_, TENSOR_META_WORDS>::new(vm, words[5]);
    let meta_words = meta_view.words();
    let meta = tensor_bus_meta(meta_words)?;
    let meta_ops = meta_view.mem_ops();
    #[cfg(not(feature = "tensor-cuda"))]
    let (output, records) = vm.tensor_bus_export_end(handle)?;
    #[cfg(feature = "tensor-cuda")]
    let (output, records) = {
        let (output, records) = vm.tensor_bus_export(handle)?;
        let resident_output = vm.tensor_bus_resident_export(handle)?;
        if resident_output != output {
            let index = resident_output
                .iter()
                .zip(&output)
                .position(|(device, host)| device != host)
                .expect("unequal vectors must have a differing word");
            anyhow::bail!(
                "TensorBus CUDA output disagrees with CPU relation at word {index}: device={} cpu={}",
                resident_output[index],
                output[index]
            );
        }
        vm.tensor_bus_end()?;
        (output, records)
    };
    ensure!(
        meta.byte_len == output.len() * 4 && words[4] as usize == output.len(),
        "TensorBus export length mismatch"
    );
    require_fixed_tensor_bus_words(words[4])?;
    let (before, mut output_ops) = tensor_bus_words(vm, words[3], output.len())?;
    for (op, value) in output_ops.iter_mut().zip(output) {
        op.value.after = value as u32;
    }
    let _ = before;
    let mut witness = SyscallWitness::new(
        desc_ops
            .into_iter()
            .chain(handle_ops)
            .chain(meta_ops)
            .chain(output_ops)
            .collect(),
        tensor_bus_reg_ops(desc_ptr),
    );
    witness.tensor_bus_records = records;
    witness.tensor_bus_event = Some(tensor_bus_event(
        TensorExportEndV1Spec::CODE,
        words
            .into_iter()
            .chain(meta_words)
            .chain([
                handle.tensor_id as u32,
                (handle.tensor_id >> 32) as u32,
                handle.version,
                0,
            ])
            .chain(std::iter::repeat_n(0, 4)),
    ));
    witness.tensor_bus_event_cycle = Some(vm.tracer().cycle());
    Ok(SyscallEffects {
        witness,
        next_pc: None,
    })
}

fn tensor_handle_op_v1<T: Tracer>(vm: &mut VMState<T>, code: u32) -> Result<SyscallEffects> {
    let desc_ptr = vm.peek_register(Platform::reg_arg0());
    let desc = MemoryView::<_, TENSOR_TRANSFER_DESC_WORDS>::new(vm, desc_ptr);
    let words = desc.words();
    let desc_ops = desc.mem_ops();
    ensure!(
        words[0] == TENSOR_ABI_V1
            && words[1] == 0
            && words[5] == TENSOR_META_WORDS as u32
            && words[6] == 0
            && words[7] == 0,
        "invalid TensorBus handle operator descriptor"
    );
    let input_view = MemoryView::<_, TENSOR_HANDLE_WORDS>::new(vm, words[2]);
    let input_words = input_view.words();
    let input = tensor_bus_handle(input_words)?;
    let input_ops = input_view.mem_ops();
    let meta_view = MemoryView::<_, TENSOR_META_WORDS>::new(vm, words[4]);
    let meta_words = meta_view.words();
    let meta = tensor_bus_meta(meta_words)?;
    let meta_ops = meta_view.mem_ops();
    ensure!(
        meta.byte_len == TENSOR_BUS_FIXED_TRANSFER_WORDS as usize * 4,
        "TensorBus operator metadata length mismatch"
    );
    let transform = move |input: &[i32]| -> Result<Vec<i32>> {
        ensure!(
            input.len() == TENSOR_BUS_FIXED_TRANSFER_WORDS as usize,
            "TensorBus operator input length mismatch"
        );
        Ok(match code {
            crate::tensor::TENSOR_HANDLE_ATTENTION_V1 => {
                let hidden = input.len() / 2;
                input
                    .iter()
                    .enumerate()
                    .map(|(index, word)| {
                        if index < hidden {
                            *word
                        } else {
                            word.wrapping_add(input[index - hidden])
                        }
                    })
                    .collect()
            }
            crate::tensor::TENSOR_HANDLE_FFN_V1 => input
                .iter()
                .map(|word| word.wrapping_mul(2).wrapping_add(1))
                .collect(),
            _ => unreachable!("fixed TensorBus operator code"),
        })
    };
    let (output, records) = vm.tensor_bus_apply(input, meta, code, transform)?;
    #[cfg(feature = "tensor-cuda")]
    vm.tensor_bus_resident_apply(input, output, code)?;
    let mut output_view = MemoryView::<_, TENSOR_HANDLE_WORDS>::new(vm, words[3]);
    output_view.write([
        output.tensor_id as u32,
        (output.tensor_id >> 32) as u32,
        output.version,
        0,
    ]);
    let mut witness = SyscallWitness::new(
        desc_ops
            .into_iter()
            .chain(input_ops)
            .chain(meta_ops)
            .chain(output_view.mem_ops())
            .collect(),
        tensor_bus_reg_ops(desc_ptr),
    );
    witness.tensor_bus_records = records;
    // Internal resident layers are bound by their own constrained ECALL and
    // RAM witnesses.  TensorBus records only the import/export boundary, so
    // no intermediate opaque handle becomes a TensorBus Core event.
    Ok(SyscallEffects {
        witness,
        next_pc: None,
    })
}

pub fn tensor_handle_attention_v1<T: Tracer>(vm: &mut VMState<T>) -> Result<SyscallEffects> {
    tensor_handle_op_v1(vm, crate::tensor::TENSOR_HANDLE_ATTENTION_V1)
}

pub fn tensor_handle_ffn_v1<T: Tracer>(vm: &mut VMState<T>) -> Result<SyscallEffects> {
    tensor_handle_op_v1(vm, crate::tensor::TENSOR_HANDLE_FFN_V1)
}

pub struct TensorMatMulV1Spec;
pub struct TensorMatMulHiddenV1Spec;
pub struct TensorMatMulIntermediateV1Spec;
pub struct TensorRmsLookupV1Spec;
pub struct TensorAttentionReducedV1Spec;
pub struct TensorAttentionBlockReducedV1Spec;
pub struct TensorFfnBlockReducedV1Spec;
pub struct TensorImportBeginV1Spec;
pub struct TensorExportEndV1Spec;
pub struct TensorHandleAttentionV1Spec;
pub struct TensorHandleFfnV1Spec;

pub const ATTENTION_REDUCED_PROFILE_V1: u32 = 1;
pub const ATTENTION_RESCALE_SHIFT_Q20_V1: u32 = 20;
pub const ATTENTION_SOFTMAX_TABLE_REDUCED_V1: u32 = 0x4154_5401;
pub const ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1: [u32; 8] = [
    0x17d8_0ab1,
    0x05a1_1002,
    0x661c_9303,
    0x3f24_4404,
    0x019b_5505,
    0x70c2_6606,
    0x2dab_7707,
    0x4e31_8808,
];
pub const BLOCK_REDUCED_PROFILE_V1: u32 = 1;
pub const FFN_TABLE_REDUCED_V1: u32 = 0x4646_4e01;
pub const FFN_TABLE_COMMITMENT_V1: [u32; 8] = [
    0x51f1_0001,
    0x51f1_0002,
    0x51f1_0003,
    0x51f1_0004,
    0x51f1_0005,
    0x51f1_0006,
    0x51f1_0007,
    0x51f1_0008,
];

impl SyscallSpec for TensorAttentionBlockReducedV1Spec {
    const NAME: &'static str = "TENSOR_ATTENTION_BLOCK_REDUCED_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = 32 + 4 + 4 * 8 + 4;
    const CODE: u32 = crate::tensor::TENSOR_ATTENTION_BLOCK_REDUCED_V1;
}

impl SyscallSpec for TensorFfnBlockReducedV1Spec {
    const NAME: &'static str = "TENSOR_FFN_BLOCK_REDUCED_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = 32 + 4 + 3 * 8 + 4;
    const CODE: u32 = crate::tensor::TENSOR_FFN_BLOCK_REDUCED_V1;
}

impl SyscallSpec for TensorAttentionReducedV1Spec {
    const NAME: &'static str = "TENSOR_ATTENTION_REDUCED_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = 32 + 12 + 4;
    const CODE: u32 = crate::tensor::TENSOR_ATTENTION_REDUCED_V1;
}

pub const RMS_INV_LOOKUP_V1: u32 = 1;
pub const RMS_INV_TABLE_REDUCED_V1: u32 = 0x524d_5301;
pub const RMS_REDUCED_ENTRIES: [(i32, i32); 10] = [
    (-10, -10),
    (-7, -7),
    (-4, -4),
    (-2, -2),
    (0, 0),
    (1, 1),
    (2, 2),
    (3, 3),
    (5, 5),
    (7, 7),
];
pub const SWIGLU_LOOKUP_V1: u32 = 2;
pub const SWIGLU_TABLE_REDUCED_V1: u32 = 0x5357_4701;
pub const ROPE_LOOKUP_Q16_REDUCED_V1: u32 = 3;
pub const ROPE_TABLE_REDUCED_V1: u32 = 0x524f_5001;
pub const RESIDUAL_LOOKUP_PACKED_REDUCED_V1: u32 = 4;
pub const RESIDUAL_TABLE_REDUCED_V1: u32 = 0x5245_5301;
pub const RESIDUAL_REDUCED_ENTRIES: [(i32, i32); 12] = [
    (561, 2),
    (462, -4),
    (626, 5),
    (397, -7),
    (628, 7),
    (394, -10),
    (592, 2),
    (400, -4),
    (688, 5),
    (304, -7),
    (752, 7),
    (208, -10),
];

impl SyscallSpec for TensorRmsLookupV1Spec {
    const NAME: &'static str = "TENSOR_RMS_LOOKUP_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = 10;
    const CODE: u32 = crate::tensor::TENSOR_RMS_LOOKUP_V1;
}

impl SyscallSpec for TensorMatMulV1Spec {
    const NAME: &'static str = "TENSOR_MATMUL_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize =
        TENSOR_DESC_WORDS + TENSOR_INPUT_WORDS + TENSOR_ROOT_WORDS + TENSOR_OUTPUT_WORDS;
    const CODE: u32 = crate::tensor::TENSOR_MATMUL_V1;
}

impl SyscallSpec for TensorImportBeginV1Spec {
    const NAME: &'static str = "TENSOR_IMPORT_BEGIN_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = TENSOR_TRANSFER_DESC_WORDS
        + TENSOR_META_WORDS
        + TENSOR_BUS_FIXED_TRANSFER_WORDS as usize
        + TENSOR_HANDLE_WORDS;
    const CODE: u32 = crate::tensor::TENSOR_IMPORT_BEGIN_V1;
}

impl SyscallSpec for TensorExportEndV1Spec {
    const NAME: &'static str = "TENSOR_EXPORT_END_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = TENSOR_TRANSFER_DESC_WORDS
        + TENSOR_HANDLE_WORDS
        + TENSOR_META_WORDS
        + TENSOR_BUS_FIXED_TRANSFER_WORDS as usize;
    const CODE: u32 = crate::tensor::TENSOR_EXPORT_END_V1;
}

impl SyscallSpec for TensorHandleAttentionV1Spec {
    const NAME: &'static str = "TENSOR_HANDLE_ATTENTION_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize =
        TENSOR_TRANSFER_DESC_WORDS + TENSOR_HANDLE_WORDS + TENSOR_META_WORDS + TENSOR_HANDLE_WORDS;
    const CODE: u32 = crate::tensor::TENSOR_HANDLE_ATTENTION_V1;
}

impl SyscallSpec for TensorHandleFfnV1Spec {
    const NAME: &'static str = "TENSOR_HANDLE_FFN_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize =
        TENSOR_TRANSFER_DESC_WORDS + TENSOR_HANDLE_WORDS + TENSOR_META_WORDS + TENSOR_HANDLE_WORDS;
    const CODE: u32 = crate::tensor::TENSOR_HANDLE_FFN_V1;
}

impl SyscallSpec for TensorMatMulHiddenV1Spec {
    const NAME: &'static str = "TENSOR_MATMUL_HIDDEN_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = 16 + 4096 + 8 + 1;
    const CODE: u32 = crate::tensor::TENSOR_MATMUL_HIDDEN_V1;
}

impl SyscallSpec for TensorMatMulIntermediateV1Spec {
    const NAME: &'static str = "TENSOR_MATMUL_INTERMEDIATE_V1";
    const REG_OPS_COUNT: usize = 1;
    const MEM_OPS_COUNT: usize = 16 + 11008 + 8 + 1;
    const CODE: u32 = crate::tensor::TENSOR_MATMUL_INTERMEDIATE_V1;
}

fn production_descriptor(words: [u32; 16]) -> ceno_rt::tensor::TensorProductionMatMulDescV1 {
    ceno_rt::tensor::TensorProductionMatMulDescV1 {
        abi_version: words[0],
        commitment_profile: words[1],
        quantization_id: words[2],
        signature_id: words[3],
        input_ptr: words[4],
        output_ptr: words[5],
        weight_tensor_id: words[6],
        first_weight_tile: words[7],
        weight_tile_count: words[8],
        rescale_shift: words[9],
        model_root_ptr: words[10],
        input_stride: words[11],
        output_stride: words[12],
        reserved: [words[13], words[14], words[15]],
    }
}

fn tensor_production_matmul_v1<T: Tracer, const K: usize>(
    vm: &VMState<T>,
    expected: crate::tensor::production::ProductionMatMulSignature,
) -> Result<SyscallEffects> {
    let desc_ptr = vm.peek_register(Platform::reg_arg0());
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(desc_ptr, desc_ptr),
        0,
    )];
    let desc_view = MemoryView::<_, 16>::new(vm, desc_ptr);
    let guest = production_descriptor(desc_view.words());
    let desc = crate::tensor::production::ProductionMatMulCellDesc::from_guest(&guest)?;
    ensure!(
        desc.signature == expected && desc.signature.k() == K,
        "ecall/signature mismatch"
    );
    let input_view = MemoryView::<_, K>::new(vm, guest.input_ptr);
    // The root is an ordered public boundary consumed by the proof-side
    // manifest relation. Emulator execution reads it but never substitutes a
    // provider-controlled value for guest memory.
    let root_view = MemoryView::<_, 8>::new(vm, guest.model_root_ptr);
    let input = input_view.words().map(|x| x as i32);
    let provider = vm
        .tensor_witness_provider()
        .ok_or_else(|| anyhow::anyhow!("tensor witness provider is not installed"))?;
    let (output, _, _ordered_roots) =
        crate::tensor::production::execute_sparse_production_cell(provider, desc, &input)?;
    let mut output_view = MemoryView::<_, 1>::new(vm, guest.output_ptr);
    output_view.write([output as u32]);
    Ok(SyscallEffects {
        witness: SyscallWitness::new(
            desc_view
                .mem_ops()
                .into_iter()
                .chain(input_view.mem_ops())
                .chain(root_view.mem_ops())
                .chain(output_view.mem_ops())
                .collect(),
            reg_ops,
        ),
        next_pc: None,
    })
}

pub fn tensor_matmul_hidden_v1<T: Tracer>(vm: &VMState<T>) -> Result<SyscallEffects> {
    tensor_production_matmul_v1::<T, 4096>(
        vm,
        crate::tensor::production::ProductionMatMulSignature::HiddenK4096,
    )
}

pub fn tensor_matmul_intermediate_v1<T: Tracer>(vm: &VMState<T>) -> Result<SyscallEffects> {
    tensor_production_matmul_v1::<T, 11008>(
        vm,
        crate::tensor::production::ProductionMatMulSignature::IntermediateK11008,
    )
}

/// Gate-5-only compact production-topology syscall.  It deliberately shares
/// the ordinary descriptor/input/root/output memory witness layout with the
/// 7B hidden projection and expands to one physical K1024 tile plus finalize.
pub fn tensor_matmul_gate5_small_hidden_v1<T: Tracer>(vm: &VMState<T>) -> Result<SyscallEffects> {
    tensor_production_matmul_v1::<T, { crate::tensor::production::GATE5_SMALL_HIDDEN_K }>(
        vm,
        crate::tensor::production::ProductionMatMulSignature::Gate5SmallHiddenK64,
    )
}

fn descriptor(words: [u32; TENSOR_DESC_WORDS]) -> TensorMatMulDescV1 {
    TensorMatMulDescV1 {
        abi_version: words[0],
        flags: words[1],
        signature_id: words[2],
        quantization_id: words[3],
        input_ptr: words[4],
        output_ptr: words[5],
        m: words[6],
        k: words[7],
        n: words[8],
        input_stride: words[9],
        output_stride: words[10],
        weight_tensor_id: words[11],
        weight_tile_id: words[12],
        model_root_ptr: words[13],
        reserved: [words[14], words[15]],
    }
}

pub fn tensor_matmul_v1<T: Tracer>(vm: &VMState<T>) -> Result<SyscallEffects> {
    let desc_ptr = vm.peek_register(Platform::reg_arg0());
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(desc_ptr, desc_ptr),
        0,
    )];

    let desc_view = MemoryView::<_, TENSOR_DESC_WORDS>::new(vm, desc_ptr);
    let desc = descriptor(desc_view.words());
    ensure!(desc.abi_version == TENSOR_ABI_V1, "unsupported tensor ABI");
    ensure!(
        matches!(desc.flags, 0 | crate::tensor::GATE2_LINEAR_COMMITMENT_V1),
        "unsupported tensor commitment profile"
    );
    ensure!(
        desc.signature_id == TENSOR_SIGNATURE_2X3X2,
        "unsupported tensor signature"
    );
    ensure!(
        (desc.m, desc.k, desc.n) == (2, 3, 2),
        "tensor signature shape mismatch"
    );
    ensure!(
        desc.quantization_id == ZKLLM_FIXED_V1,
        "unsupported quantization profile"
    );

    let input_view = MemoryView::<_, TENSOR_INPUT_WORDS>::new(vm, desc.input_ptr);
    let root_view = MemoryView::<_, TENSOR_ROOT_WORDS>::new(vm, desc.model_root_ptr);
    let root = root_view
        .words()
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .expect("eight words form a root");
    let input = input_view.words().map(|word| word as i32);
    let provider = vm
        .tensor_witness_provider()
        .ok_or_else(|| anyhow::anyhow!("tensor witness provider is not installed"))?;
    let (output, _) =
        execute_committed_matmul(provider, &desc, &root, &input, TENSOR_RESCALE_SHIFT)?;

    let mut output_view = MemoryView::<_, TENSOR_OUTPUT_WORDS>::new(vm, desc.output_ptr);
    output_view.write(
        output
            .into_iter()
            .map(|value| value as u32)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );

    let mem_ops = desc_view
        .mem_ops()
        .into_iter()
        .chain(input_view.mem_ops())
        .chain(root_view.mem_ops())
        .chain(output_view.mem_ops())
        .collect();
    Ok(SyscallEffects {
        witness: SyscallWitness::new(mem_ops, reg_ops),
        next_pc: None,
    })
}

pub fn tensor_rms_lookup_v1<T: Tracer>(vm: &VMState<T>) -> Result<SyscallEffects> {
    const DESC_WORDS: usize = 8;
    let desc_ptr = vm.peek_register(Platform::reg_arg0());
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(desc_ptr, desc_ptr),
        0,
    )];
    let desc_view = MemoryView::<_, DESC_WORDS>::new(vm, desc_ptr);
    let words = desc_view.words();
    ensure!(words[0] == TENSOR_ABI_V1, "unsupported tensor ABI");
    ensure!(
        matches!(
            (words[1], words[2]),
            (RMS_INV_LOOKUP_V1, RMS_INV_TABLE_REDUCED_V1)
                | (SWIGLU_LOOKUP_V1, SWIGLU_TABLE_REDUCED_V1)
                | (ROPE_LOOKUP_Q16_REDUCED_V1, ROPE_TABLE_REDUCED_V1)
                | (RESIDUAL_LOOKUP_PACKED_REDUCED_V1, RESIDUAL_TABLE_REDUCED_V1)
        ),
        "unsupported tensor scalar lookup profile/table"
    );
    ensure!(words[5..] == [0; 3], "nonzero RMS reserved word");
    let input_view = MemoryView::<_, 1>::new(vm, words[3]);
    let input = input_view.words()[0] as i32;
    let entries: &[(i32, i32)] = if words[1] == RESIDUAL_LOOKUP_PACKED_REDUCED_V1 {
        &RESIDUAL_REDUCED_ENTRIES
    } else {
        &RMS_REDUCED_ENTRIES
    };
    let output = entries
        .iter()
        .find_map(|(candidate, output)| (*candidate == input).then_some(*output))
        .ok_or_else(|| anyhow::anyhow!("reduced RMS fixed lookup miss"))?;
    let mut output_view = MemoryView::<_, 1>::new(vm, words[4]);
    output_view.write([output as u32]);
    Ok(SyscallEffects {
        witness: SyscallWitness::new(
            desc_view
                .mem_ops()
                .into_iter()
                .chain(input_view.mem_ops())
                .chain(output_view.mem_ops())
                .collect(),
            reg_ops,
        ),
        next_pc: None,
    })
}

pub fn tensor_attention_reduced_v1<T: Tracer>(vm: &VMState<T>) -> Result<SyscallEffects> {
    use crate::tensor::llama::{
        ZKLLM_ATTN_TABLE_SCALES, ZkllmSegmentedAttentionTables, zkllm_segmented_attention,
    };
    const DESC_WORDS: usize = 32;
    let desc_ptr = vm.peek_register(Platform::reg_arg0());
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(desc_ptr, desc_ptr),
        0,
    )];
    let desc_view = MemoryView::<_, DESC_WORDS>::new(vm, desc_ptr);
    let words = desc_view.words();
    ensure!(words[0] == TENSOR_ABI_V1, "unsupported tensor ABI");
    ensure!(
        words[1] == ATTENTION_REDUCED_PROFILE_V1,
        "unsupported attention profile"
    );
    ensure!(
        words[2] == ATTENTION_RESCALE_SHIFT_Q20_V1,
        "unsupported attention rescale identity"
    );
    ensure!(
        words[3] == ATTENTION_SOFTMAX_TABLE_REDUCED_V1,
        "unsupported attention table"
    );
    ensure!(
        words[4..12] == ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1,
        "attention table commitment mismatch"
    );
    ensure!(
        (words[16], words[17], words[18]) == (0, 0, 2),
        "invalid causal attention coordinates/mask"
    );
    ensure!(words[19..21] == [0, 0], "nonzero segment-start accumulator");
    ensure!(
        (words[21] as i32, words[22] as i32) == (11, 25),
        "invalid row shifts"
    );
    ensure!(words[23..] == [0; 9], "nonzero attention reserved word");

    let q_view = MemoryView::<_, 4>::new(vm, words[12]);
    let k_view = MemoryView::<_, 4>::new(vm, words[13]);
    let v_view = MemoryView::<_, 4>::new(vm, words[14]);
    let q = q_view.words().map(|x| x as i32);
    let k = k_view.words().map(|x| x as i32);
    let v = v_view.words().map(|x| x as i32);
    let tables = ZkllmSegmentedAttentionTables {
        middle_q18: vec![(0, ZKLLM_ATTN_TABLE_SCALES[0])],
        high_q22: vec![(0, ZKLLM_ATTN_TABLE_SCALES[1])],
    };
    let trace = zkllm_segmented_attention(&q, &k, &v, &[11, 25], &tables, 2, 2)?;
    let mut output_view = MemoryView::<_, 4>::new(vm, words[15]);
    output_view.write(
        trace
            .output
            .into_iter()
            .map(|x| x as u32)
            .collect::<Vec<_>>()
            .try_into()
            .expect("reduced attention has four outputs"),
    );
    Ok(SyscallEffects {
        witness: SyscallWitness::new(
            desc_view
                .mem_ops()
                .into_iter()
                .chain(q_view.mem_ops())
                .chain(k_view.mem_ops())
                .chain(v_view.mem_ops())
                .chain(output_view.mem_ops())
                .collect(),
            reg_ops,
        ),
        next_pc: None,
    })
}

fn block_matmul<T: Tracer>(
    vm: &VMState<T>,
    tensor_id: u32,
    tile_id: u32,
    root_words: &[u32],
    input: [i32; 4],
) -> Result<[i32; 4]> {
    let provider = vm
        .tensor_witness_provider()
        .ok_or_else(|| anyhow::anyhow!("tensor witness provider is not installed"))?;
    let desc = TensorMatMulDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: crate::tensor::GATE2_LINEAR_COMMITMENT_V1,
        signature_id: TENSOR_SIGNATURE_2X3X2,
        quantization_id: ZKLLM_FIXED_V1,
        m: 2,
        k: 3,
        n: 2,
        input_stride: 3,
        output_stride: 2,
        weight_tensor_id: tensor_id,
        weight_tile_id: tile_id,
        ..Default::default()
    };
    let root = root_words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let padded = [input[0], input[1], 0, input[2], input[3], 0];
    let (output, _) = crate::tensor::execute_committed_matmul(
        provider,
        &desc,
        root.as_slice().try_into().expect("eight words form a root"),
        &padded,
        TENSOR_RESCALE_SHIFT,
    )?;
    Ok(output
        .try_into()
        .expect("registered block MatMul has four outputs"))
}

fn validate_block_descriptor(
    words: &[u32; 32],
    expected_table: u32,
    expected_commitment: [u32; 8],
) -> Result<()> {
    ensure!(words[0] == TENSOR_ABI_V1, "unsupported tensor ABI");
    ensure!(
        words[1] == BLOCK_REDUCED_PROFILE_V1,
        "unsupported block profile"
    );
    ensure!(
        words[2] == TENSOR_SIGNATURE_2X3X2,
        "unsupported block signature"
    );
    ensure!(
        words[3] == ZKLLM_FIXED_V1,
        "unsupported quantization profile"
    );
    ensure!(words[8] == expected_table, "block table identity mismatch");
    ensure!(
        words[9..17] == expected_commitment,
        "block table commitment mismatch"
    );
    ensure!(words[17] < 32, "Llama layer index outside registered model");
    ensure!(
        words[18..] == [0; 14],
        "nonzero block descriptor padding/reserved word"
    );
    Ok(())
}

pub fn tensor_attention_block_reduced_v1<T: Tracer>(vm: &VMState<T>) -> Result<SyscallEffects> {
    use crate::tensor::llama::{
        ZKLLM_ATTN_TABLE_SCALES, ZkllmSegmentedAttentionTables, zkllm_segmented_attention,
    };
    let desc_ptr = vm.peek_register(Platform::reg_arg0());
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(desc_ptr, desc_ptr),
        0,
    )];
    let desc_view = MemoryView::<_, 32>::new(vm, desc_ptr);
    let words = desc_view.words();
    validate_block_descriptor(
        &words,
        ATTENTION_SOFTMAX_TABLE_REDUCED_V1,
        ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1,
    )?;
    let input_view = MemoryView::<_, 4>::new(vm, words[4]);
    let roots_view = MemoryView::<_, 32>::new(vm, words[6]);
    let input = input_view.words().map(|word| word as i32);
    let roots = roots_view.words();
    let q = block_matmul(vm, words[7], 0, &roots[0..8], input)?;
    let k = block_matmul(vm, words[7], 1, &roots[8..16], input)?;
    let v = block_matmul(vm, words[7], 2, &roots[16..24], input)?;
    let tables = ZkllmSegmentedAttentionTables {
        middle_q18: vec![(0, ZKLLM_ATTN_TABLE_SCALES[0])],
        high_q22: vec![(0, ZKLLM_ATTN_TABLE_SCALES[1])],
    };
    let attention = zkllm_segmented_attention(&q, &k, &v, &[11, 25], &tables, 2, 2)?;
    let projected = block_matmul(
        vm,
        words[7],
        3,
        &roots[24..32],
        attention.output.try_into().expect("four attention outputs"),
    )?;
    let output = std::array::from_fn(|i| input[i].checked_add(projected[i]).unwrap());
    let mut output_view = MemoryView::<_, 4>::new(vm, words[5]);
    output_view.write(output.map(|word| word as u32));
    Ok(SyscallEffects {
        witness: SyscallWitness::new(
            desc_view
                .mem_ops()
                .into_iter()
                .chain(input_view.mem_ops())
                .chain(roots_view.mem_ops())
                .chain(output_view.mem_ops())
                .collect(),
            reg_ops,
        ),
        next_pc: None,
    })
}

pub fn tensor_ffn_block_reduced_v1<T: Tracer>(vm: &VMState<T>) -> Result<SyscallEffects> {
    let desc_ptr = vm.peek_register(Platform::reg_arg0());
    let reg_ops = vec![WriteOp::new_register_op(
        Platform::reg_arg0(),
        Change::new(desc_ptr, desc_ptr),
        0,
    )];
    let desc_view = MemoryView::<_, 32>::new(vm, desc_ptr);
    let words = desc_view.words();
    validate_block_descriptor(&words, FFN_TABLE_REDUCED_V1, FFN_TABLE_COMMITMENT_V1)?;
    let input_view = MemoryView::<_, 4>::new(vm, words[4]);
    let roots_view = MemoryView::<_, 24>::new(vm, words[6]);
    let input = input_view.words().map(|word| word as i32);
    let roots = roots_view.words();
    let gate = block_matmul(vm, words[7], 4, &roots[0..8], input)?;
    let up = block_matmul(vm, words[7], 5, &roots[8..16], input)?;
    let down_input = std::array::from_fn(|i| gate[i] * up[i] / 256);
    let down = block_matmul(vm, words[7], 6, &roots[16..24], down_input)?;
    let output = std::array::from_fn(|i| input[i].checked_add(down[i]).unwrap());
    let mut output_view = MemoryView::<_, 4>::new(vm, words[5]);
    output_view.write(output.map(|word| word as u32));
    Ok(SyscallEffects {
        witness: SyscallWitness::new(
            desc_view
                .mem_ops()
                .into_iter()
                .chain(input_view.mem_ops())
                .chain(roots_view.mem_ops())
                .chain(output_view.mem_ops())
                .collect(),
            reg_ops,
        ),
        next_pc: None,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        ByteAddr, CENO_PLATFORM, EmuContext, Program, VMState,
        tensor::{
            DeterministicTileProvider, commit_tile, encode_i32_le, gate2_linear_commitment_v1,
        },
    };

    use super::*;

    fn attention_vm(words: [u32; 32]) -> VMState<crate::FullTracer> {
        let mut vm = VMState::new(CENO_PLATFORM.clone(), Arc::new(Program::from(&[][..])));
        let desc_ptr = CENO_PLATFORM.heap.start + 0x800;
        vm.store_register(Platform::reg_arg0(), desc_ptr).unwrap();
        for (i, word) in words.into_iter().enumerate() {
            vm.init_memory(ByteAddr(desc_ptr).waddr() + i, word);
        }
        for (base, values) in [
            (words[12], [1i32, -2, 3, -4]),
            (words[13], [1i32, -2, 3, -4]),
            (words[14], [1i32, -2, 3, -4]),
            (words[15], [0i32; 4]),
        ] {
            for (i, value) in values.into_iter().enumerate() {
                vm.init_memory(ByteAddr(base).waddr() + i, value as u32);
            }
        }
        vm
    }

    fn attention_words() -> [u32; 32] {
        let mut words = [0; 32];
        words[0] = TENSOR_ABI_V1;
        words[1] = ATTENTION_REDUCED_PROFILE_V1;
        words[2] = ATTENTION_RESCALE_SHIFT_Q20_V1;
        words[3] = ATTENTION_SOFTMAX_TABLE_REDUCED_V1;
        words[4..12].copy_from_slice(&ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1);
        words[12] = CENO_PLATFORM.heap.start + 0x1000;
        words[13] = CENO_PLATFORM.heap.start + 0x1100;
        words[14] = CENO_PLATFORM.heap.start + 0x1200;
        words[15] = CENO_PLATFORM.heap.start + 0x1300;
        words[18] = 2;
        words[21] = 11;
        words[22] = 25;
        words
    }

    fn block_vm(attention: bool, tamper_root: bool) -> VMState<crate::FullTracer> {
        let mut vm = VMState::new(CENO_PLATFORM.clone(), Arc::new(Program::from(&[][..])));
        let desc_ptr = CENO_PLATFORM.heap.start + 0x2000;
        let input_ptr = desc_ptr + 0x200;
        let output_ptr = input_ptr + 0x100;
        let roots_ptr = output_ptr + 0x100;
        let tensor_id = 73;
        let weights = [65_536, 0, 0, 65_536, 0, 0];
        let tiles = (0..7).map(|_| encode_i32_le(&weights)).collect();
        vm.set_tensor_witness_provider(Arc::new(
            DeterministicTileProvider::new(tensor_id, tiles).unwrap(),
        ));
        vm.store_register(Platform::reg_arg0(), desc_ptr).unwrap();
        let mut words = [0u32; 32];
        words[0] = TENSOR_ABI_V1;
        words[1] = BLOCK_REDUCED_PROFILE_V1;
        words[2] = TENSOR_SIGNATURE_2X3X2;
        words[3] = ZKLLM_FIXED_V1;
        words[4] = input_ptr;
        words[5] = output_ptr;
        words[6] = roots_ptr;
        words[7] = tensor_id;
        if attention {
            words[8] = ATTENTION_SOFTMAX_TABLE_REDUCED_V1;
            words[9..17].copy_from_slice(&ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1);
        } else {
            words[8] = FFN_TABLE_REDUCED_V1;
            words[9..17].copy_from_slice(&FFN_TABLE_COMMITMENT_V1);
        }
        for (i, word) in words.into_iter().enumerate() {
            vm.init_memory(ByteAddr(desc_ptr).waddr() + i, word);
        }
        let input = if attention {
            [1i32, -2, 3, -4]
        } else {
            [2, -4, 7, -10]
        };
        for (i, value) in input.into_iter().enumerate() {
            vm.init_memory(ByteAddr(input_ptr).waddr() + i, value as u32);
            vm.init_memory(ByteAddr(output_ptr).waddr() + i, 0);
        }
        let tiles = if attention { 0..4 } else { 4..7 };
        for (root_index, tile) in tiles.enumerate() {
            let mut root = gate2_linear_commitment_v1(tensor_id, tile, &weights);
            if tamper_root && root_index == 0 {
                root[0] ^= 1;
            }
            for (lane, word) in root.into_iter().enumerate() {
                vm.init_memory(ByteAddr(roots_ptr).waddr() + root_index * 8 + lane, word);
            }
        }
        vm
    }

    #[test]
    fn attention_descriptor_binds_guarded_fields_and_matches_oracle() {
        let words = attention_words();
        let effects = tensor_attention_reduced_v1(&attention_vm(words)).unwrap();
        assert_eq!(effects.witness.mem_ops.len(), 48);
        let output = effects.witness.mem_ops[44..]
            .iter()
            .map(|op| op.value.after as i32)
            .collect::<Vec<_>>();
        assert_eq!(output, [1, -2, 4, -6]);

        for index in [1usize, 2, 3, 4, 16, 17, 18, 19, 21, 23] {
            let mut tampered = words;
            tampered[index] ^= 1;
            assert!(
                tensor_attention_reduced_v1(&attention_vm(tampered)).is_err(),
                "descriptor word {index} was not bound"
            );
        }
    }

    #[test]
    fn bounded_syscall_keeps_weights_out_of_witness() {
        let mut vm = VMState::new(CENO_PLATFORM.clone(), Arc::new(Program::from(&[][..])));
        let desc_ptr = CENO_PLATFORM.heap.start + 0x100;
        let input_ptr = desc_ptr + 0x100;
        let output_ptr = input_ptr + 0x100;
        let root_ptr = output_ptr + 0x100;
        let tensor_id = 41;
        let weights = [65_536, 0, 0, 65_536, 65_536, 65_536];
        let bytes = encode_i32_le(&weights);
        let root = commit_tile(tensor_id, 0, &bytes);
        vm.set_tensor_witness_provider(Arc::new(
            DeterministicTileProvider::new(tensor_id, vec![bytes]).unwrap(),
        ));
        vm.store_register(Platform::reg_arg0(), desc_ptr).unwrap();

        let desc_words = [
            TENSOR_ABI_V1,
            0,
            TENSOR_SIGNATURE_2X3X2,
            ZKLLM_FIXED_V1,
            input_ptr,
            output_ptr,
            2,
            3,
            2,
            3,
            2,
            tensor_id,
            0,
            root_ptr,
            0,
            0,
        ];
        for (i, word) in desc_words.into_iter().enumerate() {
            vm.init_memory(ByteAddr(desc_ptr).waddr() + i, word);
        }
        for (i, word) in [1u32, 2, 3, 4, 5, 6].into_iter().enumerate() {
            vm.init_memory(ByteAddr(input_ptr).waddr() + i, word);
        }
        for (i, word) in root
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .enumerate()
        {
            vm.init_memory(ByteAddr(root_ptr).waddr() + i, word);
        }
        for i in 0..TENSOR_OUTPUT_WORDS {
            vm.init_memory(ByteAddr(output_ptr).waddr() + i, 0);
        }

        let effects = tensor_matmul_v1(&vm).unwrap();
        assert_eq!(effects.witness.reg_ops.len(), 1);
        assert_eq!(
            effects.witness.mem_ops.len(),
            TensorMatMulV1Spec::MEM_OPS_COUNT
        );
        let output = &effects.witness.mem_ops[TensorMatMulV1Spec::MEM_OPS_COUNT - 4..];
        assert_eq!(
            output.iter().map(|op| op.value.after).collect::<Vec<_>>(),
            [4, 5, 10, 11]
        );
        // Only descriptor, input, public root and output words are journaled.
        assert_eq!(effects.witness.mem_ops.len(), 34);
    }

    #[test]
    fn fused_blocks_match_primitive_boundaries_and_keep_roots_in_journal() {
        let attention = tensor_attention_block_reduced_v1(&block_vm(true, false)).unwrap();
        assert_eq!(attention.witness.mem_ops.len(), 72);
        let attention_output = attention.witness.mem_ops[68..]
            .iter()
            .map(|op| op.value.after as i32)
            .collect::<Vec<_>>();
        assert_eq!(attention_output, [2, -4, 7, -10]);

        let ffn = tensor_ffn_block_reduced_v1(&block_vm(false, false)).unwrap();
        assert_eq!(ffn.witness.mem_ops.len(), 64);
        let ffn_output = ffn.witness.mem_ops[60..]
            .iter()
            .map(|op| op.value.after as i32)
            .collect::<Vec<_>>();
        assert_eq!(ffn_output, [2, -4, 7, -10]);
        assert!(tensor_attention_block_reduced_v1(&block_vm(true, true)).is_err());
        assert!(tensor_ffn_block_reduced_v1(&block_vm(false, true)).is_err());
    }

    fn tensor_bus_vm() -> (VMState<crate::FullTracer>, u32, u32) {
        let mut vm = VMState::new(CENO_PLATFORM.clone(), Arc::new(Program::from(&[][..])));
        let base = CENO_PLATFORM.heap.start + 0x4000;
        let import_ptr = base + 0x100;
        let export_ptr = base + 0x200;
        let input_ptr = base + 0x1000;
        let output_ptr = input_ptr + TENSOR_BUS_FIXED_TRANSFER_WORDS * 4 + 0x1000;
        let meta_ptr = output_ptr + TENSOR_BUS_FIXED_TRANSFER_WORDS * 4 + 0x1000;
        let handle_ptr = meta_ptr + 0x100;
        let words = TENSOR_BUS_FIXED_TRANSFER_WORDS as usize;
        let mut input = vec![0; words];
        input[..4].copy_from_slice(&[3, (-5i32) as u32, 7, (-11i32) as u32]);
        for (ptr, words) in [
            (
                import_ptr,
                vec![
                    TENSOR_ABI_V1,
                    0,
                    input_ptr,
                    TENSOR_BUS_FIXED_TRANSFER_WORDS,
                    meta_ptr,
                    4,
                    handle_ptr,
                    0,
                ],
            ),
            (
                export_ptr,
                vec![
                    TENSOR_ABI_V1,
                    0,
                    handle_ptr,
                    output_ptr,
                    TENSOR_BUS_FIXED_TRANSFER_WORDS,
                    meta_ptr,
                    4,
                    0,
                ],
            ),
            (
                meta_ptr,
                vec![
                    TENSOR_BUS_FIXED_TRANSFER_WORDS * 4,
                    TENSOR_BUS_FIXED_TRANSFER_WORDS,
                    16,
                    0,
                ],
            ),
            (input_ptr, input),
            (output_ptr, vec![0; words]),
            (handle_ptr, vec![0; 4]),
        ] {
            for (index, word) in words.into_iter().enumerate() {
                vm.init_memory(ByteAddr(ptr).waddr() + index, word);
            }
        }
        (vm, import_ptr, export_ptr)
    }

    #[test]
    fn tensor_bus_syscalls_materialize_opaque_handles_without_pointer_abi_changes() {
        let (mut vm, import_ptr, export_ptr) = tensor_bus_vm();
        vm.init_register_unsafe(Platform::reg_arg0(), import_ptr);
        let import = tensor_import_begin_v1(&mut vm).unwrap();
        for op in &import.witness.mem_ops {
            vm.init_memory(op.addr, op.value.after);
        }
        vm.init_register_unsafe(Platform::reg_arg0(), export_ptr);
        let export = tensor_export_end_v1(&mut vm).unwrap();
        assert_eq!(
            export.witness.mem_ops[16..]
                .iter()
                .map(|op| op.value.after as i32)
                .collect::<Vec<_>>(),
            {
                let mut expected = vec![0; TENSOR_BUS_FIXED_TRANSFER_WORDS as usize];
                expected[..4].copy_from_slice(&[3, -5, 7, -11]);
                expected
            }
        );
        crate::tensor::bus::verify_tensor_bus_witnesses(&[
            import.witness.clone(),
            export.witness.clone(),
        ])
        .unwrap();
    }

    #[test]
    fn tensor_bus_syscalls_reject_lifecycle_and_offline_record_tampering() {
        let (mut vm, import_ptr, export_ptr) = tensor_bus_vm();
        vm.init_register_unsafe(Platform::reg_arg0(), export_ptr);
        assert!(tensor_export_end_v1(&mut vm).is_err());
        vm.init_register_unsafe(Platform::reg_arg0(), import_ptr);
        let import = tensor_import_begin_v1(&mut vm).unwrap();
        let mut tampered = import.witness.clone();
        let crate::tensor::bus::TensorBusRecord::Write(write) = &mut tampered.tensor_bus_records[0]
        else {
            panic!("import must emit a TensorBus write");
        };
        write.handle.version = 1;
        assert!(crate::tensor::bus::verify_tensor_bus_witnesses(&[tampered]).is_ok());
        let mut read_tampered = import.witness;
        read_tampered.tensor_bus_records[0] =
            crate::tensor::bus::TensorBusRecord::Read(crate::tensor::bus::TensorReadRecord {
                segment_id: 7,
                handle: crate::tensor::bus::TensorHandle {
                    tensor_id: 1,
                    version: 1,
                },
                meta: crate::tensor::bus::TensorBusMeta {
                    byte_len: 8,
                    shape: vec![2],
                    quantization_id: 16,
                },
                consumer: crate::tensor::bus::TensorBusSyscall::Export,
                order: 0,
            });
        assert!(crate::tensor::bus::verify_tensor_bus_witnesses(&[read_tampered]).is_err());
    }

    #[cfg(feature = "llama-tiny")]
    #[test]
    fn llama_tiny_tensor_bus_rejects_non_topology_transfer_lengths() {
        let (mut vm, import_ptr, export_ptr) = tensor_bus_vm();

        vm.init_memory(ByteAddr(import_ptr).waddr() + 3u32, 2);
        vm.init_register_unsafe(Platform::reg_arg0(), import_ptr);
        assert!(tensor_import_begin_v1(&mut vm).is_err());

        // The failed import leaves no handle; restore the fixed profile and
        // execute it before checking the export-side rejection independently.
        vm.init_memory(
            ByteAddr(import_ptr).waddr() + 3u32,
            TENSOR_BUS_FIXED_TRANSFER_WORDS,
        );
        tensor_import_begin_v1(&mut vm).unwrap();
        vm.init_memory(ByteAddr(export_ptr).waddr() + 4u32, 2);
        vm.init_register_unsafe(Platform::reg_arg0(), export_ptr);
        assert!(tensor_export_end_v1(&mut vm).is_err());
    }
}
