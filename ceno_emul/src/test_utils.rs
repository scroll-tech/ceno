use crate::{
    CENO_PLATFORM, InsnKind, Instruction, Platform, Program, StepRecord, VMState, encode_rv32,
    encode_rv32u,
    syscalls::{KECCAK_PERMUTE, SyscallWitness},
    tracer::FullTracerConfig,
};
use anyhow::Result;
use std::sync::Arc;

pub fn keccak_step() -> (StepRecord, Vec<Instruction>, Vec<SyscallWitness>) {
    let instructions = vec![
        // Call Keccak-f.
        load_immediate(Platform::reg_arg0() as u32, CENO_PLATFORM.heap.start),
        load_immediate(Platform::reg_ecall() as u32, KECCAK_PERMUTE),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        // Halt.
        load_immediate(Platform::reg_ecall() as u32, Platform::ecall_halt()),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ];

    let pc = CENO_PLATFORM.pc_base();
    let program = Program::new(
        pc,
        pc,
        CENO_PLATFORM.heap.start,
        instructions.clone(),
        Default::default(),
    );
    let mut vm: VMState = VMState::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.into(),
        FullTracerConfig { max_step_shard: 10 },
    );
    vm.iter_until_halt().collect::<Result<Vec<_>>>().unwrap();
    let steps = vm.tracer().recorded_steps();
    let syscall_witnesses = vm.tracer().syscall_witnesses().to_vec();

    (steps[2], instructions, syscall_witnesses)
}

pub fn tensor_matmul_step() -> (StepRecord, Vec<Instruction>, Vec<SyscallWitness>) {
    use crate::{
        ByteAddr, SyscallSpec, TENSOR_SIGNATURE_2X3X2, TensorMatMulV1Spec,
        tensor::{
            DeterministicTileProvider, GATE2_LINEAR_COMMITMENT_V1, TENSOR_ABI_V1, ZKLLM_FIXED_V1,
            encode_i32_le, gate2_linear_commitment_v1,
        },
    };
    let desc_ptr = CENO_PLATFORM.heap.start + 0x100;
    let input_ptr = desc_ptr + 0x100;
    let output_ptr = input_ptr + 0x100;
    let root_ptr = output_ptr + 0x100;
    let tensor_id = 41;
    let weights = [65_536, 0, 0, 65_536, 65_536, 65_536];
    let root = gate2_linear_commitment_v1(tensor_id, 0, &weights);
    let instructions = vec![
        load_immediate(Platform::reg_arg0() as u32, desc_ptr),
        load_immediate(Platform::reg_ecall() as u32, TensorMatMulV1Spec::CODE),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        load_immediate(Platform::reg_ecall() as u32, Platform::ecall_halt()),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ];
    let pc = CENO_PLATFORM.pc_base();
    let program = Program::new(
        pc,
        pc,
        CENO_PLATFORM.heap.start,
        instructions.clone(),
        Default::default(),
    );
    let mut vm: VMState = VMState::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.into(),
        FullTracerConfig { max_step_shard: 10 },
    );
    vm.set_tensor_witness_provider(Arc::new(
        DeterministicTileProvider::new(tensor_id, vec![encode_i32_le(&weights)]).unwrap(),
    ));
    let desc = [
        TENSOR_ABI_V1,
        GATE2_LINEAR_COMMITMENT_V1,
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
    for (i, value) in desc.into_iter().enumerate() {
        vm.init_memory(ByteAddr(desc_ptr).waddr() + i, value);
    }
    for (i, value) in [1, 2, 3, 4, 5, 6].into_iter().enumerate() {
        vm.init_memory(ByteAddr(input_ptr).waddr() + i, value);
    }
    for (i, value) in root.into_iter().enumerate() {
        vm.init_memory(ByteAddr(root_ptr).waddr() + i, value);
    }
    for i in 0usize..4 {
        vm.init_memory(ByteAddr(output_ptr).waddr() + i, 0);
    }
    vm.iter_until_halt().collect::<Result<Vec<_>>>().unwrap();
    let steps = vm.tracer().recorded_steps();
    let syscall_witnesses = vm.tracer().syscall_witnesses().to_vec();
    (steps[2], instructions, syscall_witnesses)
}

pub fn tensor_rms_step() -> (StepRecord, Vec<Instruction>, Vec<SyscallWitness>) {
    use crate::{ByteAddr, SyscallSpec, TensorRmsLookupV1Spec};
    let desc_ptr = CENO_PLATFORM.heap.start + 0x100;
    let input_ptr = desc_ptr + 0x100;
    let output_ptr = input_ptr + 0x100;
    let instructions = vec![
        load_immediate(Platform::reg_arg0() as u32, desc_ptr),
        load_immediate(Platform::reg_ecall() as u32, TensorRmsLookupV1Spec::CODE),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        load_immediate(Platform::reg_ecall() as u32, Platform::ecall_halt()),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ];
    let pc = CENO_PLATFORM.pc_base();
    let program = Program::new(
        pc,
        pc,
        CENO_PLATFORM.heap.start,
        instructions.clone(),
        Default::default(),
    );
    let mut vm: VMState = VMState::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.into(),
        FullTracerConfig { max_step_shard: 10 },
    );
    for (i, value) in [1, 1, 0x524d_5301, input_ptr, output_ptr, 0, 0, 0]
        .into_iter()
        .enumerate()
    {
        vm.init_memory(ByteAddr(desc_ptr).waddr() + i, value);
    }
    vm.init_memory(ByteAddr(input_ptr).waddr(), 3);
    vm.init_memory(ByteAddr(output_ptr).waddr(), 0);
    vm.iter_until_halt().collect::<Result<Vec<_>>>().unwrap();
    (
        steps_at(&vm, 2),
        instructions,
        vm.tracer().syscall_witnesses().to_vec(),
    )
}

pub fn tensor_attention_step() -> (StepRecord, Vec<Instruction>, Vec<SyscallWitness>) {
    use crate::{
        ByteAddr, SyscallSpec, TensorAttentionReducedV1Spec,
        syscalls::tensor::{
            ATTENTION_REDUCED_PROFILE_V1, ATTENTION_RESCALE_SHIFT_Q20_V1,
            ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1, ATTENTION_SOFTMAX_TABLE_REDUCED_V1,
        },
        tensor::TENSOR_ABI_V1,
    };
    let desc_ptr = CENO_PLATFORM.heap.start + 0x800;
    let q_ptr = CENO_PLATFORM.heap.start + 0x1000;
    let k_ptr = CENO_PLATFORM.heap.start + 0x1100;
    let v_ptr = CENO_PLATFORM.heap.start + 0x1200;
    let output_ptr = CENO_PLATFORM.heap.start + 0x1300;
    let instructions = vec![
        load_immediate(Platform::reg_arg0() as u32, desc_ptr),
        load_immediate(
            Platform::reg_ecall() as u32,
            TensorAttentionReducedV1Spec::CODE,
        ),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        load_immediate(Platform::reg_ecall() as u32, Platform::ecall_halt()),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ];
    let pc = CENO_PLATFORM.pc_base();
    let program = Program::new(
        pc,
        pc,
        CENO_PLATFORM.heap.start,
        instructions.clone(),
        Default::default(),
    );
    let mut vm: VMState = VMState::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.into(),
        FullTracerConfig { max_step_shard: 10 },
    );
    let mut desc = [0u32; 32];
    desc[0] = TENSOR_ABI_V1;
    desc[1] = ATTENTION_REDUCED_PROFILE_V1;
    desc[2] = ATTENTION_RESCALE_SHIFT_Q20_V1;
    desc[3] = ATTENTION_SOFTMAX_TABLE_REDUCED_V1;
    desc[4..12].copy_from_slice(&ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1);
    desc[12..16].copy_from_slice(&[q_ptr, k_ptr, v_ptr, output_ptr]);
    desc[18] = 2;
    desc[21] = 11;
    desc[22] = 25;
    for (i, value) in desc.into_iter().enumerate() {
        vm.init_memory(ByteAddr(desc_ptr).waddr() + i, value);
    }
    for ptr in [q_ptr, k_ptr, v_ptr] {
        for (i, value) in [1i32, -2, 3, -4].into_iter().enumerate() {
            vm.init_memory(ByteAddr(ptr).waddr() + i, value as u32);
        }
    }
    for i in 0usize..4 {
        vm.init_memory(ByteAddr(output_ptr).waddr() + i, 0);
    }
    vm.iter_until_halt().collect::<Result<Vec<_>>>().unwrap();
    (
        steps_at(&vm, 2),
        instructions,
        vm.tracer().syscall_witnesses().to_vec(),
    )
}

pub fn tensor_block_step(
    attention: bool,
) -> (
    StepRecord,
    Vec<Instruction>,
    Vec<SyscallWitness>,
    Arc<crate::tensor::DeterministicTileProvider>,
) {
    use crate::{
        ByteAddr, SyscallSpec, TensorAttentionBlockReducedV1Spec, TensorFfnBlockReducedV1Spec,
        syscalls::tensor::{
            ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1, ATTENTION_SOFTMAX_TABLE_REDUCED_V1,
            BLOCK_REDUCED_PROFILE_V1, FFN_TABLE_COMMITMENT_V1, FFN_TABLE_REDUCED_V1,
            TENSOR_SIGNATURE_2X3X2,
        },
        tensor::{
            DeterministicTileProvider, TENSOR_ABI_V1, ZKLLM_FIXED_V1, encode_i32_le,
            gate2_linear_commitment_v1,
        },
    };
    let desc_ptr = CENO_PLATFORM.heap.start + 0x2000;
    let input_ptr = desc_ptr + 0x200;
    let output_ptr = input_ptr + 0x100;
    let roots_ptr = output_ptr + 0x100;
    let tensor_id = 73;
    let code = if attention {
        TensorAttentionBlockReducedV1Spec::CODE
    } else {
        TensorFfnBlockReducedV1Spec::CODE
    };
    let instructions = vec![
        load_immediate(Platform::reg_arg0() as u32, desc_ptr),
        load_immediate(Platform::reg_ecall() as u32, code),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        load_immediate(Platform::reg_ecall() as u32, Platform::ecall_halt()),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ];
    let pc = CENO_PLATFORM.pc_base();
    let program = Program::new(
        pc,
        pc,
        CENO_PLATFORM.heap.start,
        instructions.clone(),
        Default::default(),
    );
    let mut vm: VMState = VMState::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.into(),
        FullTracerConfig { max_step_shard: 10 },
    );
    let weights = [65_536, 0, 0, 65_536, 0, 0];
    let provider = Arc::new(
        DeterministicTileProvider::new(
            tensor_id,
            (0..7).map(|_| encode_i32_le(&weights)).collect(),
        )
        .unwrap(),
    );
    vm.set_tensor_witness_provider(provider.clone());
    let mut desc = [0u32; 32];
    desc[0] = TENSOR_ABI_V1;
    desc[1] = BLOCK_REDUCED_PROFILE_V1;
    desc[2] = TENSOR_SIGNATURE_2X3X2;
    desc[3] = ZKLLM_FIXED_V1;
    desc[4..8].copy_from_slice(&[input_ptr, output_ptr, roots_ptr, tensor_id]);
    if attention {
        desc[8] = ATTENTION_SOFTMAX_TABLE_REDUCED_V1;
        desc[9..17].copy_from_slice(&ATTENTION_SOFTMAX_TABLE_COMMITMENT_V1);
    } else {
        desc[8] = FFN_TABLE_REDUCED_V1;
        desc[9..17].copy_from_slice(&FFN_TABLE_COMMITMENT_V1);
    }
    for (i, value) in desc.into_iter().enumerate() {
        vm.init_memory(ByteAddr(desc_ptr).waddr() + i, value);
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
        for (lane, word) in gate2_linear_commitment_v1(tensor_id, tile, &weights)
            .into_iter()
            .enumerate()
        {
            vm.init_memory(ByteAddr(roots_ptr).waddr() + root_index * 8 + lane, word);
        }
    }
    vm.iter_until_halt().collect::<Result<Vec<_>>>().unwrap();
    (
        steps_at(&vm, 2),
        instructions,
        vm.tracer().syscall_witnesses().to_vec(),
        provider,
    )
}

fn steps_at(vm: &VMState, index: usize) -> StepRecord {
    vm.tracer().recorded_steps()[index]
}

const fn load_immediate(rd: u32, imm: u32) -> Instruction {
    encode_rv32u(InsnKind::ADDI, 0, 0, rd, imm)
}
