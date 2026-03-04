use std::time::Duration;

use ceno_emul::{ByteAddr, Change, InsnKind, StepRecord, encode_rv32};
use ceno_zkvm::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    e2e::ShardContext,
    instructions::{Instruction, riscv::arith::AddInstruction},
    structs::ProgramParams,
};
use criterion::*;
use ff_ext::BabyBearExt4;

#[cfg(feature = "gpu")]
use ceno_gpu::bb31::CudaHalBB31;
#[cfg(feature = "gpu")]
use ceno_zkvm::instructions::riscv::gpu::add::extract_add_column_map;

mod alloc;

type E = BabyBearExt4;

criterion_group! {
    name = witgen_add;
    config = Criterion::default().warm_up_time(Duration::from_millis(2000));
    targets = bench_witgen_add
}

criterion_main!(witgen_add);

fn make_test_steps(n: usize) -> Vec<StepRecord> {
    let pc_start = 0x1000u32;
    (0..n)
        .map(|i| {
            let rs1 = (i as u32) % 1000 + 1;
            let rs2 = (i as u32) % 500 + 3;
            let rd_before = (i as u32) % 200;
            let rd_after = rs1.wrapping_add(rs2);
            let cycle = 4 + (i as u64) * 4;
            let pc = ByteAddr(pc_start + (i as u32) * 4);
            let insn_code = encode_rv32(InsnKind::ADD, 2, 3, 4, 0);
            StepRecord::new_r_instruction(
                cycle,
                pc,
                insn_code,
                rs1,
                rs2,
                Change::new(rd_before, rd_after),
                0,
            )
        })
        .collect()
}

#[cfg(feature = "gpu")]
fn step_records_to_bytes(records: &[StepRecord]) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            records.as_ptr() as *const u8,
            records.len() * std::mem::size_of::<StepRecord>(),
        )
    }
}

fn bench_witgen_add(c: &mut Criterion) {
    let mut cs = ConstraintSystem::<E>::new(|| "bench");
    let mut cb = CircuitBuilder::new(&mut cs);
    let config =
        AddInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
    let num_witin = cb.cs.num_witin as usize;
    let num_structural_witin = cb.cs.num_structural_witin as usize;

    #[cfg(feature = "gpu")]
    let hal = CudaHalBB31::new(0).expect("Failed to create CUDA HAL");
    #[cfg(feature = "gpu")]
    let col_map = extract_add_column_map(&config, num_witin);

    for pow in [10, 12, 14, 16, 18] {
        let n = 1usize << pow;
        let mut group = c.benchmark_group(format!("witgen_add_2^{}", pow));
        group.sample_size(10);

        let steps = make_test_steps(n);
        let indices: Vec<usize> = (0..n).collect();

        // CPU benchmark
        group.bench_function("cpu_assign_instances", |b| {
            b.iter(|| {
                let mut shard_ctx = ShardContext::default();
                AddInstruction::<E>::assign_instances(
                    &config,
                    &mut shard_ctx,
                    num_witin,
                    num_structural_witin,
                    &steps,
                    &indices,
                )
                .unwrap()
            })
        });

        // GPU benchmark (total: H2D records + indices + kernel + synchronize)
        #[cfg(feature = "gpu")]
        group.bench_function("gpu_total", |b| {
            let steps_bytes = step_records_to_bytes(&steps);
            let indices_u32: Vec<u32> = indices.iter().map(|&i| i as u32).collect();
            b.iter(|| {
                let gpu_records = hal.inner.htod_copy_stream(None, steps_bytes).unwrap();
                let shard_ctx = ShardContext::default();
                let shard_offset = shard_ctx.current_shard_offset_cycle();
                hal.witgen_add(&col_map, &gpu_records, &indices_u32, shard_offset, None)
                    .unwrap()
            })
        });

        // GPU benchmark (kernel only: records pre-uploaded)
        #[cfg(feature = "gpu")]
        {
            let steps_bytes = step_records_to_bytes(&steps);
            let gpu_records = hal.inner.htod_copy_stream(None, steps_bytes).unwrap();
            let indices_u32: Vec<u32> = indices.iter().map(|&i| i as u32).collect();
            let shard_ctx = ShardContext::default();
            let shard_offset = shard_ctx.current_shard_offset_cycle();

            group.bench_function("gpu_kernel_only", |b| {
                b.iter(|| {
                    hal.witgen_add(&col_map, &gpu_records, &indices_u32, shard_offset, None)
                        .unwrap()
                })
            });
        }

        group.finish();
    }
}
