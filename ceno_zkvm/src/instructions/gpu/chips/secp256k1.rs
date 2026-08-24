use ceno_gpu::Buffer;
use ff_ext::ExtensionField;
use gkr_iop::{tables::LookupTable, utils::lk_multiplicity::LkMultiplicity};
use rayon::prelude::*;
use witness::{DeviceMatrixLayout, RowMajorMatrix};

use crate::error::ZKVMError;

pub(crate) fn enabled() -> bool {
    std::env::var_os("CENO_I055_GPU_SECP_RELATIONS").is_none_or(|v| v != "0")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assign_relations<E: ExtensionField>(
    phase1_rows: &[E::BaseField],
    records: &[u8],
    is_double: bool,
    valid_rows: usize,
    num_witin: usize,
    num_structural_witin: usize,
    first_wit_col: usize,
    num_arithmetic_cols: usize,
    lk: &mut LkMultiplicity,
) -> Result<[RowMajorMatrix<E::BaseField>; 2], ZKVMError> {
    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() {
        return Err(ZKVMError::InvalidWitness(
            "I055 direct secp256k1 relations require BabyBear".into(),
        ));
    }
    let hal = gkr_iop::gpu::get_cuda_hal().map_err(|e| {
        ZKVMError::InvalidWitness(format!("I055 direct secp256k1 CUDA unavailable: {e}").into())
    })?;
    if phase1_rows.len() != valid_rows * num_witin {
        return Err(ZKVMError::InvalidWitness(
            "I055 invalid canonical phase-1 scratch shape".into(),
        ));
    }
    let arithmetic_end = first_wit_col + num_arithmetic_cols;
    if arithmetic_end > num_witin {
        return Err(ZKVMError::InvalidWitness(
            "I055 arithmetic range exceeds witness width".into(),
        ));
    }
    let non_arithmetic_cols = num_witin - num_arithmetic_cols;
    let mut non_arithmetic_rows = vec![E::BaseField::default(); valid_rows * non_arithmetic_cols];
    phase1_rows
        .par_chunks_exact(num_witin)
        .zip(non_arithmetic_rows.par_chunks_exact_mut(non_arithmetic_cols))
        .for_each(|(source, destination)| {
            destination[..first_wit_col].copy_from_slice(&source[..first_wit_col]);
            destination[first_wit_col..].copy_from_slice(&source[arithmetic_end..]);
        });
    let non_arithmetic: &[BB] = unsafe {
        std::slice::from_raw_parts(
            non_arithmetic_rows.as_ptr().cast(),
            non_arithmetic_rows.len(),
        )
    };
    let padded_rows = witness::next_pow2_instance_padding(valid_rows);
    let result = tracing::info_span!(
        "secp256k1_gpu_relation_module",
        operation = if is_double { "double" } else { "add" },
        n = valid_rows
    )
    .in_scope(|| {
        let _nvtx = nvtx::range!(
            "ceno.witness.secp256k1 operation={} rows={}",
            if is_double { "double" } else { "add" },
            valid_rows
        );
        hal.witgen.witgen_secp256k1_relations(
            non_arithmetic,
            records,
            is_double,
            valid_rows,
            padded_rows,
            num_witin,
            num_structural_witin,
            first_wit_col,
            num_arithmetic_cols,
        )
    })
    .map_err(|e| ZKVMError::InvalidWitness(format!("I055 secp256k1 GPU failed: {e}").into()))?;

    tracing::info_span!("secp256k1_gpu_completion_wait")
        .in_scope(|| result.completion.wait())
        .map_err(|e| ZKVMError::InvalidWitness(format!("I055 completion failed: {e}").into()))?;
    let counts = tracing::info_span!("secp256k1_gpu_lookup_d2h")
        .in_scope(|| result.double_u8.to_vec())
        .map_err(|e| ZKVMError::InvalidWitness(format!("I055 lookup D2H failed: {e}").into()))?;
    for (key, count) in counts
        .into_iter()
        .enumerate()
        .filter(|(_, count)| *count != 0)
    {
        *lk += ((LookupTable::DoubleU8, key as u64), count as usize);
    }
    Ok([
        RowMajorMatrix::new_by_device_backing(
            valid_rows,
            num_witin,
            witness::InstancePaddingStrategy::Default,
            result.witness.device_buffer,
            DeviceMatrixLayout::ColMajor,
        ),
        RowMajorMatrix::new_by_device_backing(
            valid_rows,
            num_structural_witin,
            witness::InstancePaddingStrategy::Default,
            result.structural.device_buffer,
            DeviceMatrixLayout::ColMajor,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        e2e::ShardContext,
        instructions::{
            Instruction as CircuitInstruction,
            gpu::utils::d2h::gpu_witness_to_rmm_d2h,
            riscv::ecall::{WeierstrassAddAssignInstruction, WeierstrassDoubleAssignInstruction},
        },
        precompiles::{
            EllipticCurveAddInstance, EllipticCurveDoubleInstance, WeierstrassAddAssignLayout,
            WeierstrassAddAssignTrace, WeierstrassDoubleAssignLayout, WeierstrassDoubleAssignTrace,
            random_point_pairs, random_points, setup_weierstrass_add_circuit as setup_add,
            setup_weierstrass_double_circuit as setup_double,
        },
    };
    use ceno_emul::{
        CENO_PLATFORM, FullTracerConfig, InsnKind, Instruction as EncodedInstruction, Platform,
        Program, Secp256k1AddSpec, Secp256k1DoubleSpec, SyscallSpec, VMState, encode_rv32,
        encode_rv32u,
    };
    use ff_ext::{BabyBearExt4, SmallField};
    use gkr_iop::tables::LookupTable;
    use p3::field::PrimeCharacteristicRing;
    use sp1_curves::weierstrass::{SwCurve, secp256k1::Secp256k1};
    use std::{collections::BTreeMap, sync::Arc};
    use witness::InstancePaddingStrategy;

    fn gpu_counts(counts: Vec<u32>) -> gkr_iop::utils::lk_multiplicity::Multiplicity<u64> {
        let mut result = gkr_iop::utils::lk_multiplicity::Multiplicity::default();
        for (key, count) in counts
            .into_iter()
            .enumerate()
            .filter(|(_, count)| *count != 0)
        {
            result[LookupTable::DoubleU8 as usize].insert(key as u64, count as usize);
        }
        result
    }

    fn assert_matrix_eq<F: std::fmt::Debug + PartialEq>(left: &[F], right: &[F], width: usize) {
        assert_eq!(left.len(), right.len());
        if let Some((index, (a, b))) = left
            .iter()
            .zip(right)
            .enumerate()
            .find(|(_, (a, b))| a != b)
        {
            let needle_len = 12.min(right.len() - index);
            let source_match = left
                .windows(needle_len)
                .position(|window| window == &right[index..index + needle_len]);
            let nearby = left
                .iter()
                .zip(right)
                .enumerate()
                .filter(|(_, (left, right))| left != right)
                .take(12)
                .map(|(i, (left, right))| {
                    format!("r{}c{}:{left:?}/{right:?}", i / width, i % width)
                })
                .collect::<Vec<_>>()
                .join(", ");
            panic!(
                "matrix mismatch row={} col={} cpu={a:?} gpu={b:?}; gpu-sequence-in-cpu={source_match:?}; first={nearby}",
                index / width,
                index % width
            );
        }
    }

    fn compact_non_arithmetic_rows<F: p3::field::PrimeCharacteristicRing + Copy + Send + Sync>(
        matrix: &RowMajorMatrix<F>,
        valid_rows: usize,
        first_wit: usize,
        arithmetic_cols: usize,
    ) -> Vec<F> {
        let arithmetic_end = first_wit + arithmetic_cols;
        matrix
            .values()
            .chunks(matrix.n_col())
            .take(valid_rows)
            .flat_map(|row| {
                row[..first_wit]
                    .iter()
                    .chain(&row[arithmetic_end..])
                    .copied()
            })
            .collect()
    }

    fn assert_direct_secp256k1_add_matches_cpu(size: usize) {
        type E = BabyBearExt4;
        type EC = SwCurve<Secp256k1>;
        let points = random_point_pairs::<Secp256k1>(size);
        let instances = points
            .into_iter()
            .map(|[p, q]| EllipticCurveAddInstance { p, q })
            .collect::<Vec<_>>();
        let affine = WeierstrassAddAssignLayout::<E, EC>::compute_compact_secp256k1_affine_results(
            &instances,
        );
        let records =
            WeierstrassAddAssignLayout::<E, EC>::compact_secp256k1_gpu_records(&instances, &affine);
        let (test_layout, _, num_witin, num_structural) = setup_add::<E, EC>().unwrap();
        let layout = test_layout.layout;
        assert_eq!(layout.num_arithmetic_wit_cols(), 791);

        let mut cpu = RowMajorMatrix::new(
            instances.len(),
            num_witin as usize,
            InstancePaddingStrategy::Default,
        );
        let mut cpu_structural = RowMajorMatrix::new(
            instances.len(),
            num_structural as usize,
            InstancePaddingStrategy::Default,
        );
        let mut cpu_lk = LkMultiplicity::default();
        layout.phase1_witness_group_with_affine_results(
            WeierstrassAddAssignTrace { instances },
            &affine,
            [&mut cpu, &mut cpu_structural],
            &mut cpu_lk,
        );
        let width = cpu.n_col();
        for (row_index, row) in std::ops::DerefMut::deref_mut(&mut cpu)
            .values
            .chunks_mut(width)
            .take(size)
            .enumerate()
        {
            for (col_index, value) in row[..layout.first_wit_id()].iter_mut().enumerate() {
                *value = <E as ExtensionField>::BaseField::from_u64(
                    (row_index * layout.first_wit_id() + col_index + 1) as u64,
                );
            }
        }
        cpu.padding_by_strategy();
        cpu_structural.padding_by_strategy();

        for (record_offset, column_offset) in [(224, 224), (287, 413), (350, 602)] {
            let cpu_bytes = &cpu.values()
                [layout.first_wit_id() + column_offset..layout.first_wit_id() + column_offset + 63];
            assert_eq!(
                &records[record_offset..record_offset + 63],
                &cpu_bytes
                    .iter()
                    .map(|value| value.to_canonical_u64() as u8)
                    .collect::<Vec<_>>(),
                "add packed quotient mismatch record_offset={record_offset} column_offset={column_offset}"
            );
        }

        let hal = gkr_iop::gpu::get_cuda_hal().unwrap();
        // Make suffix scatter observable too; instruction phase 1 places VM,
        // register, memory, and fetch-derived cells after the arithmetic range.
        let arithmetic_end = layout.first_wit_id() + layout.num_arithmetic_wit_cols();
        let width = cpu.n_col();
        let suffix_cols = width - arithmetic_end;
        for (row_index, row) in std::ops::DerefMut::deref_mut(&mut cpu)
            .values
            .chunks_mut(width)
            .take(size)
            .enumerate()
        {
            for (suffix_index, value) in row[arithmetic_end..].iter_mut().enumerate() {
                *value = <E as ExtensionField>::BaseField::from_u64(
                    (10_000 + row_index * suffix_cols + suffix_index) as u64,
                );
            }
        }
        let phase1 = compact_non_arithmetic_rows(
            &cpu,
            size,
            layout.first_wit_id(),
            layout.num_arithmetic_wit_cols(),
        );
        let gpu = hal
            .witgen
            .witgen_secp256k1_relations(
                &phase1,
                &records,
                false,
                size,
                cpu.height(),
                cpu.n_col(),
                cpu_structural.n_col(),
                layout.first_wit_id(),
                layout.num_arithmetic_wit_cols(),
            )
            .unwrap();
        gpu.completion.wait().unwrap();
        let counts = gpu.double_u8.to_vec().unwrap();
        let gpu_rmm = gpu_witness_to_rmm_d2h::<E>(
            &hal,
            gpu.witness,
            size,
            cpu.n_col(),
            InstancePaddingStrategy::Default,
        )
        .unwrap();
        assert_matrix_eq(cpu.values(), gpu_rmm.values(), cpu.n_col());
        let cpu_counts = cpu_lk.into_finalize_result();
        let gpu_counts = gpu_counts(counts);
        assert_eq!(
            cpu_counts[LookupTable::DoubleU8 as usize],
            gpu_counts[LookupTable::DoubleU8 as usize]
        );
        assert!(
            cpu_counts
                .iter()
                .enumerate()
                .all(|(i, table)| i == LookupTable::DoubleU8 as usize || table.is_empty())
        );
        let gpu_structural = gpu_witness_to_rmm_d2h::<E>(
            &hal,
            gpu.structural,
            size,
            cpu_structural.n_col(),
            InstancePaddingStrategy::Default,
        )
        .unwrap();
        assert_eq!(cpu_structural.values(), gpu_structural.values());
    }

    fn assert_direct_secp256k1_double_matches_cpu(size: usize) {
        type E = BabyBearExt4;
        type EC = SwCurve<Secp256k1>;
        let points = random_points::<Secp256k1>(size);
        let instances = points
            .into_iter()
            .map(|p| EllipticCurveDoubleInstance { p })
            .collect::<Vec<_>>();
        let affine =
            WeierstrassDoubleAssignLayout::<E, EC>::compute_compact_secp256k1_affine_results(
                &instances,
            );
        let records = WeierstrassDoubleAssignLayout::<E, EC>::compact_secp256k1_gpu_records(
            &instances, &affine,
        );
        let (test_layout, _, num_witin, num_structural) = setup_double::<E, EC>().unwrap();
        let layout = test_layout.layout;
        assert_eq!(layout.num_arithmetic_wit_cols(), 727);

        let mut cpu = RowMajorMatrix::new(
            instances.len(),
            num_witin as usize,
            InstancePaddingStrategy::Default,
        );
        let mut cpu_structural = RowMajorMatrix::new(
            instances.len(),
            num_structural as usize,
            InstancePaddingStrategy::Default,
        );
        let mut cpu_lk = LkMultiplicity::default();
        layout.phase1_witness_group_with_affine_results(
            WeierstrassDoubleAssignTrace { instances },
            &affine,
            [&mut cpu, &mut cpu_structural],
            &mut cpu_lk,
        );
        let width = cpu.n_col();
        for (row_index, row) in std::ops::DerefMut::deref_mut(&mut cpu)
            .values
            .chunks_mut(width)
            .take(size)
            .enumerate()
        {
            for (col_index, value) in row[..layout.first_wit_id()].iter_mut().enumerate() {
                *value = <E as ExtensionField>::BaseField::from_u64(
                    (row_index * layout.first_wit_id() + col_index + 1) as u64,
                );
            }
        }
        cpu.padding_by_strategy();
        cpu_structural.padding_by_strategy();

        for (record_offset, column_offset) in [(160, 160), (223, 349), (286, 538)] {
            let cpu_bytes = &cpu.values()
                [layout.first_wit_id() + column_offset..layout.first_wit_id() + column_offset + 63];
            assert_eq!(
                &records[record_offset..record_offset + 63],
                &cpu_bytes
                    .iter()
                    .map(|value| value.to_canonical_u64() as u8)
                    .collect::<Vec<_>>(),
                "double packed quotient mismatch record_offset={record_offset} column_offset={column_offset}"
            );
        }

        let hal = gkr_iop::gpu::get_cuda_hal().unwrap();
        // Make suffix scatter observable too; instruction phase 1 places VM,
        // register, memory, and fetch-derived cells after the arithmetic range.
        let arithmetic_end = layout.first_wit_id() + layout.num_arithmetic_wit_cols();
        let width = cpu.n_col();
        let suffix_cols = width - arithmetic_end;
        for (row_index, row) in std::ops::DerefMut::deref_mut(&mut cpu)
            .values
            .chunks_mut(width)
            .take(size)
            .enumerate()
        {
            for (suffix_index, value) in row[arithmetic_end..].iter_mut().enumerate() {
                *value = <E as ExtensionField>::BaseField::from_u64(
                    (10_000 + row_index * suffix_cols + suffix_index) as u64,
                );
            }
        }
        let phase1 = compact_non_arithmetic_rows(
            &cpu,
            size,
            layout.first_wit_id(),
            layout.num_arithmetic_wit_cols(),
        );
        let gpu = hal
            .witgen
            .witgen_secp256k1_relations(
                &phase1,
                &records,
                true,
                size,
                cpu.height(),
                cpu.n_col(),
                cpu_structural.n_col(),
                layout.first_wit_id(),
                layout.num_arithmetic_wit_cols(),
            )
            .unwrap();
        gpu.completion.wait().unwrap();
        let counts = gpu.double_u8.to_vec().unwrap();
        let gpu_rmm = gpu_witness_to_rmm_d2h::<E>(
            &hal,
            gpu.witness,
            size,
            cpu.n_col(),
            InstancePaddingStrategy::Default,
        )
        .unwrap();
        assert_matrix_eq(cpu.values(), gpu_rmm.values(), cpu.n_col());
        let cpu_counts = cpu_lk.into_finalize_result();
        let gpu_counts = gpu_counts(counts);
        assert_eq!(
            cpu_counts[LookupTable::DoubleU8 as usize],
            gpu_counts[LookupTable::DoubleU8 as usize]
        );
        assert!(
            cpu_counts
                .iter()
                .enumerate()
                .all(|(i, table)| i == LookupTable::DoubleU8 as usize || table.is_empty())
        );
        let gpu_structural = gpu_witness_to_rmm_d2h::<E>(
            &hal,
            gpu.structural,
            size,
            cpu_structural.n_col(),
            InstancePaddingStrategy::Default,
        )
        .unwrap();
        assert_eq!(cpu_structural.values(), gpu_structural.values());
    }

    #[test]
    fn direct_secp256k1_add_rows_lookup_height_and_padding_match_cpu() {
        for size in [1, 127, 128, 129, 11_709] {
            assert_direct_secp256k1_add_matches_cpu(size);
        }
    }

    #[test]
    fn direct_secp256k1_double_rows_lookup_height_and_padding_match_cpu() {
        for size in [1, 127, 128, 129, 23_552] {
            assert_direct_secp256k1_double_matches_cpu(size);
        }
    }

    #[test]
    fn instruction_phase1_secp256k1_add_and_double_cover_scattered_columns() {
        type E = BabyBearExt4;
        type EC = SwCurve<Secp256k1>;

        const fn load_immediate(rd: u32, imm: u32) -> EncodedInstruction {
            encode_rv32u(InsnKind::ADDI, 0, 0, rd, imm)
        }

        let p_addr = CENO_PLATFORM.heap.start;
        let q_addr = p_addr + 64;
        let [p, q] = random_point_pairs::<Secp256k1>(1).pop().unwrap();
        let image = p
            .into_iter()
            .enumerate()
            .map(|(i, word)| (p_addr + (i * 4) as u32, word))
            .chain(
                q.into_iter()
                    .enumerate()
                    .map(|(i, word)| (q_addr + (i * 4) as u32, word)),
            )
            .collect::<BTreeMap<_, _>>();
        let instructions = vec![
            load_immediate(Platform::reg_arg0() as u32, p_addr),
            load_immediate(Platform::reg_arg1() as u32, q_addr),
            load_immediate(Platform::reg_ecall() as u32, Secp256k1AddSpec::CODE),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            load_immediate(Platform::reg_arg0() as u32, p_addr),
            load_immediate(Platform::reg_ecall() as u32, Secp256k1DoubleSpec::CODE),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            load_immediate(Platform::reg_ecall() as u32, Platform::ecall_halt()),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ];
        let pc = CENO_PLATFORM.pc_base();
        let program = Program::new(pc, pc, p_addr, instructions, image);
        let mut vm: VMState = VMState::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            Arc::new(program),
            FullTracerConfig { max_step_shard: 32 },
        );
        vm.iter_until_halt().collect::<Result<Vec<_>, _>>().unwrap();
        let steps = vm.tracer().recorded_steps().to_vec();
        let syscall_witnesses = Arc::new(vm.tracer().syscall_witnesses().to_vec());

        let mut add_cs = ConstraintSystem::<E>::new(|| "secp256k1 add instruction phase1");
        let mut add_cb = CircuitBuilder::new(&mut add_cs);
        let (add_config, _) = WeierstrassAddAssignInstruction::<E, EC>::build_gkr_iop_circuit(
            &mut add_cb,
            &crate::structs::ProgramParams::default(),
        )
        .unwrap();
        let add_index = steps
            .iter()
            .position(|step| {
                step.rs1()
                    .is_some_and(|rs1| rs1.value == Secp256k1AddSpec::CODE)
            })
            .unwrap();
        let mut add_ctx = ShardContext::default();
        add_ctx.syscall_witnesses = syscall_witnesses.clone();
        let (add_witness, add_lk) = WeierstrassAddAssignInstruction::<E, EC>::assign_instances(
            &add_config,
            &mut add_ctx,
            add_cb.cs.num_witin as usize,
            add_cb.cs.num_structural_witin as usize,
            &steps,
            &[add_index],
        )
        .unwrap();
        assert!(add_witness.iter().all(RowMajorMatrix::has_device_backing));
        assert!(add_lk.iter().any(|table| !table.is_empty()));

        let mut double_cs = ConstraintSystem::<E>::new(|| "secp256k1 double instruction phase1");
        let mut double_cb = CircuitBuilder::new(&mut double_cs);
        let (double_config, _) =
            WeierstrassDoubleAssignInstruction::<E, EC>::build_gkr_iop_circuit(
                &mut double_cb,
                &crate::structs::ProgramParams::default(),
            )
            .unwrap();
        let double_index = steps
            .iter()
            .position(|step| {
                step.rs1()
                    .is_some_and(|rs1| rs1.value == Secp256k1DoubleSpec::CODE)
            })
            .unwrap();
        let mut double_ctx = ShardContext::default();
        double_ctx.syscall_witnesses = syscall_witnesses;
        let (double_witness, double_lk) =
            WeierstrassDoubleAssignInstruction::<E, EC>::assign_instances(
                &double_config,
                &mut double_ctx,
                double_cb.cs.num_witin as usize,
                double_cb.cs.num_structural_witin as usize,
                &steps,
                &[double_index],
            )
            .unwrap();
        assert!(
            double_witness
                .iter()
                .all(RowMajorMatrix::has_device_backing)
        );
        assert!(double_lk.iter().any(|table| !table.is_empty()));
    }
}
