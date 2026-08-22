use ceno_gpu::Buffer;
use ff_ext::ExtensionField;
use gkr_iop::{tables::LookupTable, utils::lk_multiplicity::LkMultiplicity};
use p3::field::PrimeCharacteristicRing;
use witness::{DeviceMatrixLayout, RowMajorMatrix};

use crate::error::ZKVMError;

pub(crate) fn enabled() -> bool {
    std::env::var_os("CENO_I055_GPU_SECP_RELATIONS").is_some_and(|v| v != "0")
}

pub(crate) fn fill_structural_ones<E: ExtensionField>(
    structural: &mut RowMajorMatrix<E::BaseField>,
    valid_rows: usize,
) {
    let width = structural.n_col();
    for row in std::ops::DerefMut::deref_mut(structural)
        .values
        .chunks_mut(width)
        .take(valid_rows)
    {
        row.fill(E::BaseField::ONE);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assign_relations<E: ExtensionField>(
    raw_witin: &mut RowMajorMatrix<E::BaseField>,
    records: &[u8],
    is_double: bool,
    valid_rows: usize,
    first_wit_col: usize,
    num_arithmetic_cols: usize,
    lk: &mut LkMultiplicity,
) -> Result<(), ZKVMError> {
    type BB = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB>() {
        return Err(ZKVMError::InvalidWitness(
            "I055 direct secp256k1 relations require BabyBear".into(),
        ));
    }
    let hal = gkr_iop::gpu::get_cuda_hal().map_err(|e| {
        ZKVMError::InvalidWitness(format!("I055 direct secp256k1 CUDA unavailable: {e}").into())
    })?;
    let initial: &[BB] = unsafe {
        std::slice::from_raw_parts(raw_witin.values().as_ptr().cast(), raw_witin.values().len())
    };
    let result = tracing::info_span!(
        "secp256k1_gpu_relation_module",
        operation = if is_double { "double" } else { "add" },
        n = valid_rows
    )
    .in_scope(|| {
        hal.witgen.witgen_secp256k1_relations(
            initial,
            records,
            is_double,
            valid_rows,
            raw_witin.height(),
            raw_witin.n_col(),
            first_wit_col,
            num_arithmetic_cols,
        )
    })
    .map_err(|e| ZKVMError::InvalidWitness(format!("I055 secp256k1 GPU failed: {e}").into()))?;

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
    raw_witin.set_device_backing(result.witness.device_buffer, DeviceMatrixLayout::ColMajor);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instructions::gpu::utils::d2h::gpu_witness_to_rmm_d2h,
        precompiles::{
            EllipticCurveAddInstance, EllipticCurveDoubleInstance, WeierstrassAddAssignLayout,
            WeierstrassAddAssignTrace, WeierstrassDoubleAssignLayout, WeierstrassDoubleAssignTrace,
            random_point_pairs, random_points, setup_weierstrass_add_circuit as setup_add,
            setup_weierstrass_double_circuit as setup_double,
        },
    };
    use ff_ext::{BabyBearExt4, SmallField};
    use gkr_iop::{ProtocolWitnessGenerator, tables::LookupTable};
    use sp1_curves::weierstrass::{SwCurve, secp256k1::Secp256k1};
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

    #[test]
    fn direct_secp256k1_add_rows_lookup_height_and_padding_match_cpu() {
        type E = BabyBearExt4;
        type EC = SwCurve<Secp256k1>;
        let points = random_point_pairs::<Secp256k1>(5);
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
        let initial = vec![<E as ExtensionField>::BaseField::ZERO; cpu.height() * cpu.n_col()];
        let gpu = hal
            .witgen
            .witgen_secp256k1_relations(
                &initial,
                &records,
                false,
                5,
                cpu.height(),
                cpu.n_col(),
                layout.first_wit_id(),
                layout.num_arithmetic_wit_cols(),
            )
            .unwrap();
        let counts = gpu.double_u8.to_vec().unwrap();
        let gpu_rmm = gpu_witness_to_rmm_d2h::<E>(
            &hal,
            gpu.witness,
            5,
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
        let mut gpu_structural =
            RowMajorMatrix::new(5, num_structural as usize, InstancePaddingStrategy::Default);
        fill_structural_ones::<E>(&mut gpu_structural, 5);
        assert_eq!(cpu_structural.values(), gpu_structural.values());
    }

    #[test]
    fn direct_secp256k1_double_rows_lookup_height_and_padding_match_cpu() {
        type E = BabyBearExt4;
        type EC = SwCurve<Secp256k1>;
        let points = random_points::<Secp256k1>(5);
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
        let initial = vec![<E as ExtensionField>::BaseField::ZERO; cpu.height() * cpu.n_col()];
        let gpu = hal
            .witgen
            .witgen_secp256k1_relations(
                &initial,
                &records,
                true,
                5,
                cpu.height(),
                cpu.n_col(),
                layout.first_wit_id(),
                layout.num_arithmetic_wit_cols(),
            )
            .unwrap();
        let counts = gpu.double_u8.to_vec().unwrap();
        let gpu_rmm = gpu_witness_to_rmm_d2h::<E>(
            &hal,
            gpu.witness,
            5,
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
        let mut gpu_structural =
            RowMajorMatrix::new(5, num_structural as usize, InstancePaddingStrategy::Default);
        fill_structural_ones::<E>(&mut gpu_structural, 5);
        assert_eq!(cpu_structural.values(), gpu_structural.values());
    }
}
