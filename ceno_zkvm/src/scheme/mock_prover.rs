use super::utils::{first_layer_selector_contexts, wit_infer_by_expr};
#[cfg(not(feature = "llama-tiny"))]
use crate::tables::{LlamaTinyRom, ProductionSoftmaxExpHighRom, ProductionSoftmaxExpMiddleRom};
use crate::{
    ROMType,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    structs::{ComposedConstrainSystem, ProgramParams, RAMType, ZKVMFixedTraces},
    tables::{ProgramTableCircuit, RMMCollections, TableCircuit},
    witness::LkMultiplicity,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ceno_emul::{ByteAddr, CENO_PLATFORM, Program};
use either::Either;
use ff_ext::{BabyBearExt4, ExtensionField, GoldilocksExt2, SmallField};
use generic_static::StaticTypeMap;
use gkr_iop::{
    selector::{SelectorContext, SelectorType},
    tables::{
        LookupTable, OpsTable,
        ops::{AndTable, LtuTable, OrTable, PowTable, XorTable},
    },
    utils::lk_multiplicity::{LkMultiplicityRaw, Multiplicity},
};
use itertools::{Itertools, chain, enumerate, izip};
use multilinear_extensions::{
    Expression, WitnessId, fmt,
    mle::{ArcMultilinearExtension, FieldType, MultilinearExtension},
    util::ceil_log2,
    utils::{eval_by_expr, eval_by_expr_with_fixed, eval_by_expr_with_instance},
};
use p3::field::{Field, PrimeCharacteristicRing as FieldAlgebra};
use rand::thread_rng;
use std::{
    cmp::max,
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Debug,
    fs::File,
    hash::Hash,
    io::{BufReader, ErrorKind},
    marker::PhantomData,
    sync::{Arc, OnceLock},
};
use strum::IntoEnumIterator;
use tiny_keccak::{Hasher, Keccak};
use witness::next_pow2_instance_padding;

const MAX_CONSTRAINT_DEGREE: usize = 3;
const MOCK_PROGRAM_SIZE: usize = 32;
const MAX_MOCK_CHIP_HOST_BYTES: usize = 2 * 1024 * 1024 * 1024;
pub const MOCK_PC_START: ByteAddr = ByteAddr(0x0800_0000);

type MockRamRecords<E> = HashMap<String, (Vec<(E, usize)>, String)>;

#[derive(Default)]
struct MockTaskSelectorMasks<E: ExtensionField> {
    zero: Option<ArcMultilinearExtension<'static, E>>,
    lookup: Option<ArcMultilinearExtension<'static, E>>,
    read: Option<ArcMultilinearExtension<'static, E>>,
    write: Option<ArcMultilinearExtension<'static, E>>,
    host_bytes: usize,
}

#[cfg(feature = "gpu")]
fn exact_gpu_selector_masks<E: ExtensionField>(
    circuit_name: &str,
    composed_cs: &ComposedConstrainSystem<E>,
    num_instances: [usize; 2],
    num_vars: usize,
) -> MockTaskSelectorMasks<E> {
    let cs = &composed_cs.zkvm_v1_css;
    let gkr_circuit = composed_cs
        .gkr_circuit
        .as_ref()
        .unwrap_or_else(|| panic!("exact GPU mock requires a GKR circuit: {circuit_name}"));
    let first_layer = gkr_circuit
        .layers
        .first()
        .unwrap_or_else(|| panic!("exact GPU mock requires a first GKR layer: {circuit_name}"));
    let selector_ctxs =
        first_layer_selector_contexts(composed_cs, gkr_circuit, num_instances, num_vars);
    assert_eq!(
        selector_ctxs.len(),
        first_layer.out_sel_and_eval_exprs.len(),
        "exact GPU mock selector context/group count mismatch: {circuit_name}"
    );

    let mut cache: Vec<(
        SelectorType<E>,
        SelectorContext,
        ArcMultilinearExtension<'static, E>,
    )> = vec![];
    let mut derive = |role: &str,
                      selector: Option<&SelectorType<E>>,
                      required: bool|
     -> Option<ArcMultilinearExtension<'static, E>> {
        let Some(selector) = selector else {
            assert!(
                !required,
                "exact GPU mock missing {role} selector for active expressions: {circuit_name}"
            );
            return None;
        };
        assert!(
            !matches!(selector, SelectorType::None),
            "exact GPU mock does not accept SelectorType::None for {role}: {circuit_name}"
        );

        let matching_ctxs = first_layer
            .out_sel_and_eval_exprs
            .iter()
            .zip_eq(selector_ctxs.iter())
            .filter_map(|((candidate, outputs), ctx)| {
                (candidate == selector && !outputs.is_empty()).then_some(ctx)
            })
            .collect_vec();
        let ctx = *matching_ctxs.first().unwrap_or_else(|| {
            panic!(
                "exact GPU mock {role} selector is absent from first-layer groups: {circuit_name}"
            )
        });
        assert!(
            matching_ctxs.iter().all(|candidate| {
                candidate.offset == ctx.offset
                    && candidate.num_instances == ctx.num_instances
                    && candidate.num_vars == ctx.num_vars
            }),
            "exact GPU mock {role} selector has conflicting first-layer contexts: {circuit_name}"
        );
        assert_eq!(
            ctx.num_vars, num_vars,
            "exact GPU mock {role} selector rotation/domain mismatch: {circuit_name}"
        );
        assert!(
            ctx.offset
                .checked_add(ctx.num_instances)
                .is_some_and(|end| end <= (1usize << num_vars)),
            "exact GPU mock {role} selector range exceeds its domain: {circuit_name}"
        );

        if let Some((_, _, mask)) = cache.iter().find(|(cached_selector, cached_ctx, _)| {
            cached_selector == selector
                && cached_ctx.offset == ctx.offset
                && cached_ctx.num_instances == ctx.num_instances
                && cached_ctx.num_vars == ctx.num_vars
        }) {
            return Some(mask.clone());
        }

        assert!(
            matches!(
                selector,
                SelectorType::Whole(_)
                    | SelectorType::Prefix(_)
                    | SelectorType::OrderedSparse { .. }
            ),
            "exact GPU mock unsupported {role} selector type for row-mask materialization: {circuit_name}: {selector:?}"
        );
        let selector_mle = selector.to_mle(ctx).unwrap_or_else(|| {
            panic!("exact GPU mock {role} selector produced no mask: {circuit_name}")
        });
        let mask: ArcMultilinearExtension<'static, E> = match selector_mle.evaluations() {
            FieldType::Base(values) => {
                MultilinearExtension::from_evaluations_vec(num_vars, values.to_vec()).into()
            }
            FieldType::Ext(values) => {
                MultilinearExtension::from_evaluations_ext_vec(num_vars, values.to_vec()).into()
            }
            FieldType::Unreachable => unreachable!(),
        };
        assert_eq!(
            mask.num_vars(),
            num_vars,
            "exact GPU mock {role} selector mask num-vars mismatch: {circuit_name}"
        );
        assert_eq!(
            mask.evaluations().len(),
            1usize << num_vars,
            "exact GPU mock {role} selector mask length mismatch: {circuit_name}"
        );
        assert!(
            selector_mask_is_boolean(&mask),
            "exact GPU mock {role} selector mask is non-Boolean: {circuit_name}"
        );
        tracing::info!(
            circuit = %circuit_name,
            role,
            selector_type = selector_type_name(selector),
            offset = ctx.offset,
            logical_instances = ctx.num_instances,
            num_vars = ctx.num_vars,
            active_rows = selector_mask_active_rows(&mask),
            "MockProver selector-context equivalence audit"
        );
        cache.push((selector.clone(), ctx.clone(), mask.clone()));
        Some(mask)
    };

    let zero = derive(
        "zero",
        cs.zero_selector.as_ref(),
        !cs.assert_zero_expressions.is_empty() || !cs.assert_zero_sumcheck_expressions.is_empty(),
    );
    let lookup = derive(
        "lookup",
        cs.lk_selector.as_ref(),
        !cs.lk_expressions.is_empty(),
    );
    let read = derive(
        "read",
        cs.r_selector.as_ref(),
        !cs.r_expressions.is_empty() || !cs.r_table_expressions.is_empty(),
    );
    let write = derive(
        "write",
        cs.w_selector.as_ref(),
        !cs.w_expressions.is_empty() || !cs.w_table_expressions.is_empty(),
    );
    let host_bytes = cache
        .iter()
        .map(|(_, _, mask)| match mask.evaluations() {
            FieldType::Base(values) => values.len() * std::mem::size_of::<E::BaseField>(),
            FieldType::Ext(values) => values.len() * std::mem::size_of::<E>(),
            FieldType::Unreachable => unreachable!(),
        })
        .sum();
    MockTaskSelectorMasks {
        zero,
        lookup,
        read,
        write,
        host_bytes,
    }
}

fn selector_type_name<E: ExtensionField>(selector: &SelectorType<E>) -> &'static str {
    match selector {
        SelectorType::None => "None",
        SelectorType::Whole(_) => "Whole",
        SelectorType::Prefix(_) => "Prefix",
        SelectorType::OrderedSparse { .. } => "OrderedSparse",
        SelectorType::QuarkBinaryTreeLessThan(_) => "QuarkBinaryTreeLessThan",
    }
}

fn selector_mask_is_boolean<E: ExtensionField>(mask: &ArcMultilinearExtension<E>) -> bool {
    match mask.evaluations() {
        FieldType::Base(values) => values
            .iter()
            .all(|value| *value == E::BaseField::ZERO || *value == E::BaseField::ONE),
        FieldType::Ext(values) => values
            .iter()
            .all(|value| *value == E::ZERO || *value == E::ONE),
        FieldType::Unreachable => false,
    }
}

fn selector_mask_active_rows<E: ExtensionField>(mask: &ArcMultilinearExtension<E>) -> usize {
    match mask.evaluations() {
        FieldType::Base(values) => values
            .iter()
            .filter(|value| **value == E::BaseField::ONE)
            .count(),
        FieldType::Ext(values) => values.iter().filter(|value| **value == E::ONE).count(),
        FieldType::Unreachable => 0,
    }
}

fn selector_mask_is_active<E: ExtensionField>(
    mask: &ArcMultilinearExtension<E>,
    index: usize,
) -> bool {
    match mask.evaluations() {
        FieldType::Base(values) => values[index] == E::BaseField::ONE,
        FieldType::Ext(values) => values[index] == E::ONE,
        FieldType::Unreachable => unreachable!(),
    }
}

struct MockRamRws<E: ExtensionField> {
    reads: HashMap<E, usize>,
    reads_by_annotation: MockRamRecords<E>,
    writes: HashMap<E, usize>,
    writes_by_annotation: MockRamRecords<E>,
    global_state: HashMap<String, Vec<Vec<E>>>,
    raw_samples: HashMap<E, Vec<u64>>,
}

impl<E: ExtensionField> Default for MockRamRws<E> {
    fn default() -> Self {
        Self {
            reads: HashMap::new(),
            reads_by_annotation: HashMap::new(),
            writes: HashMap::new(),
            writes_by_annotation: HashMap::new(),
            global_state: HashMap::new(),
            raw_samples: HashMap::new(),
        }
    }
}

fn mle_row_value<E: ExtensionField>(mle: &ArcMultilinearExtension<E>, row: usize) -> E {
    match mle.evaluations() {
        FieldType::Base(values) => E::from(values[row % values.len()]),
        FieldType::Ext(values) => values[row % values.len()],
        FieldType::Unreachable => unreachable!(),
    }
}

#[allow(clippy::too_many_arguments)]
fn raw_record_at_row<E: ExtensionField>(
    raw_record: &[Expression<E>],
    fixed: &[ArcMultilinearExtension<E>],
    witness: &[ArcMultilinearExtension<E>],
    structural_witness: &[ArcMultilinearExtension<E>],
    circuit_pi_mles: &[ArcMultilinearExtension<E>],
    circuit_pub_io_evals: &[Either<E::BaseField, E>],
    challenges: &[E],
    row: usize,
) -> Vec<u64> {
    let fixed = fixed
        .iter()
        .map(|mle| mle_row_value(mle, row))
        .collect_vec();
    let witness = witness
        .iter()
        .map(|mle| mle_row_value(mle, row))
        .collect_vec();
    let structural_witness = structural_witness
        .iter()
        .map(|mle| mle_row_value(mle, row))
        .collect_vec();
    let instance = circuit_pi_mles
        .iter()
        .map(|mle| mle_row_value(mle, row))
        .chain(circuit_pub_io_evals.iter().map(|value| match value {
            Either::Left(value) => E::from(*value),
            Either::Right(value) => *value,
        }))
        .collect_vec();
    raw_record
        .iter()
        .map(|expr| {
            eval_by_expr_with_instance(
                &fixed,
                &witness,
                &structural_witness,
                &instance,
                challenges,
                expr,
            )
            .map_either(E::from, |value| value)
            .into_inner()
            .to_canonical_u64()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn accumulate_ram_rws<E: ExtensionField>(
    circuit_name: &str,
    cs: &ConstraintSystem<E>,
    fixed: &[ArcMultilinearExtension<E>],
    witness: &[ArcMultilinearExtension<E>],
    structural_witness: &[ArcMultilinearExtension<E>],
    circuit_pi_mles: &[ArcMultilinearExtension<E>],
    circuit_pub_io_evals: &[Either<E::BaseField, E>],
    challenges: &[E],
    num_rows: usize,
    selector_masks: Option<&MockTaskSelectorMasks<E>>,
    ram_type: RAMType,
    accumulator: &mut MockRamRws<E>,
) {
    let w_selector: ArcMultilinearExtension<_> =
        if let Some(selector) = selector_masks.and_then(|masks| masks.write.as_ref()) {
            selector.clone()
        } else if let Some(w_selector) = &cs.w_selector {
            structural_witness[w_selector.selector_expr().id()].clone()
        } else {
            let mut selector = vec![E::BaseField::ONE; num_rows];
            selector.resize(next_pow2_instance_padding(num_rows), E::BaseField::ZERO);
            MultilinearExtension::from_evaluation_vec_smart(
                ceil_log2(next_pow2_instance_padding(num_rows)),
                selector,
            )
            .into()
        };

    for ((w_rlc_expr, annotation), (ram_type_expr, raw_record)) in (cs
        .w_expressions
        .iter()
        .chain(cs.w_table_expressions.iter().map(|expr| &expr.expr)))
    .zip_eq(
        cs.w_expressions_namespace_map
            .iter()
            .chain(cs.w_table_expressions_namespace_map.iter()),
    )
    .zip_eq(cs.w_ram_types.iter())
    {
        let ram_type_mle = wit_infer_by_expr(
            ram_type_expr,
            cs.num_witin,
            cs.num_fixed as WitnessId,
            0,
            fixed,
            witness,
            structural_witness,
            circuit_pi_mles,
            circuit_pub_io_evals,
            challenges,
        );
        let write_rlc_records = wit_infer_by_expr(
            w_rlc_expr,
            cs.num_witin,
            cs.num_fixed as WitnessId,
            0,
            fixed,
            witness,
            structural_witness,
            circuit_pi_mles,
            circuit_pub_io_evals,
            challenges,
        );
        let ram_type_vec = ram_type_mle.get_ext_field_vec();
        let write_rlc_records = write_rlc_records.get_ext_field_vec();
        let write_rlc_records = write_rlc_records
            .iter()
            .copied()
            .enumerate()
            .filter(|(i, _)| {
                ram_type_vec[*i] == E::from_u32(ram_type as u32)
                    && selector_mask_is_active(&w_selector, *i)
            })
            .collect_vec();
        if write_rlc_records.is_empty() {
            continue;
        }

        let mut records = vec![];
        let selected_rows = write_rlc_records.len();
        for (row, (physical_row, record_rlc)) in enumerate(write_rlc_records) {
            if ram_type == RAMType::Custom && record_rlc == E::ZERO {
                continue;
            }
            *accumulator.writes.entry(record_rlc).or_default() += 1;
            if selected_rows <= 4096 || row < 2 || row + 2 >= selected_rows {
                accumulator.raw_samples.insert(
                    record_rlc,
                    raw_record_at_row(
                        raw_record,
                        fixed,
                        witness,
                        structural_witness,
                        circuit_pi_mles,
                        circuit_pub_io_evals,
                        challenges,
                        physical_row,
                    ),
                );
            }
            records.push((record_rlc, row));
        }
        accumulator
            .writes_by_annotation
            .insert(annotation.clone(), (records, circuit_name.to_owned()));
    }

    let r_selector: ArcMultilinearExtension<_> =
        if let Some(selector) = selector_masks.and_then(|masks| masks.read.as_ref()) {
            selector.clone()
        } else if let Some(r_selector) = &cs.r_selector {
            structural_witness[r_selector.selector_expr().id()].clone()
        } else {
            let mut selector = vec![E::BaseField::ONE; num_rows];
            selector.resize(next_pow2_instance_padding(num_rows), E::BaseField::ZERO);
            MultilinearExtension::from_evaluation_vec_smart(
                ceil_log2(next_pow2_instance_padding(num_rows)),
                selector,
            )
            .into()
        };

    for ((r_rlc_expr, annotation), (ram_type_expr, r_exprs)) in (cs
        .r_expressions
        .iter()
        .chain(cs.r_table_expressions.iter().map(|expr| &expr.expr)))
    .zip_eq(
        cs.r_expressions_namespace_map
            .iter()
            .chain(cs.r_table_expressions_namespace_map.iter()),
    )
    .zip_eq(cs.r_ram_types.iter())
    {
        let ram_type_mle = wit_infer_by_expr(
            ram_type_expr,
            cs.num_witin,
            cs.num_fixed as WitnessId,
            0,
            fixed,
            witness,
            structural_witness,
            circuit_pi_mles,
            circuit_pub_io_evals,
            challenges,
        );
        let read_records = wit_infer_by_expr(
            r_rlc_expr,
            cs.num_witin,
            cs.num_fixed as WitnessId,
            0,
            fixed,
            witness,
            structural_witness,
            circuit_pi_mles,
            circuit_pub_io_evals,
            challenges,
        );
        let ram_type_vec = ram_type_mle.get_ext_field_vec();
        let read_records = read_records.get_ext_field_vec();
        let read_records = read_records
            .iter()
            .copied()
            .enumerate()
            .filter(|(i, _)| {
                ram_type_vec[*i] == E::from_u32(ram_type as u32)
                    && selector_mask_is_active(&r_selector, *i)
            })
            .collect_vec();
        if read_records.is_empty() {
            continue;
        }

        if ram_type == RAMType::GlobalState {
            assert_eq!(r_exprs.len(), 3);
            let r = r_exprs
                .iter()
                .skip(1)
                .map(|expr| {
                    let value = wit_infer_by_expr(
                        expr,
                        cs.num_witin,
                        cs.num_fixed as WitnessId,
                        0,
                        fixed,
                        witness,
                        structural_witness,
                        circuit_pi_mles,
                        circuit_pub_io_evals,
                        challenges,
                    );
                    filter_mle_by_selector_mle(value, r_selector.clone())
                })
                .collect_vec();
            let r = (0..r[0].len())
                .map(|row| r.iter().map(|values| values[row]).collect_vec())
                .collect_vec();
            assert!(
                accumulator
                    .global_state
                    .insert(circuit_name.to_owned(), r)
                    .is_none()
            );
        }

        let mut records = vec![];
        let selected_rows = read_records.len();
        for (row, (physical_row, record)) in enumerate(read_records) {
            if ram_type == RAMType::Custom && record == E::ZERO {
                continue;
            }
            *accumulator.reads.entry(record).or_default() += 1;
            if selected_rows <= 4096 || row < 2 || row + 2 >= selected_rows {
                accumulator.raw_samples.insert(
                    record,
                    raw_record_at_row(
                        r_exprs,
                        fixed,
                        witness,
                        structural_witness,
                        circuit_pi_mles,
                        circuit_pub_io_evals,
                        challenges,
                        physical_row,
                    ),
                );
            }
            records.push((record, row));
        }
        accumulator
            .reads_by_annotation
            .insert(annotation.clone(), (records, circuit_name.to_owned()));
    }
}

#[cfg(feature = "gpu")]
fn materialize_gpu_mle<E: ExtensionField>(
    circuit_name: &str,
    kind: &str,
    index: usize,
    expected_num_vars: usize,
    mle: &gkr_iop::gpu::MultilinearExtensionGpu<'_, E>,
) -> (ArcMultilinearExtension<'static, E>, usize) {
    type BB = <BabyBearExt4 as ExtensionField>::BaseField;

    assert_eq!(
        std::any::TypeId::of::<E::BaseField>(),
        std::any::TypeId::of::<BB>(),
        "exact GPU mock materialization only supports BabyBear"
    );
    assert_eq!(
        mle.inner().num_vars(),
        expected_num_vars,
        "{circuit_name} {kind}[{index}] num_vars differs from the GPU task domain"
    );
    let padded_len = 1usize
        .checked_shl(expected_num_vars as u32)
        .expect("exact GPU mock padded domain overflow");

    let (cpu_mle, physical_len, field_layout, field_bytes) = match mle.inner() {
        gkr_iop::gpu::GpuFieldType::Base(poly) => {
            let mut values: Vec<E::BaseField> =
                unsafe { std::mem::transmute(poly.to_cpu_vec(None)) };
            let physical_len = values.len();
            assert!(
                physical_len <= padded_len,
                "{circuit_name} {kind}[{index}] base evaluations exceed padded domain"
            );
            values.resize(padded_len, E::BaseField::ZERO);
            (
                MultilinearExtension::from_evaluations_vec(expected_num_vars, values),
                physical_len,
                "base",
                std::mem::size_of::<E::BaseField>(),
            )
        }
        gkr_iop::gpu::GpuFieldType::Ext(poly) => {
            let mut values: Vec<E> = unsafe { std::mem::transmute(poly.to_cpu_vec(None)) };
            let physical_len = values.len();
            assert!(
                physical_len <= padded_len,
                "{circuit_name} {kind}[{index}] extension evaluations exceed padded domain"
            );
            values.resize(padded_len, E::ZERO);
            (
                MultilinearExtension::from_evaluations_ext_vec(expected_num_vars, values),
                physical_len,
                "extension",
                std::mem::size_of::<E>(),
            )
        }
        gkr_iop::gpu::GpuFieldType::VirtualExt(leaf) => {
            assert_eq!(leaf.num_vars, expected_num_vars);
            assert_eq!(leaf.row_offset, 0, "formula MLE row offset changed");
            assert_eq!(leaf.padded_ops, 1, "formula MLE layout changed");
            assert_eq!(leaf.valid_rows as usize, padded_len);
            assert_eq!(leaf.compact_rows as usize, padded_len);
            let values = match leaf.real_ops {
                ceno_gpu::GPU_VIRTUAL_FORMULA_INDEX => {
                    (0..padded_len).map(E::BaseField::from_usize).collect_vec()
                }
                ceno_gpu::GPU_VIRTUAL_FORMULA_INDEX_23 => (0..padded_len)
                    .map(|row| E::BaseField::from_usize(row & ((1usize << 23) - 1)))
                    .collect_vec(),
                ceno_gpu::GPU_VIRTUAL_FORMULA_ZERO => {
                    vec![E::BaseField::ZERO; padded_len]
                }
                ceno_gpu::GPU_VIRTUAL_FORMULA_ONE => {
                    vec![E::BaseField::ONE; padded_len]
                }
                other => panic!(
                    "{circuit_name} {kind}[{index}] unsupported virtual GPU MLE formula {other}"
                ),
            };
            (
                MultilinearExtension::from_evaluations_vec(expected_num_vars, values),
                padded_len,
                "virtual-formula",
                std::mem::size_of::<E::BaseField>(),
            )
        }
        gkr_iop::gpu::GpuFieldType::Unreachable => {
            panic!("{circuit_name} {kind}[{index}] has unreachable GPU MLE layout")
        }
    };
    assert_eq!(cpu_mle.num_vars(), expected_num_vars);
    assert_eq!(cpu_mle.evaluations.len(), padded_len);
    let host_bytes = padded_len
        .checked_mul(field_bytes)
        .expect("exact GPU mock host-byte calculation overflow");
    tracing::info!(
        circuit = %circuit_name,
        kind,
        index,
        expected_num_vars,
        physical_len,
        padded_len,
        field_layout,
        host_bytes,
        "exact GPU MLE materialized for CPU MockProver"
    );
    (Arc::new(cpu_mle), host_bytes)
}

/// Allow LK Multiplicity's key to be used with `u64` and `GoldilocksExt2`.
pub trait LkMultiplicityKey: Copy + Clone + Debug + Eq + Hash + Send {
    /// If key is u64, return Some(u64), otherwise None.
    fn to_u64(&self) -> Option<u64>;
}

impl LkMultiplicityKey for u64 {
    fn to_u64(&self) -> Option<u64> {
        Some(*self)
    }
}

impl LkMultiplicityKey for GoldilocksExt2 {
    fn to_u64(&self) -> Option<u64> {
        None
    }
}

impl LkMultiplicityKey for BabyBearExt4 {
    fn to_u64(&self) -> Option<u64> {
        None
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum MockProverError<E: ExtensionField, K: LkMultiplicityKey> {
    AssertZeroError {
        expression: Expression<E>,
        evaluated: Either<E::BaseField, E>,
        name: String,
        inst_id: usize,
    },
    AssertEqualError {
        left_expression: Expression<E>,
        right_expression: Expression<E>,
        left: Either<E::BaseField, E>,
        right: Either<E::BaseField, E>,
        name: String,
        inst_id: usize,
    },
    DegreeTooHigh {
        expression: Expression<E>,
        degree: usize,
        name: String,
    },
    LookupError {
        rom_type: ROMType,
        expression: Expression<E>,
        evaluated: E,
        name: String,
        inst_id: usize,
    },
    LkMultiplicityError {
        rom_type: ROMType,
        key: K,
        count: isize, // +ve => missing in cs, -ve => missing in assignments
    },
}

impl<E: ExtensionField, K: LkMultiplicityKey> PartialEq for MockProverError<E, K> {
    // Compare errors based on the content, ignoring the inst_id
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                MockProverError::AssertZeroError {
                    expression: left_expression,
                    evaluated: left_evaluated,
                    name: left_name,
                    ..
                },
                MockProverError::AssertZeroError {
                    expression: right_expression,
                    evaluated: right_evaluated,
                    name: right_name,
                    ..
                },
            ) => {
                left_expression == right_expression
                    && left_evaluated == right_evaluated
                    && left_name == right_name
            }
            (
                MockProverError::AssertEqualError {
                    left_expression: left_left_expression,
                    right_expression: left_right_expression,
                    left: left_left,
                    right: left_right,
                    name: left_name,
                    ..
                },
                MockProverError::AssertEqualError {
                    left_expression: right_left_expression,
                    right_expression: right_right_expression,
                    left: right_left,
                    right: right_right,
                    name: right_name,
                    ..
                },
            ) => {
                left_left_expression == right_left_expression
                    && left_right_expression == right_right_expression
                    && left_left == right_left
                    && left_right == right_right
                    && left_name == right_name
            }
            (
                MockProverError::LookupError {
                    expression: left_expression,
                    evaluated: left_evaluated,
                    name: left_name,
                    ..
                },
                MockProverError::LookupError {
                    expression: right_expression,
                    evaluated: right_evaluated,
                    name: right_name,
                    ..
                },
            ) => {
                left_expression == right_expression
                    && left_evaluated == right_evaluated
                    && left_name == right_name
            }
            (
                MockProverError::LkMultiplicityError {
                    rom_type: left_rom_type,
                    key: left_key,
                    count: left_count,
                },
                MockProverError::LkMultiplicityError {
                    rom_type: right_rom_type,
                    key: right_key,
                    count: right_count,
                },
            ) => (left_rom_type, left_key, left_count) == (right_rom_type, right_key, right_count),
            _ => false,
        }
    }
}

impl<E: ExtensionField, K: LkMultiplicityKey> MockProverError<E, K> {
    fn print(&self, wits_in: &[ArcMultilinearExtension<E>], wits_in_name: &[String]) {
        let mut wtns = vec![];

        match self {
            Self::AssertZeroError {
                expression,
                evaluated,
                name,
                inst_id,
            } => {
                let expression_fmt = fmt::expr(expression, &mut wtns, false);
                let wtns_fmt = fmt::wtns(&wtns, wits_in, *inst_id, wits_in_name);
                let eval_fmt = fmt::either_field(*evaluated, false);
                println!(
                    "\nAssertZeroError {name:?}: Evaluated expression is not zero\n\
                    Expression: {expression_fmt}\n\
                    Evaluation: {eval_fmt} != 0\n\
                    Inst[{inst_id}]:\n{wtns_fmt}\n",
                );
            }
            Self::AssertEqualError {
                left_expression,
                right_expression,
                left,
                right,
                name,
                inst_id,
            } => {
                let left_expression_fmt = fmt::expr(left_expression, &mut wtns, false);
                let right_expression_fmt = fmt::expr(right_expression, &mut wtns, false);
                let wtns_fmt = fmt::wtns(&wtns, wits_in, *inst_id, wits_in_name);
                let left_eval_fmt = fmt::either_field(*left, false);
                let right_eval_fmt = fmt::either_field(*right, false);
                println!(
                    "\nAssertEqualError {name:?}\n\
                    Left: {left_eval_fmt} != Right: {right_eval_fmt}\n\
                    Left Expression: {left_expression_fmt}\n\
                    Right Expression: {right_expression_fmt}\n\
                    Inst[{inst_id}]:\n{wtns_fmt}\n",
                );
            }
            Self::DegreeTooHigh {
                expression,
                degree,
                name,
            } => {
                let expression_fmt = fmt::expr(expression, &mut wtns, false);
                println!(
                    "\nDegreeTooHigh {name:?}: Expression degree is too high\n\
                    Expression: {expression_fmt}\n\
                    Degree: {degree} > {MAX_CONSTRAINT_DEGREE}\n",
                );
            }
            Self::LookupError {
                rom_type,
                expression,
                evaluated,
                name,
                inst_id,
            } => {
                let expression_fmt = fmt::expr(expression, &mut wtns, false);
                let wtns_fmt = fmt::wtns(&wtns, wits_in, *inst_id, wits_in_name);
                let eval_fmt = fmt::field(*evaluated);
                println!(
                    "\nLookupError {name:#?}: Evaluated expression does not exist in T vector\n\
                    ROM Type: {rom_type:?}\n\
                    Expression: {expression_fmt}\n\
                    Evaluation: {eval_fmt}\n\
                    Inst[{inst_id}]:\n{wtns_fmt}\n",
                );
            }
            Self::LkMultiplicityError {
                rom_type,
                key,
                count,
                ..
            } => {
                let lookups = if count.abs() > 1 {
                    format!("{} Lookups", count.abs())
                } else {
                    "Lookup".to_string()
                };

                let (location, element) = if let Some(key) = key.to_u64() {
                    let location = if *count > 0 {
                        "constraint system"
                    } else {
                        "assignments"
                    };
                    let element = match rom_type {
                        ROMType::Dynamic => {
                            let left = u64::BITS - 1 - key.leading_zeros();
                            let element = key & ((1 << left) - 1);
                            format!("Dynamic Range Table U{left} with Element: {element:?}")
                        }
                        ROMType::DoubleU8 => {
                            let a = (key >> 8) & u8::MAX as u64;
                            let b = key & (u8::MAX as u64);
                            format!("Double U8 Range Table with Elements: ({a:?}, {b:?})")
                        }
                        ROMType::And => {
                            let (a, b) = AndTable::unpack(key);
                            format!("Element: {a} && {b}")
                        }
                        ROMType::Or => {
                            let (a, b) = OrTable::unpack(key);
                            format!("Element: {a} || {b}")
                        }
                        ROMType::Xor => {
                            let (a, b) = XorTable::unpack(key);
                            format!("Element: {a} ^ {b}")
                        }
                        ROMType::Ltu => {
                            let (a, b) = LtuTable::unpack(key);
                            format!("Element: {a} < {b}")
                        }
                        ROMType::Pow => {
                            let (a, b) = PowTable::unpack(key);
                            format!("Element: {a} ** {b}")
                        }
                        ROMType::Instruction => format!("PC: {key}"),
                        ROMType::LlamaSoftmaxExp3 => format!("llama softmax exp3 digit: {key}"),
                        ROMType::LlamaSoftmaxExp4 => format!("llama softmax exp4 digit: {key}"),
                        ROMType::LlamaProductionSoftmaxExpMiddle => {
                            format!("production softmax middle digit: {key}")
                        }
                        ROMType::LlamaProductionSoftmaxExpHigh => {
                            format!("production softmax high digit: {key}")
                        }
                        ROMType::LlamaRmsInv => format!("llama RMS energy: {key}"),
                        ROMType::LlamaSwiGlu => format!("llama SwiGLU raw i16 key: {key}"),
                    };
                    (location, element)
                } else {
                    (
                        if *count > 0 {
                            "combined_lkm_tables"
                        } else {
                            "combined_lkm_opcodes"
                        },
                        format!("Element: {key:?}"),
                    )
                };
                println!(
                    "\nLkMultiplicityError:\n\
                    {lookups} of {rom_type:?} missing in {location}\n\
                    {element}\n"
                );
            }
        }
    }

    #[cfg(test)]
    fn inst_id(&self) -> usize {
        match self {
            Self::AssertZeroError { inst_id, .. }
            | Self::AssertEqualError { inst_id, .. }
            | Self::LookupError { inst_id, .. } => *inst_id,
            Self::DegreeTooHigh { .. } | Self::LkMultiplicityError { .. } => unreachable!(),
        }
    }

    fn contains(&self, constraint_name: &str) -> bool {
        format!("{:?}", self).contains(constraint_name)
    }
}

pub struct MockProver<E: ExtensionField> {
    _phantom: PhantomData<E>,
}

fn load_tables<E: ExtensionField>(
    cs: &ConstraintSystem<E>,
    challenge: [E; 2],
) -> HashSet<Vec<u64>> {
    fn load_dynamic_range_table<E: ExtensionField, const MAX_BITS: usize>(
        t_vec: &mut Vec<Vec<u64>>,
        cs: &ConstraintSystem<E>,
        challenge: [E; 2],
    ) {
        for (i, bits) in std::iter::once(0)
            .chain((0..=MAX_BITS).flat_map(|i| 0..(1 << i)))
            .zip(
                std::iter::once(0)
                    .chain((0..=MAX_BITS).flat_map(|i| std::iter::repeat_n(i, 1 << i))),
            )
        {
            let rlc_record = cs.rlc_chip_record(vec![
                (LookupTable::Dynamic as usize).into(),
                (i as usize).into(),
                bits.into(),
            ]);
            let rlc_record = eval_by_expr(&[], &[], &challenge, &rlc_record);
            t_vec.push(rlc_record.to_canonical_u64_vec());
        }
    }

    fn load_double_u8_range_table<E: ExtensionField>(
        t_vec: &mut Vec<Vec<u64>>,
        cs: &ConstraintSystem<E>,
        challenge: [E; 2],
    ) {
        for (a, b) in (0..(1 << 8))
            .flat_map(|i| std::iter::repeat_n(i, 1 << 8))
            .zip(std::iter::repeat_n(0, 1 << 8).flat_map(|_| 0..(1 << 8)))
        {
            let rlc_record = cs.rlc_chip_record(vec![
                (LookupTable::DoubleU8 as usize).into(),
                a.into(),
                b.into(),
            ]);
            let rlc_record = eval_by_expr(&[], &[], &challenge, &rlc_record);
            t_vec.push(rlc_record.to_canonical_u64_vec());
        }
    }

    fn load_op_table<OP: OpsTable, E: ExtensionField>(
        t_vec: &mut Vec<Vec<u64>>,
        cs: &ConstraintSystem<E>,
        challenge: [E; 2],
    ) {
        for [a, b, c] in OP::content() {
            let rlc_record = cs.rlc_chip_record(vec![
                (OP::ROM_TYPE as usize).into(),
                (a as usize).into(),
                (b as usize).into(),
                (c as usize).into(),
            ]);
            let rlc_record = eval_by_expr(&[], &[], &challenge, &rlc_record);
            t_vec.push(rlc_record.to_canonical_u64_vec());
        }
    }

    let mut table_vec = vec![];
    load_dynamic_range_table::<_, { crate::scheme::constants::DYNAMIC_RANGE_MAX_BITS }>(
        &mut table_vec,
        cs,
        challenge,
    );
    load_double_u8_range_table(&mut table_vec, cs, challenge);
    load_op_table::<AndTable, _>(&mut table_vec, cs, challenge);
    load_op_table::<OrTable, _>(&mut table_vec, cs, challenge);
    load_op_table::<XorTable, _>(&mut table_vec, cs, challenge);
    load_op_table::<LtuTable, _>(&mut table_vec, cs, challenge);
    if E::BaseField::bits() > 32 {
        // this pow table only work on large prime field
        load_op_table::<PowTable, _>(&mut table_vec, cs, challenge);
    }
    #[cfg(not(feature = "llama-tiny"))]
    fn load_production_rom<R: LlamaTinyRom, E: ExtensionField>(
        t_vec: &mut Vec<Vec<u64>>,
        cs: &ConstraintSystem<E>,
        challenge: [E; 2],
    ) {
        for index in 0..R::ROWS {
            let rlc_record = cs.rlc_chip_record(vec![
                (R::CATEGORY as usize).into(),
                R::input(index).into(),
                R::output(index).into(),
            ]);
            t_vec.push(eval_by_expr(&[], &[], &challenge, &rlc_record).to_canonical_u64_vec());
        }
    }
    #[cfg(not(feature = "llama-tiny"))]
    {
        load_production_rom::<ProductionSoftmaxExpMiddleRom, E>(&mut table_vec, cs, challenge);
        load_production_rom::<ProductionSoftmaxExpHighRom, E>(&mut table_vec, cs, challenge);
    }

    HashSet::from_iter(table_vec)
}

// load once per generic type E instantiation
// return challenge and table
#[allow(clippy::type_complexity)]
fn load_once_tables<E: ExtensionField + 'static + Sync + Send>(
    cs: &ConstraintSystem<E>,
) -> ([E; 2], HashSet<Vec<u64>>) {
    static CACHE: OnceLock<StaticTypeMap<([Vec<u64>; 2], HashSet<Vec<u64>>)>> = OnceLock::new();
    let cache = CACHE.get_or_init(StaticTypeMap::new);

    let (challenges_repr, table) = cache.call_once::<E, _>(|| {
        let mut rng = thread_rng();
        let challenge = [E::random(&mut rng), E::random(&mut rng)];
        let mut keccak = Keccak::v256();
        let mut filename_digest = [0u8; 32];
        keccak.update(serde_json::to_string(&challenge).unwrap().as_bytes());
        keccak.finalize(&mut filename_digest);
        let file_path = format!(
            "table_cache_dev_{:?}.json",
            URL_SAFE_NO_PAD.encode(filename_digest)
        );
        let table = match File::open(&file_path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                serde_json::from_reader(reader).unwrap()
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // Cached file doesn't exist, let's make a new one.
                // And carefully avoid exposing a half-written file to other threads,
                // or other runs of this program (in case of a crash).

                let mut file = tempfile::NamedTempFile::new_in(".").unwrap();

                // load new table and seserialize to file for later use
                let table = load_tables(cs, challenge);
                serde_json::to_writer(&mut file, &table).unwrap();
                // Persist the file to the target location
                // This is an atomic operation on Posix-like systems, so we don't have to worry
                // about half-written files.
                // Note, that if another process wrote to our target file in the meantime,
                // we silently overwrite it here.  But that's fine.
                file.persist(file_path).unwrap();
                table
            }
            Err(e) => panic!("{:?}", e),
        };

        (
            challenge.map(|c| {
                c.as_bases()
                    .iter()
                    .map(|b: &E::BaseField| b.to_canonical_u64())
                    .collect_vec()
            }),
            table,
        )
    });
    // reinitialize per generic type E
    (
        challenges_repr.clone().map(|repr| {
            E::from_basis_coefficients_iter(repr.iter().copied().map(E::BaseField::from_u64))
                .expect("challenge repr must describe a valid extension element")
        }),
        table.clone(),
    )
}

impl<'a, E: ExtensionField + Hash> MockProver<E> {
    pub fn run_with_challenge(
        cb: &CircuitBuilder<E>,
        fixed: &[ArcMultilinearExtension<'a, E>],
        wits_in: &[ArcMultilinearExtension<'a, E>],
        structural_witin: &[ArcMultilinearExtension<'a, E>],
        challenge: [E; 2],
        lkm: Option<Multiplicity<u64>>,
    ) -> Result<(), Vec<MockProverError<E, u64>>> {
        Self::run_maybe_challenge(
            cb,
            fixed,
            wits_in,
            structural_witin,
            &[],
            &[],
            &[],
            Some(challenge),
            lkm,
        )
    }

    pub fn run(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        program: &[ceno_emul::Instruction],
        lkm: Option<Multiplicity<u64>>,
    ) -> Result<(), Vec<MockProverError<E, u64>>> {
        Self::run_maybe_challenge(cb, &[], wits_in, &[], program, &[], &[], None, lkm)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_maybe_challenge(
        cb: &CircuitBuilder<E>,
        fixed: &[ArcMultilinearExtension<'a, E>],
        wits_in: &[ArcMultilinearExtension<'a, E>],
        structural_witin: &[ArcMultilinearExtension<'a, E>],
        program: &[ceno_emul::Instruction],
        pi_mles: &[ArcMultilinearExtension<'a, E>],
        pub_io_evals: &[Either<E::BaseField, E>],
        challenge: Option<[E; 2]>,
        lkm: Option<Multiplicity<u64>>,
    ) -> Result<(), Vec<MockProverError<E, u64>>> {
        let program = Program::from(program);
        let (table, challenge) = Self::load_tables_with_program(cb.cs, &program, challenge);

        Self::run_maybe_challenge_with_table(
            cb.cs,
            &table,
            fixed,
            wits_in,
            structural_witin,
            pi_mles,
            pub_io_evals,
            None,
            1,
            challenge,
            lkm,
        )
        .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    fn run_maybe_challenge_with_table(
        cs: &ConstraintSystem<E>,
        table: &HashSet<Vec<u64>>,
        fixed: &[ArcMultilinearExtension<'a, E>],
        wits_in: &[ArcMultilinearExtension<'a, E>],
        structural_witin: &[ArcMultilinearExtension<'a, E>],
        pi_mles: &[ArcMultilinearExtension<'a, E>],
        pub_io_evals: &[Either<E::BaseField, E>],
        selector_masks: Option<&MockTaskSelectorMasks<E>>,
        num_instances: usize,
        challenge: [E; 2],
        expected_lkm: Option<Multiplicity<u64>>,
    ) -> Result<LkMultiplicityRaw<E>, Vec<MockProverError<E, u64>>> {
        let mut shared_lkm = LkMultiplicityRaw::<E>::default();
        let mut errors = vec![];

        let num_instance_padded = wits_in
            .first()
            .or_else(|| fixed.first())
            .or_else(|| pi_mles.first())
            .or_else(|| structural_witin.first())
            .map(|mle| mle.evaluations().len())
            .unwrap_or_else(|| next_pow2_instance_padding(num_instances));

        // Assert zero expressions
        for (expr, name) in cs
            .assert_zero_expressions
            .iter()
            .chain(&cs.assert_zero_sumcheck_expressions)
            .zip_eq(
                cs.assert_zero_expressions_namespace_map
                    .iter()
                    .chain(&cs.assert_zero_sumcheck_expressions_namespace_map),
            )
        {
            if expr.degree() > MAX_CONSTRAINT_DEGREE {
                errors.push(MockProverError::DegreeTooHigh {
                    expression: expr.clone(),
                    degree: expr.degree(),
                    name: name.clone(),
                });
            }

            let zero_selector: ArcMultilinearExtension<_> =
                if let Some(selector) = selector_masks.and_then(|masks| masks.zero.as_ref()) {
                    selector.clone()
                } else if let Some(zero_selector) = &cs.zero_selector {
                    structural_witin[zero_selector.selector_expr().id()].clone()
                } else {
                    let mut selector = vec![E::BaseField::ONE; num_instances];
                    selector.resize(num_instance_padded, E::BaseField::ZERO);
                    MultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(num_instance_padded),
                        selector,
                    )
                    .into()
                };

            // require_equal does not always have the form of Expr::Sum as
            // the sum of witness and constant is expressed as scaled sum
            if let Expression::Sum(left, right) = expr
                && name.contains("require_equal")
            {
                let right = -right.as_ref();

                let left_evaluated = wit_infer_by_expr(
                    left,
                    cs.num_witin,
                    cs.num_fixed as WitnessId,
                    0,
                    fixed,
                    wits_in,
                    structural_witin,
                    pi_mles,
                    pub_io_evals,
                    &challenge,
                );
                let left_evaluated =
                    filter_mle_by_selector_mle(left_evaluated, zero_selector.clone());

                let right_evaluated = wit_infer_by_expr(
                    &right,
                    cs.num_witin,
                    cs.num_fixed as WitnessId,
                    0,
                    fixed,
                    wits_in,
                    structural_witin,
                    pi_mles,
                    pub_io_evals,
                    &challenge,
                );
                let right_evaluated =
                    filter_mle_by_selector_mle(right_evaluated, zero_selector.clone());

                // left_evaluated.len() ?= right_evaluated.len() due to padding instance
                for (inst_id, (left_element, right_element)) in
                    izip!(left_evaluated, right_evaluated).enumerate()
                {
                    if left_element != right_element {
                        errors.push(MockProverError::AssertEqualError {
                            left_expression: *left.clone(),
                            right_expression: right.clone(),
                            left: Either::Right(left_element),
                            right: Either::Right(right_element),
                            name: name.clone(),
                            inst_id,
                        });
                    }
                }
            } else {
                // contains require_zero
                let expr_evaluated = wit_infer_by_expr(
                    expr,
                    cs.num_witin,
                    cs.num_fixed as WitnessId,
                    0,
                    fixed,
                    wits_in,
                    structural_witin,
                    pi_mles,
                    pub_io_evals,
                    &challenge,
                );
                let expr_evaluated =
                    filter_mle_by_selector_mle(expr_evaluated, zero_selector.clone());

                for (inst_id, element) in enumerate(expr_evaluated) {
                    if element != E::ZERO {
                        errors.push(MockProverError::AssertZeroError {
                            expression: expr.clone(),
                            evaluated: Either::Right(element),
                            name: name.clone(),
                            inst_id,
                        });
                    }
                }
            }
        }

        let lk_selector: ArcMultilinearExtension<_> =
            if let Some(selector) = selector_masks.and_then(|masks| masks.lookup.as_ref()) {
                selector.clone()
            } else if let Some(lk_selector) = &cs.lk_selector {
                structural_witin[lk_selector.selector_expr().id()].clone()
            } else {
                let mut selector = vec![E::BaseField::ONE; num_instances];
                selector.resize(num_instance_padded, E::BaseField::ZERO);
                MultilinearExtension::from_evaluation_vec_smart(
                    ceil_log2(num_instance_padded),
                    selector,
                )
                .into()
            };

        // Lookup expressions
        for (expr, (name, (rom_type, _))) in cs.lk_expressions.iter().zip(
            cs.lk_expressions_namespace_map
                .iter()
                .zip_eq(cs.lk_expressions_items_map.iter()),
        ) {
            let expr_evaluated = wit_infer_by_expr(
                expr,
                cs.num_witin,
                cs.num_fixed as WitnessId,
                0,
                fixed,
                wits_in,
                structural_witin,
                pi_mles,
                pub_io_evals,
                &challenge,
            );
            let expr_evaluated = filter_mle_by_selector_mle(expr_evaluated, lk_selector.clone());

            // Check each lookup expr exists in t vec
            for (inst_id, element) in enumerate(&expr_evaluated) {
                let fixed_table_checked_by_global_multiplicity = matches!(
                    rom_type,
                    ROMType::LlamaSoftmaxExp3
                        | ROMType::LlamaSoftmaxExp4
                        | ROMType::LlamaRmsInv
                        | ROMType::LlamaSwiGlu
                );
                if !fixed_table_checked_by_global_multiplicity
                    && !table.contains(&element.to_canonical_u64_vec())
                {
                    errors.push(MockProverError::LookupError {
                        rom_type: *rom_type,
                        expression: expr.clone(),
                        evaluated: *element,
                        name: name.clone(),
                        inst_id,
                    });
                }
            }

            // Increment shared LK Multiplicity
            for element in expr_evaluated {
                shared_lkm.increment(*rom_type, element);
            }
        }

        // LK Multiplicity check
        if let Some(lkm_from_assignment) = expected_lkm {
            let selected_count = lk_selector
                .get_base_field_vec()
                .iter()
                .filter(|sel| **sel == E::BaseField::ONE)
                .count();
            // Infer LK Multiplicity from constraint system.
            let mut lkm_from_cs = LkMultiplicity::default();
            for (rom_type, args) in &cs.lk_expressions_items_map {
                let args_eval: Vec<_> = args
                    .iter()
                    .map(|arg_expr| {
                        let arg_eval = wit_infer_by_expr(
                            arg_expr,
                            cs.num_witin,
                            cs.num_fixed as WitnessId,
                            0,
                            fixed,
                            wits_in,
                            structural_witin,
                            pi_mles,
                            pub_io_evals,
                            &challenge,
                        );
                        if arg_expr.is_constant() && arg_eval.evaluations.len() == 1 {
                            vec![arg_eval.get_ext_field_vec()[0].to_canonical_u64(); selected_count]
                        } else {
                            filter_mle_by_selector_mle(arg_eval, lk_selector.clone())
                                .iter()
                                .map(E::to_canonical_u64)
                                .collect_vec()
                        }
                    })
                    .collect();

                // Count lookups infered from ConstraintSystem from all instances into lkm_from_cs.
                for (arg0, arg1) in args_eval[0]
                    .iter()
                    .zip(args_eval[1].iter())
                    .take(selected_count)
                {
                    match rom_type {
                        ROMType::Dynamic => {
                            lkm_from_cs.assert_dynamic_range(*arg0, *arg1);
                        }
                        ROMType::DoubleU8 => {
                            lkm_from_cs.assert_double_u8(*arg0, *arg1);
                        }
                        ROMType::And => lkm_from_cs.lookup_and_byte(*arg0, *arg1),
                        ROMType::Or => lkm_from_cs.lookup_or_byte(*arg0, *arg1),
                        ROMType::Xor => lkm_from_cs.lookup_xor_byte(*arg0, *arg1),
                        ROMType::Ltu => lkm_from_cs.lookup_ltu_byte(*arg0, *arg1),
                        ROMType::Pow => {
                            assert_eq!(*arg0, 2);
                            lkm_from_cs.lookup_pow2(*arg1)
                        }
                        ROMType::Instruction => lkm_from_cs.fetch(*arg0 as u32),
                        ROMType::LlamaSoftmaxExp3
                        | ROMType::LlamaSoftmaxExp4
                        | ROMType::LlamaProductionSoftmaxExpMiddle
                        | ROMType::LlamaProductionSoftmaxExpHigh
                        | ROMType::LlamaRmsInv => lkm_from_cs.increment(*rom_type, *arg0),
                        ROMType::LlamaSwiGlu => {
                            let modulus = E::BaseField::MODULUS_U64;
                            let signed = if *arg0 >= modulus - (1 << 15) {
                                *arg0 as i64 - modulus as i64
                            } else {
                                *arg0 as i64
                            };
                            let raw = u64::from(
                                i16::try_from(signed)
                                    .expect("SwiGLU lookup input must be a signed i16")
                                    as u16,
                            );
                            lkm_from_cs.increment(*rom_type, raw);
                        }
                    };
                }
            }

            errors.extend(compare_lkm(
                lkm_from_assignment,
                lkm_from_cs.into_finalize_result(),
            ));
        }

        if errors.is_empty() {
            Ok(shared_lkm)
        } else {
            Err(errors)
        }
    }

    fn load_tables_with_program(
        cs: &ConstraintSystem<E>,
        program: &Program,
        challenge: Option<[E; 2]>,
    ) -> (HashSet<Vec<u64>>, [E; 2]) {
        // load tables
        let (challenge, mut table) = if let Some(challenge) = challenge {
            (challenge, load_tables(cs, challenge))
        } else {
            load_once_tables(cs)
        };
        table.extend(Self::load_program_table(program, challenge));
        (table, challenge)
    }

    fn load_program_table(program: &Program, challenge: [E; 2]) -> Vec<Vec<u64>> {
        let mut t_vec = vec![];
        let mut cs = ConstraintSystem::<E>::new(|| "mock_program");
        let params = ProgramParams {
            platform: CENO_PLATFORM.clone(),
            program_size: max(
                next_pow2_instance_padding(program.instructions.len()),
                MOCK_PROGRAM_SIZE,
            ),
            ..ProgramParams::default()
        };
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = ProgramTableCircuit::<_>::construct_circuit(&mut cb, &params).unwrap();
        let fixed = ProgramTableCircuit::<E>::generate_fixed_traces(&config, cs.num_fixed, program);
        for table_expr in &cs.lk_table_expressions {
            for row in fixed.iter_rows() {
                // TODO: Find a better way to obtain the row content.
                let row: Vec<E> = row.iter().map(|v| (*v).into()).collect();
                let rlc_record =
                    eval_by_expr_with_fixed(&row, &[], &[], &challenge, &table_expr.values);
                t_vec.push(rlc_record.to_canonical_u64_vec());
            }
        }
        t_vec
    }

    #[allow(clippy::too_many_arguments)]
    /// Run and check errors
    ///
    /// Panic, unless we see exactly the expected errors.
    /// (Expecting no errors is a valid expectation.)
    pub fn assert_with_expected_errors(
        cb: &CircuitBuilder<E>,
        fixed: &[ArcMultilinearExtension<'a, E>],
        wits_in: &[ArcMultilinearExtension<'a, E>],
        structural_witin: &[ArcMultilinearExtension<'a, E>],
        program: &[ceno_emul::Instruction],
        constraint_names: &[&str],
        challenge: Option<[E; 2]>,
        lkm: Option<Multiplicity<u64>>,
    ) {
        let error_groups = if let Some(challenge) = challenge {
            Self::run_with_challenge(cb, fixed, wits_in, structural_witin, challenge, lkm)
        } else {
            Self::run(cb, wits_in, program, lkm)
        }
        .err()
        .into_iter()
        .flatten()
        .into_group_map_by(|error| constraint_names.iter().find(|&name| error.contains(name)));
        // Unexpected errors
        if let Some(errors) = error_groups.get(&None) {
            println!("======================================================");

            println!(
                r"
Hints:
- If you encounter a constraint error that sporadically occurs in different environments
    (e.g., passes locally but fails in CI),
    this often points to unassigned witnesses during the assignment phase.
    Accessing these cells before they are properly written leads to undefined behavior.
                    "
            );

            print_errors(errors, wits_in, &cb.cs.witin_namespace_map, true);
        }
        for constraint_name in constraint_names {
            // Expected errors didn't happen:
            error_groups.get(&Some(constraint_name)).unwrap_or_else(|| {
                println!("======================================================");
                println!("Error: {} constraint satisfied", constraint_name);
                println!("======================================================");
                panic!("Constraints unexpectedly satisfied");
            });
        }
    }

    pub fn assert_satisfied_raw(
        cb: &CircuitBuilder<E>,
        [raw_witin, raw_structural_witin]: RMMCollections<E::BaseField>,
        program: &[ceno_emul::Instruction],
        challenge: Option<[E; 2]>,
        lkm: Option<Multiplicity<u64>>,
    ) {
        let wits_in = raw_witin
            .to_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec();
        let structural_witin = raw_structural_witin
            .to_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec();
        Self::assert_satisfied(cb, &wits_in, &structural_witin, program, challenge, lkm);
    }

    pub fn assert_satisfied(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        structural_witin: &[ArcMultilinearExtension<'a, E>],
        program: &[ceno_emul::Instruction],
        challenge: Option<[E; 2]>,
        lkm: Option<Multiplicity<u64>>,
    ) {
        assert_eq!(cb.cs.num_fixed, 0);
        Self::assert_with_expected_errors(
            cb,
            &[],
            wits_in,
            structural_witin,
            program,
            &[],
            challenge,
            lkm,
        );
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn assert_satisfied_gpu_tasks<PCS>(
        mut fixed_trace: ZKVMFixedTraces<E>,
        lk_mlts: &std::collections::BTreeMap<String, Multiplicity<u64>>,
        mut tasks: Vec<crate::scheme::scheduler::ChipTask<'_, gkr_iop::gpu::GpuBackend<E, PCS>>>,
        pcs_data: &<gkr_iop::gpu::GpuBackend<E, PCS> as gkr_iop::hal::ProverBackend>::PcsData,
        program: &Program,
    ) where
        E: LkMultiplicityKey,
        PCS: mpcs::PolynomialCommitmentScheme<E> + 'static,
    {
        let mut rng = thread_rng();
        let challenges = [0u8; 2].map(|_| E::random(&mut rng));

        // Load lookup table.
        let (lookup_table, _) = Self::load_tables_with_program(
            &ConstraintSystem::<E>::new(|| "temp for loading table"),
            program,
            Some(challenges),
        );

        let mut ram_rws = [
            MockRamRws::default(),
            MockRamRws::default(),
            MockRamRws::default(),
            MockRamRws::default(),
        ];
        let mut mock_peak_host_bytes = 0usize;
        let mut processed_circuits = 0usize;

        let mut lkm_tables = LkMultiplicityRaw::<E>::default();
        let mut lkm_opcodes = LkMultiplicityRaw::<E>::default();
        let fused_lk_names = lk_mlts
            .keys()
            .filter(|name| name.starts_with("__gpu_shard_lk"))
            .collect_vec();
        assert!(
            fused_lk_names.len() <= 1,
            "exact GPU mock found multiple shard lookup multiplicity sources: {fused_lk_names:?}"
        );
        let fused_lkm = fused_lk_names.first().map(|name| {
            assert_eq!(
                name.as_str(),
                "__gpu_shard_lk",
                "exact GPU mock found malformed shard lookup multiplicity source: {name}"
            );
            lk_mlts
                .get(name.as_str())
                .expect("validated shard lookup multiplicity source must exist")
        });
        let recorded_lkm = fused_lkm.map(|_| {
            let mut combined = Multiplicity::default();
            for (source, multiplicity) in lk_mlts {
                for (rom_type, counts) in izip!(ROMType::iter(), multiplicity) {
                    for (raw_key, count) in counts {
                        assert_ne!(
                            *count, 0,
                            "recorded lookup source contains a zero count: source={source}, table={rom_type:?}, raw_key={raw_key}"
                        );
                    }
                }
                combined += multiplicity.clone();
            }
            combined
        });
        let mut consumed_recorded_lk = BTreeSet::new();
        tracing::info!(
            ownership = if fused_lkm.is_some() {
                "recorded_assignments_with_fused_shard"
            } else {
                "inferred_per_chip"
            },
            recorded_sources = if fused_lkm.is_some() {
                lk_mlts.len()
            } else {
                0
            },
            "MockProver opcode lookup aggregate ownership"
        );

        for task in &mut tasks {
            crate::scheme::prover::prepare_gpu_chip_input(task, pcs_data);
            let circuit_name = task.circuit_name.as_str();
            let composed_cs = task.pk.get_cs();
            let cs = &composed_cs.zkvm_v1_css;
            let num_rows = task.input.num_instances();
            let num_vars =
                task.input.log2_num_instances() + composed_cs.rotation_vars().unwrap_or(0);
            let selector_masks = exact_gpu_selector_masks(
                circuit_name,
                composed_cs,
                task.input.num_instances,
                num_vars,
            );
            assert_eq!(task.input.witness.len(), cs.num_witin as usize);
            assert_eq!(
                task.input.structural_witness.len(),
                cs.num_structural_witin as usize
            );
            let mut witness_host_bytes = 0usize;
            let witness = task
                .input
                .witness
                .iter()
                .enumerate()
                .map(|(index, mle)| {
                    let (mle, bytes) =
                        materialize_gpu_mle(circuit_name, "witness", index, num_vars, mle);
                    witness_host_bytes = witness_host_bytes
                        .checked_add(bytes)
                        .expect("mock witness host-byte calculation overflow");
                    mle
                })
                .collect_vec();
            let mut structural_host_bytes = 0usize;
            let structural_witness = task
                .input
                .structural_witness
                .iter()
                .enumerate()
                .map(|(index, mle)| {
                    let (mle, bytes) =
                        materialize_gpu_mle(circuit_name, "structural", index, num_vars, mle);
                    structural_host_bytes = structural_host_bytes
                        .checked_add(bytes)
                        .expect("mock structural host-byte calculation overflow");
                    mle
                })
                .collect_vec();
            let chip_peak_host_bytes = witness_host_bytes
                .checked_add(structural_host_bytes)
                .and_then(|bytes| bytes.checked_add(selector_masks.host_bytes))
                .expect("mock chip host-byte calculation overflow");
            assert!(
                chip_peak_host_bytes <= MAX_MOCK_CHIP_HOST_BYTES,
                "mock chip host materialization exceeds bound before D2H: circuit={circuit_name}, bytes={chip_peak_host_bytes}, bound={MAX_MOCK_CHIP_HOST_BYTES}"
            );
            mock_peak_host_bytes = mock_peak_host_bytes.max(chip_peak_host_bytes);
            processed_circuits += 1;
            tracing::info!(
                circuit = %circuit_name,
                witness_host_bytes,
                structural_host_bytes,
                selector_host_bytes = selector_masks.host_bytes,
                chip_peak_host_bytes,
                mock_peak_host_bytes,
                "MockProver bounded per-chip host materialization"
            );
            assert_eq!(task.input.pi.len(), cs.instance.len());
            let circuit_pub_io_evals = task.input.pi.clone();
            let circuit_pi_mles = vec![];
            let fixed: Vec<_> = fixed_trace
                .circuit_fixed_traces
                .remove(circuit_name)
                .and_then(|fixed| fixed)
                .map_or(vec![], |fixed| {
                    fixed.to_mles().into_iter().map(|f| f.into()).collect_vec()
                });
            // not lookup table
            if cs.lk_table_expressions.is_empty() {
                tracing::info!(
                    "Mock proving opcode {} with {} entries",
                    circuit_name,
                    num_rows
                );
                // Assert opcode and check single opcode lk multiplicity
                // Also combine multiplicity in lkm_opcodes
                // Fused GPU replay records lookup multiplicity once for the
                // shard, rather than duplicating it across per-chip entries.
                // The global table-vs-opcode comparison below still checks the
                // complete multiplicity inferred from these chip constraints.
                let lkm_from_assignments = fused_lkm
                    .is_none()
                    .then(|| lk_mlts.get(circuit_name).cloned())
                    .flatten();

                match Self::run_maybe_challenge_with_table(
                    cs,
                    &lookup_table,
                    &fixed,
                    &witness,
                    &structural_witness,
                    &circuit_pi_mles,
                    &circuit_pub_io_evals,
                    Some(&selector_masks),
                    num_rows,
                    challenges,
                    lkm_from_assignments,
                ) {
                    Ok(multiplicities) => {
                        if fused_lkm.is_none() {
                            lkm_opcodes += multiplicities;
                        }
                    }
                    Err(errors) => {
                        tracing::error!("Mock proving failed for opcode {}", circuit_name);
                        print_errors(&errors, &witness, &cs.witin_namespace_map, true);
                    }
                }
            } else {
                tracing::info!(
                    "Mock proving table {} with {} entries",
                    circuit_name,
                    num_rows
                );
                // gather lookup tables
                for (expr, (rom_type, record)) in
                    izip!(&cs.lk_table_expressions, &cs.lk_expressions_items_map)
                {
                    let lk_table = wit_infer_by_expr(
                        &expr.values,
                        cs.num_witin,
                        cs.num_fixed as WitnessId,
                        0,
                        &fixed,
                        &witness,
                        &structural_witness,
                        &circuit_pi_mles,
                        &circuit_pub_io_evals,
                        &challenges,
                    )
                    .get_ext_field_vec()
                    .to_vec();

                    let multiplicity = wit_infer_by_expr(
                        &expr.multiplicity,
                        cs.num_witin,
                        cs.num_fixed as WitnessId,
                        0,
                        &fixed,
                        &witness,
                        &structural_witness,
                        &circuit_pi_mles,
                        &circuit_pub_io_evals,
                        &challenges,
                    )
                    .get_ext_field_vec()
                    .to_vec();

                    let raw_keys = if *rom_type == ROMType::Instruction {
                        let pc = record.first().unwrap_or_else(|| {
                            panic!("instruction lookup table record must contain a PC")
                        });
                        wit_infer_by_expr(
                            pc,
                            cs.num_witin,
                            cs.num_fixed as WitnessId,
                            0,
                            &fixed,
                            &witness,
                            &structural_witness,
                            &circuit_pi_mles,
                            &circuit_pub_io_evals,
                            &challenges,
                        )
                        .get_ext_field_vec()
                        .iter()
                        .map(E::to_canonical_u64)
                        .collect_vec()
                    } else {
                        (0..lk_table.len()).map(|row| row as u64).collect_vec()
                    };
                    assert_eq!(
                        raw_keys.len(),
                        lk_table.len(),
                        "lookup table raw-key domain mismatch: circuit={circuit_name}, table={rom_type:?}"
                    );

                    for (raw_key, key, multiplicity) in izip!(raw_keys, lk_table, multiplicity) {
                        let count = usize::try_from(multiplicity.to_canonical_u64())
                            .expect("lookup table multiplicity must fit the host count domain");
                        lkm_tables.set_count(*rom_type, key, count);
                        if let Some(recorded_lkm) = recorded_lkm.as_ref() {
                            let recorded_count = recorded_lkm[*rom_type as usize]
                                .get(&raw_key)
                                .copied()
                                .unwrap_or_default();
                            assert_eq!(
                                count, recorded_count,
                                "recorded lookup/table count mismatch: circuit={circuit_name}, table={rom_type:?}, raw_key={raw_key}"
                            );
                            if recorded_count != 0 {
                                assert!(
                                    consumed_recorded_lk.insert((*rom_type as usize, raw_key)),
                                    "recorded lookup key consumed multiple times: table={rom_type:?}, raw_key={raw_key}"
                                );
                                lkm_opcodes += ((*rom_type, key), recorded_count);
                            }
                        }
                    }
                }
            }
            for (ram_type, accumulator) in [
                RAMType::GlobalState,
                RAMType::Register,
                RAMType::Memory,
                RAMType::Custom,
            ]
            .into_iter()
            .zip(&mut ram_rws)
            {
                accumulate_ram_rws(
                    circuit_name,
                    cs,
                    &fixed,
                    &witness,
                    &structural_witness,
                    &circuit_pi_mles,
                    &circuit_pub_io_evals,
                    &challenges,
                    num_rows,
                    Some(&selector_masks),
                    ram_type,
                    accumulator,
                );
            }
        }

        if let Some(recorded_lkm) = recorded_lkm {
            let mut recorded_entry_count = 0usize;
            for (rom_type, counts) in izip!(ROMType::iter(), &recorded_lkm) {
                for (raw_key, count) in counts {
                    assert_ne!(
                        *count, 0,
                        "combined recorded lookup source contains a zero count: table={rom_type:?}, raw_key={raw_key}"
                    );
                    assert!(
                        consumed_recorded_lk.contains(&(rom_type as usize, *raw_key)),
                        "recorded lookup key is outside the table domain: table={rom_type:?}, raw_key={raw_key}, count={count}"
                    );
                    recorded_entry_count += 1;
                }
            }
            assert_eq!(
                consumed_recorded_lk.len(),
                recorded_entry_count,
                "recorded lookup multiplicity was not consumed exactly once"
            );
            tracing::info!(
                recorded_entry_count,
                "MockProver consumed recorded lookup aggregate exactly once"
            );
        }

        tracing::info!(
            processed_circuits,
            mock_peak_host_bytes,
            bound_bytes = MAX_MOCK_CHIP_HOST_BYTES,
            "MockProver completed bounded chip inventory"
        );

        // Assert lkm between all tables and combined opcode circuits
        let errors: Vec<MockProverError<E, E>> = compare_lkm(
            lkm_tables.into_finalize_result(),
            lkm_opcodes.into_finalize_result(),
        );

        if errors.is_empty() {
            tracing::info!("Mock proving successful for tables");
        } else {
            tracing::error!("Mock proving failed for tables - {} errors", errors.len());
            print_errors(&errors, &[], &[], true);
        }

        // find out r != w errors
        let mut num_rw_mismatch_errors = 0;

        macro_rules! find_rw_mismatch {
            ($rws:ident,$ram_type:expr,$gs:expr) => {
                for (annotation, (reads, circuit_name)) in &$rws.reads_by_annotation {
                    // (pc, timestamp)
                    let gs_of_circuit = $gs.get(circuit_name);
                    let num_missing = reads
                        .iter()
                        .filter(|(read, _)| !$rws.writes.contains_key(read))
                        .count();
                    let num_reads = reads.len();
                    reads
                        .iter()
                        .filter(|(read, _)| !$rws.writes.contains_key(read))
                        .take(10)
                        .for_each(|(read, row)| {
                            let pc = gs_of_circuit.map_or(0, |gs| gs[*row][0].to_canonical_u64());
                            let ts = gs_of_circuit.map_or(0, |gs| gs[*row][1].to_canonical_u64());
                            tracing::error!(
                                "{} at row {} (pc={:x},ts={}) not found in {:?} writes",
                                annotation,
                                row,
                                pc,
                                ts,
                                $ram_type,
                            );
                            if let Some(raw_tuple) = $rws.raw_samples.get(read) {
                                tracing::error!(?raw_tuple, "missing RAM read raw tuple");
                            }
                        });

                    if num_missing > 10 {
                        tracing::error!(
                            ".... {} more missing (num_instances = {})",
                            num_missing - 10,
                            num_reads,
                        );
                    }
                    if num_missing > 0 {
                        tracing::error!("--------------------");
                    }
                    num_rw_mismatch_errors += num_missing;
                }
                for (annotation, (writes, circuit_name)) in &$rws.writes_by_annotation {
                    let gs_of_circuit = $gs.get(circuit_name);
                    let num_missing = writes
                        .iter()
                        .filter(|(write, _)| !$rws.reads.contains_key(write))
                        .count();
                    let num_writes = writes.len();
                    writes
                        .iter()
                        .filter(|(write, _)| !$rws.reads.contains_key(write))
                        .take(10)
                        .for_each(|(write, row)| {
                            let pc = gs_of_circuit.map_or(0, |gs| gs[*row][0].to_canonical_u64());
                            let ts = gs_of_circuit.map_or(0, |gs| gs[*row][1].to_canonical_u64());
                            tracing::error!(
                                "{} at row {} (pc={:x},ts={}) not found in {:?} reads",
                                annotation,
                                row,
                                pc,
                                ts,
                                $ram_type,
                            );
                            if let Some(raw_tuple) = $rws.raw_samples.get(write) {
                                tracing::error!(?raw_tuple, "missing RAM write raw tuple");
                            }
                        });

                    if num_missing > 10 {
                        tracing::error!(
                            ".... {} more missing (num_instances = {})",
                            num_missing - 10,
                            num_writes,
                        );
                    }
                    if num_missing > 0 {
                        tracing::error!("--------------------");
                    }
                    num_rw_mismatch_errors += num_missing;
                }
                let multiplicity_mismatches = $rws
                    .reads
                    .keys()
                    .chain($rws.writes.keys())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .map(|record| {
                        $rws.reads.get(record).copied().unwrap_or_default().abs_diff(
                            $rws.writes.get(record).copied().unwrap_or_default(),
                        )
                    })
                    .sum::<usize>();
                if multiplicity_mismatches != 0 {
                    tracing::error!(
                        ram_type = ?$ram_type,
                        multiplicity_mismatches,
                        "RAM record multiplicities differ"
                    );
                    num_rw_mismatch_errors += multiplicity_mismatches;
                }
            };
        }
        let [gs_rws, reg_rws, mem_rws, custom_rws] = ram_rws;
        let gs = &gs_rws.global_state;

        // gs stores { (pc, timestamp) }
        find_rw_mismatch!(gs_rws, RAMType::GlobalState, gs);

        // part2 registers
        find_rw_mismatch!(reg_rws, RAMType::Register, gs);

        // part3 memory
        find_rw_mismatch!(mem_rws, RAMType::Memory, gs);

        // part4 custom local buses
        find_rw_mismatch!(custom_rws, RAMType::Custom, gs);

        if num_rw_mismatch_errors > 0 {
            panic!("found {} r/w mismatch errors", num_rw_mismatch_errors);
        }
    }
}

fn compare_lkm<E, K>(lkm_a: Multiplicity<K>, lkm_b: Multiplicity<K>) -> Vec<MockProverError<E, K>>
where
    E: ExtensionField,
    K: LkMultiplicityKey + Default + Ord,
{
    // Compare each LK Multiplicity.
    izip!(ROMType::iter(), &lkm_a, &lkm_b)
        .flat_map(|(rom_type, a_map, b_map)| {
            // We use a BTreeSet, instead of a HashSet, to ensure deterministic order.
            let keys: BTreeSet<_> = chain!(a_map.keys(), b_map.keys()).collect();
            keys.into_iter().filter_map(move |key| {
                let count =
                    *a_map.get(key).unwrap_or(&0) as isize - *b_map.get(key).unwrap_or(&0) as isize;

                (count != 0).then_some(MockProverError::LkMultiplicityError {
                    rom_type,
                    key: *key,
                    count,
                })
            })
        })
        .collect()
}

fn print_errors<E: ExtensionField, K: LkMultiplicityKey>(
    errors: &[MockProverError<E, K>],
    wits_in: &[ArcMultilinearExtension<E>],
    wits_in_name: &[String],
    panic_on_error: bool,
) {
    println!("======================================================");
    for (count, error) in errors.iter().dedup_with_count() {
        error.print(wits_in, wits_in_name);
        if count > 1 {
            println!("Error: {} duplicates hidden.", count - 1);
        }
    }
    println!("Error: {} constraints not satisfied", errors.len());
    println!("======================================================");
    if panic_on_error {
        panic!("(Unexpected) Constraints not satisfied");
    }
}

fn filter_mle_by_predicate<E, F>(target_mle: ArcMultilinearExtension<E>, mut predicate: F) -> Vec<E>
where
    E: ExtensionField,
    F: FnMut(usize, &E) -> bool,
{
    target_mle
        .get_ext_field_vec()
        .iter()
        .enumerate()
        .filter_map(|(i, v)| if predicate(i, v) { Some(*v) } else { None })
        .collect_vec()
}

fn filter_mle_by_selector_mle<E: ExtensionField>(
    target_mle: ArcMultilinearExtension<E>,
    selector: ArcMultilinearExtension<E>,
) -> Vec<E> {
    assert_eq!(target_mle.evaluations().len(), selector.evaluations().len());
    target_mle
        .get_ext_field_vec()
        .iter()
        .enumerate()
        .filter_map(|(index, value)| selector_mask_is_active(&selector, index).then_some(*value))
        .collect_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ROMType,
        error::ZKVMError,
        gadgets::{AssertLtConfig, IsLtConfig},
        witness::LkMultiplicity,
    };
    use ff_ext::{FieldInto, GoldilocksExt2};
    use multilinear_extensions::{ToExpr, WitIn, mle::IntoMLE};
    use p3::{field::PrimeCharacteristicRing as FieldAlgebra, goldilocks::Goldilocks};
    use witness::{InstancePaddingStrategy, RowMajorMatrix, set_val};

    #[derive(Debug)]
    struct AssertZeroCircuit {
        #[allow(dead_code)]
        pub a: WitIn,
        #[allow(dead_code)]
        pub b: WitIn,
        #[allow(dead_code)]
        pub c: WitIn,
    }

    impl AssertZeroCircuit {
        pub fn construct_circuit(
            cb: &mut CircuitBuilder<GoldilocksExt2>,
        ) -> Result<Self, ZKVMError> {
            let a = cb.create_witin(|| "a");
            let b = cb.create_witin(|| "b");
            let c = cb.create_witin(|| "c");

            // degree 1
            cb.require_equal(|| "a + 1 == b", b.expr(), a.expr() + 1)?;
            cb.require_zero(|| "c - 2 == 0", c.expr() - 2)?;

            // degree > 1
            let d = cb.create_witin(|| "d");
            cb.require_zero(
                || "d*d - 6*d + 9 == 0",
                d.expr() * d.expr() - d.expr() * 6 + 9,
            )?;

            Ok(Self { a, b, c })
        }
    }

    #[test]
    fn test_assert_zero_1() {
        let mut cs = ConstraintSystem::new(|| "test_assert_zero_1");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let _ = AssertZeroCircuit::construct_circuit(&mut builder).unwrap();

        let wits_in = vec![
            (vec![3u64.into_f(), 500u64.into_f()] as Vec<Goldilocks>),
            vec![4u64.into_f(), 501.into_f()],
            vec![2.into_f(), 2.into_f()],
            vec![3.into_f(), 3.into_f()],
        ]
        .into_iter()
        .map(|f| f.into_mle().into())
        .collect_vec();

        MockProver::assert_satisfied(&builder, &wits_in, &[], &[], None, None);
    }

    #[derive(Debug)]
    struct RangeCheckCircuit {
        #[allow(dead_code)]
        pub a: WitIn,
    }

    impl RangeCheckCircuit {
        pub fn construct_circuit(
            cb: &mut CircuitBuilder<GoldilocksExt2>,
        ) -> Result<Self, ZKVMError> {
            let a = cb.create_witin(|| "a");
            cb.assert_ux::<_, _, 5>(|| "assert u5", a.expr())?;
            Ok(Self { a })
        }
    }

    #[test]
    fn test_lookup_1() {
        let mut cs = ConstraintSystem::new(|| "test_lookup_1");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let _ = RangeCheckCircuit::construct_circuit(&mut builder).unwrap();

        let wits_in = vec![
            vec![Goldilocks::from_u64(3u64), Goldilocks::from_u64(5u64)]
                .into_mle()
                .into(),
        ];

        let challenge = [1.into_f(), 1000.into_f()];
        MockProver::assert_satisfied(&builder, &wits_in, &[], &[], Some(challenge), None);
    }

    #[test]
    // TODO: add it back after the support of missing lookup
    fn test_lookup_error() {
        let mut cs = ConstraintSystem::new(|| "test_lookup_error");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let _ = RangeCheckCircuit::construct_circuit(&mut builder).unwrap();

        let wits_in = vec![(vec![123u64.into_f()] as Vec<Goldilocks>).into_mle().into()];

        let challenge = [2.into_f(), 1000.into_f()];
        let result = MockProver::run_with_challenge(&builder, &[], &wits_in, &[], challenge, None);
        assert!(result.is_err(), "Expected error");
        let err = result.unwrap_err();
        assert_eq!(
            err,
            vec![MockProverError::LookupError {
                rom_type: ROMType::Dynamic,
                expression: Expression::Sum(
                    Box::new(Expression::Sum(
                        Box::new(Expression::ScaledSum(
                            Box::new(Expression::WitIn(0)),
                            Box::new(Expression::Challenge(
                                1,
                                1,
                                GoldilocksExt2::ONE,
                                GoldilocksExt2::ZERO,
                            )),
                            Box::new(Goldilocks::from_u64(ROMType::Dynamic as u64).expr()),
                        )),
                        Box::new(Expression::Challenge(
                            1,
                            2,
                            5.into_f(),
                            GoldilocksExt2::ZERO,
                        ))
                    )),
                    Box::new(Expression::Challenge(
                        0,
                        1,
                        GoldilocksExt2::ONE,
                        GoldilocksExt2::ZERO,
                    )),
                ),
                evaluated: 5123002.into_f(), // 123 * 1000 + 5 * (1000^2) + 2
                name: "test_lookup_error/assert_const_range/assert u5".to_string(),
                inst_id: 0,
            }]
        );
        // because inst_id is not checked in our PartialEq impl
        assert_eq!(err[0].inst_id(), 0);
    }

    #[derive(Debug)]
    struct AssertLtCircuit {
        pub a: WitIn,
        pub b: WitIn,
        pub lt_wtns: AssertLtConfig,
    }

    struct AssertLtCircuitInput {
        pub a: u64,
        pub b: u64,
    }

    impl AssertLtCircuit {
        fn construct_circuit(cb: &mut CircuitBuilder<GoldilocksExt2>) -> Result<Self, ZKVMError> {
            let a = cb.create_witin(|| "a");
            let b = cb.create_witin(|| "b");
            let lt_wtns = AssertLtConfig::construct_circuit(cb, || "lt", a.expr(), b.expr(), 1)?;
            Ok(Self { a, b, lt_wtns })
        }

        fn assign_instance<E: ExtensionField>(
            &self,
            instance: &mut [E::BaseField],
            input: AssertLtCircuitInput,
            lk_multiplicity: &mut LkMultiplicity,
        ) -> Result<(), ZKVMError> {
            set_val!(instance, self.a, input.a);
            set_val!(instance, self.b, input.b);
            self.lt_wtns
                .assign_instance(instance, lk_multiplicity, input.a, input.b)?;

            Ok(())
        }

        fn assign_instances<E: ExtensionField>(
            &self,
            num_witin: usize,
            instances: Vec<AssertLtCircuitInput>,
            lk_multiplicity: &mut LkMultiplicity,
        ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
            let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(
                instances.len(),
                num_witin,
                InstancePaddingStrategy::Default,
            );
            let raw_witin_iter = raw_witin.iter_mut();

            raw_witin_iter
                .zip_eq(instances.into_iter())
                .try_for_each(|(instance, input)| {
                    self.assign_instance::<E>(instance, input, lk_multiplicity)
                })?;

            Ok(raw_witin)
        }
    }

    #[test]
    fn test_assert_lt_1() {
        let mut cs = ConstraintSystem::new(|| "test_assert_lt_1");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let circuit = AssertLtCircuit::construct_circuit(&mut builder).unwrap();

        let mut lk_multiplicity = LkMultiplicity::default();
        let raw_witin = circuit
            .assign_instances::<GoldilocksExt2>(
                builder.cs.num_witin as usize,
                vec![
                    AssertLtCircuitInput { a: 3, b: 5 },
                    AssertLtCircuitInput { a: 7, b: 11 },
                ],
                &mut lk_multiplicity,
            )
            .unwrap();

        MockProver::assert_satisfied_raw(
            &builder,
            [raw_witin, RowMajorMatrix::empty()],
            &[],
            Some([1.into_f(), 1000.into_f()]),
            None,
        );
    }

    #[test]
    fn test_assert_lt_u32() {
        let mut cs = ConstraintSystem::new(|| "test_assert_lt_u32");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let circuit = AssertLtCircuit::construct_circuit(&mut builder).unwrap();
        let mut lk_multiplicity = LkMultiplicity::default();
        let raw_witin = circuit
            .assign_instances::<GoldilocksExt2>(
                builder.cs.num_witin as usize,
                vec![
                    AssertLtCircuitInput {
                        a: u32::MAX as u64 - 5,
                        b: u32::MAX as u64 - 3,
                    },
                    AssertLtCircuitInput {
                        a: u32::MAX as u64 - 3,
                        b: u32::MAX as u64 - 2,
                    },
                ],
                &mut lk_multiplicity,
            )
            .unwrap();

        MockProver::assert_satisfied_raw(
            &builder,
            [raw_witin, RowMajorMatrix::empty()],
            &[],
            Some([1.into_f(), 1000.into_f()]),
            None,
        );
    }

    #[derive(Debug)]
    struct LtCircuit {
        pub a: WitIn,
        pub b: WitIn,
        pub lt_wtns: IsLtConfig,
    }

    struct LtCircuitInput {
        pub a: u64,
        pub b: u64,
    }

    impl LtCircuit {
        fn construct_circuit(cb: &mut CircuitBuilder<GoldilocksExt2>) -> Result<Self, ZKVMError> {
            let a = cb.create_witin(|| "a");
            let b = cb.create_witin(|| "b");
            let lt_wtns = IsLtConfig::construct_circuit(cb, || "lt", a.expr(), b.expr(), 1)?;
            Ok(Self { a, b, lt_wtns })
        }

        fn assign_instance<E: ExtensionField>(
            &self,
            instance: &mut [E::BaseField],
            input: LtCircuitInput,
            lk_multiplicity: &mut LkMultiplicity,
        ) -> Result<(), ZKVMError> {
            set_val!(instance, self.a, input.a);
            set_val!(instance, self.b, input.b);
            self.lt_wtns
                .assign_instance(instance, lk_multiplicity, input.a, input.b)?;

            Ok(())
        }

        fn assign_instances<E: ExtensionField>(
            &self,
            num_witin: usize,
            instances: Vec<LtCircuitInput>,
            lk_multiplicity: &mut LkMultiplicity,
        ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
            let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(
                instances.len(),
                num_witin,
                InstancePaddingStrategy::Default,
            );
            let raw_witin_iter = raw_witin.iter_mut();

            raw_witin_iter
                .zip_eq(instances.into_iter())
                .try_for_each(|(instance, input)| {
                    self.assign_instance::<E>(instance, input, lk_multiplicity)
                })?;

            Ok(raw_witin)
        }
    }

    #[test]
    fn test_lt_1() {
        let mut cs = ConstraintSystem::new(|| "test_lt_1");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let circuit = LtCircuit::construct_circuit(&mut builder).unwrap();

        let mut lk_multiplicity = LkMultiplicity::default();
        let raw_witin = circuit
            .assign_instances::<GoldilocksExt2>(
                builder.cs.num_witin as usize,
                vec![
                    LtCircuitInput { a: 3, b: 5 },
                    LtCircuitInput { a: 7, b: 11 },
                ],
                &mut lk_multiplicity,
            )
            .unwrap();

        MockProver::assert_satisfied_raw(
            &builder,
            [raw_witin, RowMajorMatrix::empty()],
            &[],
            Some([1.into_f(), 1000.into_f()]),
            None,
        );
    }

    #[test]
    fn test_lt_u32() {
        let mut cs = ConstraintSystem::new(|| "test_lt_u32");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let circuit = LtCircuit::construct_circuit(&mut builder).unwrap();

        let mut lk_multiplicity = LkMultiplicity::default();
        let raw_witin = circuit
            .assign_instances::<GoldilocksExt2>(
                builder.cs.num_witin as usize,
                vec![
                    LtCircuitInput {
                        a: u32::MAX as u64 - 5,
                        b: u32::MAX as u64 - 3,
                    },
                    LtCircuitInput {
                        a: u32::MAX as u64 - 3,
                        b: u32::MAX as u64 - 5,
                    },
                ],
                &mut lk_multiplicity,
            )
            .unwrap();

        MockProver::assert_satisfied_raw(
            &builder,
            [raw_witin, RowMajorMatrix::empty()],
            &[],
            Some([1.into_f(), 1000.into_f()]),
            None,
        );
    }
}
