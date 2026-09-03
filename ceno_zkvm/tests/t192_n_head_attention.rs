use std::sync::Arc;

use ceno_emul::tensor::TensorProductionFullLayerWitness;
use ceno_zkvm::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{
        Instruction,
        riscv::ecall::{
            TensorAttentionPv, TensorAttentionQkShiftSoftmax,
            TensorProductionBoundaryHiddenInputInstruction,
            TensorProductionBoundaryReplayDescriptor, validate_production_attention_group,
            validate_production_boundary_group,
        },
    },
    scheme::{
        matrix_reduction::{descriptor, exact_production_domain},
        scheduler::is_exclusive_production_circuit,
    },
    structs::ProgramParams,
};
use ff_ext::{BabyBearExt4, ExtensionField, FieldFrom};
use gkr_iop::utils::{eval_inner_repeated_incremental_vec, eval_outer_repeated_incremental_vec};
use multilinear_extensions::{Expression, StructuralWitInType, utils::eval_by_expr_with_instance};
use p3::field::PrimeCharacteristicRing;
use rand::{Rng, SeedableRng, rngs::StdRng};

type E = BabyBearExt4;
type F = <E as ExtensionField>::BaseField;

fn id(names: &[String], needle: &str) -> usize {
    names
        .iter()
        .position(|name| name.contains(needle))
        .unwrap_or_else(|| panic!("missing metadata {needle}"))
}

fn construct<I: Instruction<E>>() -> ConstraintSystem<E> {
    let mut cs = ConstraintSystem::<E>::new(|| I::name());
    let mut cb = CircuitBuilder::new(&mut cs);
    I::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();
    cs
}

fn eval(expr: &Expression<E>, witness: &[F], structural: &[F]) -> E {
    let witness = witness.iter().copied().map(E::from).collect::<Vec<_>>();
    let structural = structural.iter().copied().map(E::from).collect::<Vec<_>>();
    eval_by_expr_with_instance::<E>(
        &[],
        &witness,
        &structural,
        &[],
        &[E::from_v(7), E::from_v(11)],
        expr,
    )
    .unwrap_right()
}

fn named_zero<'a>(cs: &'a ConstraintSystem<E>, needle: &str) -> &'a Expression<E> {
    cs.assert_zero_expressions_namespace_map
        .iter()
        .zip(&cs.assert_zero_expressions)
        .chain(
            cs.assert_zero_sumcheck_expressions_namespace_map
                .iter()
                .zip(&cs.assert_zero_sumcheck_expressions),
        )
        .find_map(|(name, expression)| name.contains(needle).then_some(expression))
        .unwrap_or_else(|| panic!("missing constraint {needle}"))
}

fn set_named(names: &[String], values: &mut [F], needle: &str, value: u64) {
    values[id(names, needle)] = F::from_u64(value);
}

fn fused_structural(cs: &ConstraintSystem<E>, physical: u64) -> Vec<F> {
    let mut structural = vec![F::ZERO; cs.num_structural_witin as usize];
    let names = &cs.structural_witin_namespace_map;
    set_named(names, &mut structural, "axis_low7_prefix", physical & 0x7f);
    set_named(
        names,
        &mut structural,
        "axis_high4_prefix",
        physical & 0x7ff,
    );
    set_named(
        names,
        &mut structural,
        "row_low7_prefix",
        physical & 0x3ffff,
    );
    set_named(
        names,
        &mut structural,
        "row_high4_prefix",
        physical & 0x3fffff,
    );
    set_named(names, &mut structural, "physical_index", physical);
    structural
}

fn pv_structural(cs: &ConstraintSystem<E>, physical: u64) -> Vec<F> {
    let mut structural = vec![F::ZERO; cs.num_structural_witin as usize];
    let names = &cs.structural_witin_namespace_map;
    set_named(
        names,
        &mut structural,
        "production_pv_axis",
        physical & 0x7f,
    );
    set_named(names, &mut structural, "row_low7_prefix", physical & 0x3fff);
    set_named(
        names,
        &mut structural,
        "row_high4_prefix",
        physical & 0x3ffff,
    );
    set_named(names, &mut structural, "head_prefix", physical >> 22);
    set_named(
        names,
        &mut structural,
        "production_pv_local_row_prefix",
        physical & ((1 << 22) - 1),
    );
    set_named(names, &mut structural, "physical_index", physical);
    structural
}

fn assert_domain<I: Instruction<E>>(
    constraint: &str,
    structural: fn(&ConstraintSystem<E>, u64) -> Vec<F>,
    heads: usize,
) {
    let cs = construct::<I>();
    let row_bits = 22 + heads.trailing_zeros() as usize;
    let physical = id(&cs.structural_witin_namespace_map, "physical_index");
    assert!(matches!(
        cs.structural_witins[physical].witin_type,
        StructuralWitInType::OuterRepeatingIncrementalSequence { k, n }
            if (k, n) == (row_bits, row_bits)
    ));
    let witness = vec![F::ZERO; cs.num_witin as usize];
    for row in [0, (1u64 << 22) - 1, ((heads as u64) << 22) - 1] {
        assert_eq!(
            eval(named_zero(&cs, constraint), &witness, &structural(&cs, row)),
            E::ZERO
        );
    }
    let matrix = descriptor(&I::name()).expect("production matrix descriptor");
    assert_eq!(matrix.output_vars, row_bits);
    assert!(exact_production_domain(heads << 22, matrix));
    assert!(!exact_production_domain(1 << 21, matrix));
    assert!(!exact_production_domain(1 << 22, matrix) || heads == 1);
}

#[test]
fn generic_geometry_and_matrix_domains_are_exact() {
    assert_domain::<TensorAttentionQkShiftSoftmax<E, 1>>(
        "production_fused_physical_coordinate",
        fused_structural,
        1,
    );
    assert_domain::<TensorAttentionQkShiftSoftmax<E, 2>>(
        "production_fused_physical_coordinate",
        fused_structural,
        2,
    );
    assert_domain::<TensorAttentionQkShiftSoftmax<E, 4>>(
        "production_fused_physical_coordinate",
        fused_structural,
        4,
    );
    assert_domain::<TensorAttentionPv<E, 1>>("production_pv_physical_coordinate", pv_structural, 1);
    assert_domain::<TensorAttentionPv<E, 2>>("production_pv_physical_coordinate", pv_structural, 2);
    assert_domain::<TensorAttentionPv<E, 4>>("production_pv_physical_coordinate", pv_structural, 4);
}

fn verifier_sequence_eval(witin_type: StructuralWitInType, point: &[E]) -> E {
    match witin_type {
        StructuralWitInType::InnerRepeatingIncrementalSequence { k, .. } => {
            eval_inner_repeated_incremental_vec(k as u64, point)
        }
        StructuralWitInType::OuterRepeatingIncrementalSequence { k, .. } => {
            eval_outer_repeated_incremental_vec(k as u64, point)
        }
        other => panic!("unexpected verifier-equivalent structural type: {other:?}"),
    }
}

#[test]
fn pv_local_row_prefix_matches_verifier_at_random_points() {
    fn check<const N: usize>() {
        let cs = construct::<TensorAttentionPv<E, N>>();
        let row_bits = 22 + N.trailing_zeros() as usize;
        let local_row_id = id(
            &cs.structural_witin_namespace_map,
            "production_pv_local_row_prefix",
        );
        let row_high_id = id(
            &cs.structural_witin_namespace_map,
            "production_pv_row_high4_prefix",
        );
        let local_row_type = cs.structural_witins[local_row_id].witin_type;
        assert!(matches!(
            local_row_type,
            StructuralWitInType::OuterRepeatingIncrementalSequence { k, n }
                if (k, n) == (22, row_bits)
        ));
        assert_eq!(local_row_type.max_len(), 1 << row_bits);

        let mut rng = StdRng::seed_from_u64(0x0192_4090 + N as u64);
        for _ in 0..8 {
            let point = (0..row_bits)
                .map(|_| E::from_v(rng.gen_range(1..1_000_000)))
                .collect::<Vec<_>>();
            let local_row_eval = verifier_sequence_eval(local_row_type, &point);
            let assigned_local_row_eval = eval_outer_repeated_incremental_vec(22, &point);
            assert_eq!(local_row_eval, assigned_local_row_eval);

            let row_high_eval =
                verifier_sequence_eval(cs.structural_witins[row_high_id].witin_type, &point);
            let assigned_tile_eval = eval_inner_repeated_incremental_vec(18, &point[..22]);
            assert_eq!(
                local_row_eval - row_high_eval,
                assigned_tile_eval * E::from_v(1 << 18),
            );

            if row_bits > 22 {
                let mut changed_head = point.clone();
                for coordinate in &mut changed_head[22..] {
                    *coordinate += E::ONE;
                }
                assert_eq!(
                    verifier_sequence_eval(local_row_type, &changed_head),
                    local_row_eval,
                );
            }
        }
    }

    check::<1>();
    check::<2>();
    check::<4>();
}

#[test]
fn invalid_generic_head_counts_are_rejected() {
    assert!(std::panic::catch_unwind(construct::<TensorAttentionQkShiftSoftmax<E, 0>>).is_err());
    assert!(std::panic::catch_unwind(construct::<TensorAttentionQkShiftSoftmax<E, 3>>).is_err());
    assert!(std::panic::catch_unwind(construct::<TensorAttentionPv<E, 0>>).is_err());
    assert!(std::panic::catch_unwind(construct::<TensorAttentionPv<E, 3>>).is_err());
}

#[test]
fn fused_and_pv_bind_slot_descriptors_and_reset_pv_state() {
    let fused = construct::<TensorAttentionQkShiftSoftmax<E, 2>>();
    let mut fused_witness = vec![F::ZERO; fused.num_witin as usize];
    set_named(
        &fused.witin_namespace_map,
        &mut fused_witness,
        "head_start",
        8,
    );
    set_named(
        &fused.witin_namespace_map,
        &mut fused_witness,
        "import_cycle",
        101,
    );
    set_named(
        &fused.witin_namespace_map,
        &mut fused_witness,
        "input_version",
        7,
    );
    set_named(
        &fused.witin_namespace_map,
        &mut fused_witness,
        "output_version",
        9,
    );
    let fused_row = fused_structural(&fused, 1 << 22);
    let call = fused
        .r_expressions_namespace_map
        .iter()
        .position(|name| name.ends_with("production_fused_attention_call_once"))
        .expect("fused call record");
    let record = &fused.r_ram_types[call].1;
    assert_eq!(eval(&record[2], &fused_witness, &fused_row), E::from_v(101));
    assert_eq!(eval(&record[5], &fused_witness, &fused_row), E::from_v(7));
    assert_eq!(eval(&record[8], &fused_witness, &fused_row), E::from_v(9));
    assert_eq!(eval(&record[12], &fused_witness, &fused_row), E::from_v(9));
    assert_eq!(record.len(), 14);

    let pv = construct::<TensorAttentionPv<E, 2>>();
    let mut pv_witness = vec![F::ZERO; pv.num_witin as usize];
    set_named(&pv.witin_namespace_map, &mut pv_witness, "head_start", 8);
    let slot_one = pv_structural(&pv, 1 << 22);
    let state = pv
        .r_expressions_namespace_map
        .iter()
        .position(|name| name.ends_with("production_pv_w_state_read"))
        .expect("PV state record");
    assert_eq!(
        eval(&pv.r_ram_types[state].1[7], &pv_witness, &slot_one),
        E::from_v(9)
    );

    set_named(
        &pv.witin_namespace_map,
        &mut pv_witness,
        "accumulator_q_before",
        1,
    );
    let seed = named_zero(&pv, "production_pv_accumulator_seed_q");
    assert_eq!(eval(seed, &pv_witness, &slot_one), E::ONE);
    set_named(&pv.witin_namespace_map, &mut pv_witness, "tile_inverse", 1);
    assert_eq!(
        eval(
            seed,
            &pv_witness,
            &pv_structural(&pv, (1 << 22) + (1 << 18)),
        ),
        E::ZERO
    );
}

fn attention_call(head_start: u32) -> TensorProductionFullLayerWitness {
    TensorProductionFullLayerWitness {
        import_cycle: 100,
        input_tensor_id: 10,
        input_version: 3,
        projected_qkv_tensor_id: 10,
        projected_qkv_version: 3,
        attention_output_tensor_id: 20,
        attention_output_version: 4,
        output_tensor_id: 20,
        output_version: 4,
        profile: ceno_emul::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER,
        layer: 5,
        stage: 1,
        head_start,
        head_count: 1,
        operation_records: Vec::new(),
    }
}

fn call_refs(calls: &[TensorProductionFullLayerWitness]) -> Vec<&TensorProductionFullLayerWitness> {
    calls.iter().collect()
}

#[test]
fn attention_group_rejects_topology_and_descriptor_drift() {
    let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
    let canonical = (0..heads)
        .map(|slot| attention_call(slot as u32))
        .collect::<Vec<_>>();
    validate_production_attention_group(&call_refs(&canonical)).unwrap();
    assert!(validate_production_attention_group(&call_refs(&canonical[..heads - 1])).is_err());

    let mut extra = canonical.clone();
    extra.push(attention_call(heads as u32));
    assert!(validate_production_attention_group(&call_refs(&extra)).is_err());
    for mutate in [
        |call: &mut TensorProductionFullLayerWitness| call.head_start += 1,
        |call: &mut TensorProductionFullLayerWitness| call.layer += 1,
        |call: &mut TensorProductionFullLayerWitness| call.head_count += 1,
        |call: &mut TensorProductionFullLayerWitness| call.input_tensor_id += 1,
        |call: &mut TensorProductionFullLayerWitness| call.input_version += 1,
        |call: &mut TensorProductionFullLayerWitness| call.projected_qkv_version += 1,
        |call: &mut TensorProductionFullLayerWitness| call.output_version += 1,
        |call: &mut TensorProductionFullLayerWitness| call.attention_output_version += 1,
    ] {
        let mut invalid = canonical.clone();
        mutate(&mut invalid[heads - 1]);
        assert!(validate_production_attention_group(&call_refs(&invalid)).is_err());
    }
    if heads > 1 {
        let mut duplicate = canonical.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(validate_production_attention_group(&call_refs(&duplicate)).is_err());
        let mut reversed = canonical;
        reversed.swap(0, 1);
        assert!(validate_production_attention_group(&call_refs(&reversed)).is_err());
    }
}

fn boundary(slot: usize) -> TensorProductionBoundaryReplayDescriptor {
    let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
    TensorProductionBoundaryReplayDescriptor {
        layer: 3,
        stage: 1,
        direction: 0,
        part: 0,
        group: 2,
        head_start: (2 * heads + slot) as u32,
        head_count: 1,
        step_index: slot,
        import_cycle: 100 + slot as u64,
        tensor_id: 200 + slot as u64,
        tensor_version: 7,
        base_byte_address: 0,
        tensor_index_start: 0,
        values: Arc::from([]),
        rows: 1 << 18,
        log_rows: 18,
    }
}

#[test]
fn boundary_groups_reject_missing_extra_order_and_descriptor_drift() {
    let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
    let canonical = (0..heads).map(boundary).collect::<Vec<_>>();
    validate_production_boundary_group(&canonical).unwrap();
    assert!(validate_production_boundary_group(&canonical[..heads - 1]).is_err());
    let mut extra = canonical.clone();
    extra.push(boundary(heads));
    assert!(validate_production_boundary_group(&extra).is_err());
    for mutate in [
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.layer += 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.direction += 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.part += 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.group += 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.head_count += 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.rows *= 2,
    ] {
        let mut invalid = canonical.clone();
        mutate(&mut invalid[heads - 1]);
        assert!(validate_production_boundary_group(&invalid).is_err());
    }
    if heads > 1 {
        let mut duplicate = canonical.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(validate_production_boundary_group(&duplicate).is_err());
        let mut reversed = canonical;
        reversed.swap(0, 1);
        assert!(validate_production_boundary_group(&reversed).is_err());
    }
}

fn hidden_boundary(slot: usize, values: Arc<[i32]>) -> TensorProductionBoundaryReplayDescriptor {
    TensorProductionBoundaryReplayDescriptor {
        layer: 3,
        stage: 0,
        direction: 0,
        part: 0,
        group: 0,
        head_start: slot as u32,
        head_count: 1,
        step_index: slot,
        import_cycle: 100 + slot as u64,
        tensor_id: 200 + slot as u64,
        tensor_version: 7 + slot as u32,
        base_byte_address: 300 + slot as u32,
        tensor_index_start: 1,
        values,
        rows: 4,
        log_rows: 2,
    }
}

#[test]
fn hidden_broadcast_rejects_noncanonical_shape_and_values() {
    let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
    let values: Arc<[i32]> = Arc::from([99, 10, 20, 30, 40, 88]);
    let canonical = (0..heads)
        .map(|slot| hidden_boundary(slot, values.clone()))
        .collect::<Vec<_>>();
    validate_production_boundary_group(&canonical).unwrap();
    assert!(validate_production_boundary_group(&canonical[..heads - 1]).is_err());

    for mutate in [
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.layer += 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.group += 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.head_start += 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.head_count += 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.tensor_index_start = 0,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.rows -= 1,
        |item: &mut TensorProductionBoundaryReplayDescriptor| item.log_rows += 1,
    ] {
        let mut invalid = canonical.clone();
        mutate(&mut invalid[heads - 1]);
        assert!(validate_production_boundary_group(&invalid).is_err());
    }

    let mut changed_value = canonical;
    changed_value[heads - 1].values = Arc::from([99, 10, 20, 31, 40, 88]);
    assert!(validate_production_boundary_group(&changed_value).is_err());
}

#[test]
fn hidden_broadcast_vk_has_one_value_and_n_metadata_record_sets() {
    let heads = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
    let cs = construct::<TensorProductionBoundaryHiddenInputInstruction<E>>();
    assert_eq!(cs.num_witin as usize, 4 + 5 * heads);
    let value_columns = cs
        .witin_namespace_map
        .iter()
        .enumerate()
        .filter_map(|(index, name)| name.contains("production_boundary_value").then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(value_columns.len(), 2);
    assert_eq!(
        cs.witin_namespace_map
            .iter()
            .filter(|name| name.contains("production_boundary_sign"))
            .count(),
        1
    );
    for slot in 0..heads {
        for field in [
            "import_cycle",
            "tensor_id_lo",
            "tensor_id_hi",
            "tensor_version",
            "base_byte_address",
        ] {
            assert_eq!(
                cs.witin_namespace_map
                    .iter()
                    .filter(|name| name.contains(&format!("production_boundary_{field}_{slot}")))
                    .count(),
                1
            );
        }
    }
    assert_eq!(
        cs.w_expressions_namespace_map
            .iter()
            .filter(|name| name.contains("production_hidden_witness_local_write_"))
            .count(),
        heads
    );
    assert_eq!(
        cs.r_expressions_namespace_map
            .iter()
            .filter(|name| name.contains("production_hidden_witness_local_read_"))
            .count(),
        heads
    );

    let mut witness = vec![F::ZERO; cs.num_witin as usize];
    set_named(
        &cs.witin_namespace_map,
        &mut witness,
        "production_boundary_layer",
        5,
    );
    witness[value_columns[0]] = F::from_u64(123);
    for slot in 0..heads {
        set_named(
            &cs.witin_namespace_map,
            &mut witness,
            &format!("production_boundary_import_cycle_{slot}"),
            100 + slot as u64,
        );
        set_named(
            &cs.witin_namespace_map,
            &mut witness,
            &format!("production_boundary_tensor_id_lo_{slot}"),
            200 + slot as u64,
        );
        set_named(
            &cs.witin_namespace_map,
            &mut witness,
            &format!("production_boundary_tensor_version_{slot}"),
            7 + slot as u64,
        );
        let record_index = cs
            .w_expressions_namespace_map
            .iter()
            .position(|name| {
                name.contains(&format!("production_hidden_witness_local_write_{slot}"))
            })
            .unwrap();
        let record = &cs.w_ram_types[record_index].1;
        assert_eq!(
            eval(
                &record[2],
                &witness,
                &vec![F::ZERO; cs.num_structural_witin as usize]
            ),
            E::from_v(100 + slot as u64)
        );
        assert_eq!(
            eval(
                &record[4],
                &witness,
                &vec![F::ZERO; cs.num_structural_witin as usize]
            ),
            E::from_v(200 + slot as u64)
        );
        assert_eq!(
            eval(
                &record[6],
                &witness,
                &vec![F::ZERO; cs.num_structural_witin as usize]
            ),
            E::from_v(7 + slot as u64)
        );
        assert_eq!(
            eval(
                &record[8],
                &witness,
                &vec![F::ZERO; cs.num_structural_witin as usize]
            ),
            E::from_v(123)
        );
    }
}

#[test]
fn fused_pv_and_boundary_scheduling_is_exclusive() {
    for name in [
        TensorAttentionQkShiftSoftmax::<E, 2>::name(),
        TensorAttentionQkShiftSoftmax::<E, 4>::name(),
        TensorAttentionPv::<E, 2>::name(),
        TensorAttentionPv::<E, 4>::name(),
        "TensorProductionBoundaryAttentionInputPart0Heads00_01".into(),
    ] {
        assert!(is_exclusive_production_circuit(&name), "{name}");
    }
    assert!(!is_exclusive_production_circuit(
        "TensorProjectionDenseQueryHeads00_00"
    ));
}
