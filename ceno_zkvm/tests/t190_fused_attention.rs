use ceno_zkvm::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    instructions::{Instruction, riscv::ecall::TensorProductionQkShiftSoftmaxCoreInstruction},
    scheme::mock_prover::MockProver,
    structs::ProgramParams,
    tables::{LlamaTinyRom, ProductionSoftmaxExpHighRom, ProductionSoftmaxExpMiddleRom},
};
use ff_ext::{BabyBearExt4, ExtensionField, FieldFrom};
use multilinear_extensions::{
    Expression,
    mle::{ArcMultilinearExtension, MultilinearExtension},
    utils::eval_by_expr_with_instance,
};
use p3::field::{Field, PrimeCharacteristicRing, PrimeField64};

type E = BabyBearExt4;
type F = <E as ExtensionField>::BaseField;

fn circuit() -> ConstraintSystem<E> {
    let mut cs =
        ConstraintSystem::<E>::new(|| TensorProductionQkShiftSoftmaxCoreInstruction::<E>::name());
    let mut cb = CircuitBuilder::new(&mut cs);
    TensorProductionQkShiftSoftmaxCoreInstruction::construct_circuit(
        &mut cb,
        &ProgramParams::default(),
    )
    .unwrap();
    cs
}

fn id(names: &[String], needle: &str) -> usize {
    names
        .iter()
        .position(|name| name.contains(needle))
        .unwrap_or_else(|| panic!("missing fused column {needle}"))
}

fn canonical_row(cs: &ConstraintSystem<E>) -> (Vec<F>, Vec<F>) {
    let mut witness = vec![F::ZERO; cs.num_witin as usize];
    let mut structural = vec![F::ZERO; cs.num_structural_witin as usize];
    let w = |name| id(&cs.witin_namespace_map, name);
    let s = |name| id(&cs.structural_witin_namespace_map, name);
    let physical = 1_u64 << 11;

    witness[w("production_fused_qk_a")] = F::from_u64(2);
    witness[w("production_fused_qk_w")] = -F::from_u64(3);
    witness[w("production_fused_qk_q")] = -F::ONE;
    witness[w("production_fused_qk_remainder")] = F::from_u64(65_530);
    witness[w("production_fused_qk_a_low7")] = F::from_u64(2);
    witness[w("production_fused_qk_w_low7")] = F::from_u64(125);
    witness[w("production_fused_qk_w_sign")] = F::ONE;
    witness[w("production_fused_qk_axis_active")] = F::ONE;
    witness[w("production_fused_qk_row_active")] = F::ONE;
    witness[w("production_fused_import_cycle")] = F::from_u64(3);
    witness[w("production_fused_input_id_lo")] = F::from_u64(4);
    witness[w("production_fused_input_id_hi")] = F::from_u64(5);
    witness[w("production_fused_input_version")] = F::from_u64(6);
    witness[w("production_fused_layer")] = F::from_u64(7);
    witness[w("production_fused_head_start")] = F::from_u64(8);
    witness[w("production_fused_output_id_lo")] = F::from_u64(9);
    witness[w("production_fused_output_id_hi")] = F::from_u64(10);
    witness[w("production_fused_output_version")] = F::from_u64(11);
    witness[w("production_fused_call_row_inverse")] = F::from_u64(physical).inverse();
    witness[w("production_fused_shift")] = F::from_u64(10);
    witness[w("production_fused_softmax_limb_0")] = F::from_u64(16);
    let exp3 = F::from_u64(ProductionSoftmaxExpMiddleRom::output(0) as u64);
    let exp4 = F::from_u64(ProductionSoftmaxExpHighRom::output(0) as u64);
    witness[w("production_fused_softmax_exp3")] = exp3;
    witness[w("production_fused_softmax_exp4")] = exp4;
    witness[w("production_fused_softmax_causal")] = F::ONE;
    witness[w("production_fused_softmax_diff_bit_0")] = F::ONE;
    witness[w("production_fused_softmax_probability")] = exp3 * exp4;

    structural[s("production_fused_axis_low7_prefix")] = F::ZERO;
    structural[s("production_fused_axis_high4_prefix")] = F::ZERO;
    structural[s("production_fused_row_low7_prefix")] = F::from_u64(physical);
    structural[s("production_fused_row_high4_prefix")] = F::from_u64(physical);
    structural[s("production_fused_physical_index")] = F::from_u64(physical);
    for name in [
        "matrix_a_selector",
        "matrix_w_selector",
        "matrix_output_selector",
        "/selector",
    ] {
        structural[s(name)] = F::ONE;
    }
    (witness, structural)
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
        .unwrap_or_else(|| panic!("missing fused constraint {needle}"))
}

fn one_row_mles(values: &[F]) -> Vec<ArcMultilinearExtension<'_, E>> {
    values
        .iter()
        .map(|value| MultilinearExtension::from_evaluation_vec_smart(0, vec![*value]).into())
        .collect()
}

#[test]
fn fused_positive_q_reconstruction_records_and_lookups() {
    let mut cs = circuit();
    let (witness, structural) = canonical_row(&cs);
    for expression in cs
        .assert_zero_expressions
        .iter()
        .chain(&cs.assert_zero_sumcheck_expressions)
    {
        assert_eq!(eval(expression, &witness, &structural), E::ZERO);
    }
    let q = witness[id(&cs.witin_namespace_map, "production_fused_qk_q")];
    assert_eq!(q, -F::ONE);
    assert_eq!(q.as_canonical_u64(), 2_013_265_920);
    let remainder = witness[id(&cs.witin_namespace_map, "production_fused_qk_remainder")];
    assert_eq!(-65_536 + remainder.as_canonical_u64() as i64, -6);
    let descriptor = ceno_zkvm::scheme::matrix_reduction::descriptor(
        &TensorProductionQkShiftSoftmaxCoreInstruction::<E>::name(),
    )
    .unwrap();
    assert_eq!(descriptor.columns, [0, 1, 2, 3]);
    assert_eq!(descriptor.shift, 16);

    let reads = cs.r_expressions_namespace_map.join("\n");
    let writes = cs.w_expressions_namespace_map.join("\n");
    assert!(reads.contains("attention_call_once"));
    assert!(reads.contains("fused_q_read") && reads.contains("fused_k_read"));
    assert!(!reads.contains("score") && !reads.contains("shift"));
    assert!(writes.contains("probability_write"));
    assert!(!writes.contains("score") && !writes.contains("shift"));
    assert_eq!(
        eval(&cs.w_ram_types[0].1[6], &witness, &structural),
        E::from_v(13)
    );

    let challenge = [E::from_v(7), E::from_v(11)];
    let cb = CircuitBuilder::new(&mut cs);
    MockProver::assert_satisfied(
        &cb,
        &one_row_mles(&witness),
        &one_row_mles(&structural),
        &[],
        Some(challenge),
        None,
    );
}

#[test]
fn fused_negative_internal_seams_lookup_order_and_version() {
    let mut cs = circuit();
    let (witness, structural) = canonical_row(&cs);
    let q = id(&cs.witin_namespace_map, "production_fused_qk_q");
    let remainder = id(&cs.witin_namespace_map, "production_fused_qk_remainder");
    let shift = id(&cs.witin_namespace_map, "production_fused_shift");
    let causal = id(&cs.witin_namespace_map, "production_fused_softmax_causal");
    let probability = id(
        &cs.witin_namespace_map,
        "production_fused_softmax_probability",
    );
    let exp3 = id(&cs.witin_namespace_map, "production_fused_softmax_exp3");
    let output_version = id(&cs.witin_namespace_map, "production_fused_output_version");
    let physical_index = id(
        &cs.structural_witin_namespace_map,
        "production_fused_physical_index",
    );
    let version_expr = cs.w_ram_types[0].1[6].clone();
    for (constraint, column, delta) in [
        ("production_fused_qk_quotient", q, F::from_u64(2)),
        (
            "production_fused_softmax_shifted_magnitude",
            remainder,
            F::ONE,
        ),
        ("production_fused_softmax_shifted_magnitude", shift, F::ONE),
        ("production_fused_softmax_causal_comparison", causal, F::ONE),
        (
            "production_fused_softmax_masked_probability",
            probability,
            F::ONE,
        ),
    ] {
        let mut bad = witness.clone();
        bad[column] += delta;
        assert_ne!(
            eval(named_zero(&cs, constraint), &bad, &structural),
            E::ZERO
        );
    }
    let mut bad_order = structural.clone();
    bad_order[physical_index] += F::ONE;
    assert_ne!(
        eval(
            named_zero(&cs, "production_fused_physical_coordinate"),
            &witness,
            &bad_order,
        ),
        E::ZERO
    );

    let mut bad_lookup = witness.clone();
    bad_lookup[exp3] += F::ONE;
    let challenge = [E::from_v(7), E::from_v(11)];
    let cb = CircuitBuilder::new(&mut cs);
    assert!(
        MockProver::run_with_challenge(
            &cb,
            &[],
            &one_row_mles(&bad_lookup),
            &one_row_mles(&structural),
            challenge,
            None,
        )
        .is_err()
    );

    let expected_version = eval(&version_expr, &witness, &structural);
    let mut bad_version = witness;
    bad_version[output_version] += F::ONE;
    assert_eq!(
        eval(&version_expr, &bad_version, &structural),
        expected_version + E::ONE
    );
}
