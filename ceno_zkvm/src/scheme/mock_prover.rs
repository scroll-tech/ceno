use super::utils::{eval_by_expr, wit_infer_by_expr};
use crate::{
    circuit_builder::CircuitBuilder,
    expression::Expression,
    structs::{ROMType, WitnessId},
};
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;
use std::{collections::HashSet, hash::Hash, marker::PhantomData, ops::Neg};

#[allow(clippy::enum_variant_names)]
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum MockProverError<E: ExtensionField> {
    AssertZeroError {
        expression: Expression<E>,
        evaluated: E,
        name: String,
        inst_id: usize,
    },
    AssertEqualError {
        left_expression: Expression<E>,
        right_expression: Expression<E>,
        left: E,
        right: E,
        name: String,
        inst_id: usize,
    },
    LookupError {
        expression: Expression<E>,
        evaluated: E,
        name: String,
        inst_id: usize,
    },
    // TODO later
    // r_expressions
    // w_expressions
}

impl<E: ExtensionField> MockProverError<E> {
    pub fn print(&self, wits_in: &[ArcMultilinearExtension<E>]) {
        let mut wtns = vec![];

        match self {
            Self::AssertZeroError {
                expression,
                evaluated,
                name,
                inst_id,
            } => {
                let expression_fmt = fmt_expr(expression, &mut wtns, false);
                let wtns_fmt = fmt_wtns::<E>(&wtns, wits_in, *inst_id);
                let eval_fmt = fmt_field::<E>(evaluated);
                println!(
                    "\nAssertZeroError {name:?}: Evaluated expression is not zero\n\
                    Expression: {expression_fmt}\n\
                    Evaluation: {eval_fmt} != 0\n\
                    Inst[{inst_id}]: {wtns_fmt}\n",
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
                let left_expression_fmt = fmt_expr(left_expression, &mut wtns, false);
                let right_expression_fmt = fmt_expr(right_expression, &mut wtns, false);
                let wtns_fmt = fmt_wtns::<E>(&wtns, wits_in, *inst_id);
                let left_eval_fmt = fmt_field::<E>(left);
                let right_eval_fmt = fmt_field::<E>(right);
                println!(
                    "\nAssertEqualError {name:?}\n\
                    Left: {left_eval_fmt} != Right: {right_eval_fmt}\n\
                    Left Expression: {left_expression_fmt}\n\
                    Right Expression: {right_expression_fmt}\n\
                    Inst[{inst_id}]: {wtns_fmt}\n",
                );
            }
            Self::LookupError {
                expression,
                evaluated,
                name,
                inst_id,
            } => {
                let expression_fmt = fmt_expr(expression, &mut wtns, false);
                let wtns_fmt = fmt_wtns::<E>(&wtns, wits_in, *inst_id);
                let eval_fmt = fmt_field::<E>(evaluated);
                println!(
                    "\nLookupError {name:#?}: Evaluated expression does not exist in T vector\n\
                    Expression: {expression_fmt}\n\
                    Evaluation: {eval_fmt}\n\
                    Inst[{inst_id}]: {wtns_fmt}\n",
                );
            }
        }

        fn fmt_expr<E: ExtensionField>(
            expression: &Expression<E>,
            wtns: &mut Vec<WitnessId>,
            add_prn_sum: bool,
        ) -> String {
            match expression {
                Expression::WitIn(wit_in) => {
                    wtns.push(*wit_in);
                    format!("WitIn({})", wit_in)
                }
                Expression::Challenge(id, _, _, _) => format!("Challenge({})", id),
                Expression::Constant(constant) => fmt_base_field::<E>(constant, true).to_string(),
                Expression::Fixed(fixed) => format!("{:?}", fixed),
                Expression::Sum(left, right) => {
                    let s = format!(
                        "{} + {}",
                        fmt_expr(left, wtns, false),
                        fmt_expr(right, wtns, false)
                    );
                    if add_prn_sum { format!("({})", s) } else { s }
                }
                Expression::Product(left, right) => {
                    format!(
                        "{} * {}",
                        fmt_expr(left, wtns, true),
                        fmt_expr(right, wtns, true)
                    )
                }
                Expression::ScaledSum(x, a, b) => {
                    let s = format!(
                        "{} * {} + {}",
                        fmt_expr(a, wtns, true),
                        fmt_expr(x, wtns, true),
                        fmt_expr(b, wtns, false)
                    );
                    if add_prn_sum { format!("({})", s) } else { s }
                }
            }
        }

        fn fmt_field<E: ExtensionField>(field: &E) -> String {
            let name = format!("{:?}", field);
            let name = name.split('(').next().unwrap_or("ExtensionField");
            format!(
                "{name}[{}]",
                field
                    .as_bases()
                    .iter()
                    .map(|b| fmt_base_field::<E>(b, false))
                    .collect::<Vec<String>>()
                    .join(",")
            )
        }

        fn fmt_base_field<E: ExtensionField>(base_field: &E::BaseField, add_prn: bool) -> String {
            let value = base_field.to_canonical_u64();

            if value > E::BaseField::MODULUS_U64 - u16::MAX as u64 {
                // beautiful format for negative number > -65536
                fmt_prn(format!("-{}", E::BaseField::MODULUS_U64 - value), add_prn)
            } else if value < u16::MAX as u64 {
                format!("{value}")
            } else {
                // hex
                if value > E::BaseField::MODULUS_U64 - (u32::MAX as u64 + u16::MAX as u64) {
                    fmt_prn(
                        format!("-{:#x}", E::BaseField::MODULUS_U64 - value),
                        add_prn,
                    )
                } else {
                    format!("{value:#x}")
                }
            }
        }

        fn fmt_prn(s: String, add_prn: bool) -> String {
            if add_prn { format!("({})", s) } else { s }
        }

        fn fmt_wtns<E: ExtensionField>(
            wtns: &[WitnessId],
            wits_in: &[ArcMultilinearExtension<E>],
            inst_id: usize,
        ) -> String {
            wtns.iter()
                .sorted()
                .map(|wt_id| {
                    let wit = &wits_in[*wt_id as usize];
                    let value_fmt = if let Some(e) = wit.get_ext_field_vec_optn() {
                        fmt_field(&e[inst_id])
                    } else if let Some(bf) = wit.get_base_field_vec_optn() {
                        fmt_base_field::<E>(&bf[inst_id], true)
                    } else {
                        "Unknown".to_string()
                    };
                    format!("WitIn({wt_id})={value_fmt}")
                })
                .join(",")
        }
    }
}

pub(crate) struct MockProver<E: ExtensionField> {
    _phantom: PhantomData<E>,
}

impl<'a, E: ExtensionField> MockProver<E>
where
    E: Hash,
{
    #[allow(dead_code)]
    pub fn run(
        cb: &mut CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        challenge: Option<[E; 2]>,
    ) -> Result<(), Vec<MockProverError<E>>> {
        let challenge = challenge.unwrap_or([E::ONE, E::ONE]);

        let mut errors = vec![];

        // Assert zero expressions
        for (expr, name) in cb
            .cs
            .assert_zero_expressions
            .iter()
            .chain(&cb.cs.assert_zero_sumcheck_expressions)
            .zip_eq(
                cb.cs
                    .assert_zero_expressions_namespace_map
                    .iter()
                    .chain(&cb.cs.assert_zero_sumcheck_expressions_namespace_map),
            )
        {
            if name.contains("require_equal") {
                let (left, right) = expr.unpack_sum().unwrap();

                let left = left.neg().neg(); // TODO get_ext_field_vec doesn't work without this
                let right = right.neg();

                let left_evaluated = wit_infer_by_expr(&[], wits_in, &challenge, &left);
                let left_evaluated = left_evaluated.get_ext_field_vec();

                let right_evaluated = wit_infer_by_expr(&[], wits_in, &challenge, &right);
                let right_evaluated = right_evaluated.get_ext_field_vec();

                for (inst_id, (left_element, right_element)) in
                    left_evaluated.iter().zip_eq(right_evaluated).enumerate()
                {
                    if *left_element != *right_element {
                        errors.push(MockProverError::AssertEqualError {
                            left_expression: left.clone(),
                            right_expression: right.clone(),
                            left: *left_element,
                            right: *right_element,
                            name: name.clone(),
                            inst_id,
                        });
                    }
                }
            } else {
                // contains require_zero
                let expr = expr.clone().neg().neg(); // TODO get_ext_field_vec doesn't work without this
                let expr_evaluated = wit_infer_by_expr(&[], wits_in, &challenge, &expr);
                let expr_evaluated = expr_evaluated.get_ext_field_vec();

                for (inst_id, element) in expr_evaluated.iter().enumerate() {
                    if *element != E::ZERO {
                        errors.push(MockProverError::AssertZeroError {
                            expression: expr.clone(),
                            evaluated: *element,
                            name: name.clone(),
                            inst_id,
                        });
                    }
                }
            }
        }

        // TODO load more tables here
        // TODO cache table_vec across unittest
        let mut table_vec = vec![];
        load_u5_table(&mut table_vec, cb, challenge);
        load_u16_table(&mut table_vec, cb, challenge);
        load_lt_table(&mut table_vec, cb, challenge);
        let table: HashSet<E> = table_vec.into_iter().collect();

        // Lookup expressions
        for (expr, name) in cb
            .cs
            .lk_expressions
            .iter()
            .zip_eq(cb.cs.lk_expressions_namespace_map.iter())
        {
            let expr_evaluated = wit_infer_by_expr(&[], wits_in, &challenge, expr);
            let expr_evaluated = expr_evaluated.get_ext_field_vec();

            // Check each lookup expr exists in t vec
            for (inst_id, element) in expr_evaluated.iter().enumerate() {
                if !table.contains(element) {
                    errors.push(MockProverError::LookupError {
                        expression: expr.clone(),
                        evaluated: *element,
                        name: name.clone(),
                        inst_id,
                    });
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    #[allow(dead_code)]
    pub fn assert_satisfied(
        cb: &mut CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        challenge: Option<[E; 2]>,
    ) {
        let result = Self::run(cb, wits_in, challenge);
        match result {
            Ok(_) => {}
            Err(errors) => {
                println!("======================================================");
                println!("Error: {} constraints not satisfied", errors.len());

                for error in errors {
                    error.print(wits_in);
                }
                println!("======================================================");
                panic!("Constraints not satisfied");
            }
        }
    }
}

pub fn load_u5_table<E: ExtensionField>(
    t_vec: &mut Vec<E>,
    cb: &CircuitBuilder<E>,
    challenge: [E; 2],
) {
    for i in 0..(1 << 5) {
        let rlc_record = cb.rlc_chip_record(vec![
            Expression::Constant(E::BaseField::from(ROMType::U5 as u64)),
            i.into(),
        ]);
        let rlc_record = eval_by_expr(&[], &challenge, &rlc_record);
        t_vec.push(rlc_record);
    }
}

pub fn load_u16_table<E: ExtensionField>(
    t_vec: &mut Vec<E>,
    cb: &CircuitBuilder<E>,
    challenge: [E; 2],
) {
    t_vec.reserve(1 << 16);
    for i in 0..(1 << 16) {
        let rlc_record = cb.rlc_chip_record(vec![
            Expression::Constant(E::BaseField::from(ROMType::U16 as u64)),
            i.into(),
        ]);
        let rlc_record = eval_by_expr(&[], &challenge, &rlc_record);
        t_vec.push(rlc_record);
    }
}

pub fn load_lt_table<E: ExtensionField>(
    t_vec: &mut Vec<E>,
    cb: &CircuitBuilder<E>,
    challenge: [E; 2],
) {
    t_vec.reserve(1 << 16);
    for lhs in 0..(1 << 8) {
        for rhs in 0..(1 << 8) {
            let is_lt = if lhs < rhs { 1 } else { 0 };
            let lhs_rhs = lhs * 256 + rhs;
            let rlc_record = cb.rlc_chip_record(vec![
                Expression::Constant(E::BaseField::from(ROMType::Ltu as u64)),
                lhs_rhs.into(),
                is_lt.into(),
            ]);
            let rlc_record = eval_by_expr(&[], &challenge, &rlc_record);
            t_vec.push(rlc_record);
        }
    }
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        error::ZKVMError,
        expression::{ToExpr, WitIn},
        instructions::{
            riscv::config::{ExprLtConfig, ExprLtInput},
            Instruction,
        },
        set_val,
        witness::RowMajorMatrix,
    };
    use ff::Field;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use multilinear_extensions::mle::{IntoMLE, IntoMLEs};
    use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

    #[derive(Debug)]
    #[allow(dead_code)]
    struct AssertZeroCircuit {
        pub a: WitIn,
        pub b: WitIn,
        pub c: WitIn,
    }

    impl AssertZeroCircuit {
        pub fn construct_circuit(
            cb: &mut CircuitBuilder<GoldilocksExt2>,
        ) -> Result<Self, ZKVMError> {
            let a = cb.create_witin(|| "a")?;
            let b = cb.create_witin(|| "b")?;
            let c = cb.create_witin(|| "c")?;

            // degree 1
            cb.require_equal(|| "a + 1 == b", b.expr(), a.expr() + 1.into())?;
            cb.require_zero(|| "c - 2 == 0", c.expr() - 2.into())?;

            // degree > 1
            let d = cb.create_witin(|| "d")?;
            cb.require_zero(
                || "d*d - 6*d + 9 == 0",
                d.expr() * d.expr() - d.expr() * 6.into() + 9.into(),
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
            vec![Goldilocks::from(3), Goldilocks::from(500)]
                .into_mle()
                .into(),
            vec![Goldilocks::from(4), Goldilocks::from(501)]
                .into_mle()
                .into(),
            vec![Goldilocks::from(2), Goldilocks::from(2)]
                .into_mle()
                .into(),
            vec![Goldilocks::from(3), Goldilocks::from(3)]
                .into_mle()
                .into(),
        ];

        MockProver::assert_satisfied(&mut builder, &wits_in, None);
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
            let a = cb.create_witin(|| "a")?;
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
            vec![Goldilocks::from(3u64), Goldilocks::from(5u64)]
                .into_mle()
                .into(),
        ];

        let challenge = [1.into(), 1000.into()];
        MockProver::assert_satisfied(&mut builder, &wits_in, Some(challenge));
    }

    #[test]
    // TODO: add it back after the support of missing lookup
    fn test_lookup_error() {
        let mut cs = ConstraintSystem::new(|| "test_lookup_error");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let _ = RangeCheckCircuit::construct_circuit(&mut builder).unwrap();

        let wits_in = vec![vec![Goldilocks::from(123)].into_mle().into()];

        let challenge = [2.into(), 1000.into()];
        let result = MockProver::run(&mut builder, &wits_in, Some(challenge));
        assert!(result.is_err(), "Expected error");
        let err = result.unwrap_err();
        assert_eq!(
            err,
            vec![MockProverError::LookupError {
                expression: Expression::ScaledSum(
                    Box::new(Expression::WitIn(0)),
                    Box::new(Expression::Challenge(
                        1,
                        1,
                        // TODO this still uses default challenge in ConstraintSystem, but challengeId
                        // helps to evaluate the expression correctly. Shoudl challenge be just challengeId?
                        GoldilocksExt2::ONE,
                        GoldilocksExt2::ZERO,
                    )),
                    Box::new(Expression::Challenge(
                        0,
                        1,
                        GoldilocksExt2::ONE,
                        GoldilocksExt2::ZERO,
                    )),
                ),
                evaluated: 123002.into(), // 123 * 1000 + 2
                name: "test_lookup_error/assert_u5/assert u5".to_string(),
                inst_id: 0,
            }]
        );
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    struct AssertLtCircuit {
        pub a: WitIn,
        pub b: WitIn,
        pub lt_wtns: ExprLtConfig,
    }

    struct AssertLtCircuitInput {
        pub a: u64,
        pub b: u64,
    }

    impl AssertLtCircuit {
        fn construct_circuit(cb: &mut CircuitBuilder<GoldilocksExt2>) -> Result<Self, ZKVMError> {
            let a = cb.create_witin(|| "a")?;
            let b = cb.create_witin(|| "b")?;
            let lt_wtns = cb.less_than(|| "lt", a.expr(), b.expr(), Some(true))?;
            Ok(Self { a, b, lt_wtns })
        }

        fn assign_instance<E: ExtensionField>(
            &self,
            instance: &mut [MaybeUninit<E::BaseField>],
            input: AssertLtCircuitInput,
        ) -> Result<(), ZKVMError> {
            set_val!(instance, self.a, input.a);
            set_val!(instance, self.b, input.b);
            ExprLtInput {
                lhs: input.a,
                rhs: input.b,
            }
            .assign(instance, &self.lt_wtns);

            Ok(())
        }

        fn assign_instances<E: ExtensionField>(
            &self,
            num_witin: usize,
            instances: Vec<AssertLtCircuitInput>,
        ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
            let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(instances.len(), num_witin);
            let raw_witin_iter = raw_witin.par_iter_mut();

            raw_witin_iter
                .zip_eq(instances.into_par_iter())
                .map(|(instance, input)| self.assign_instance::<E>(instance, input))
                .collect::<Result<(), ZKVMError>>()?;

            Ok(raw_witin)
        }
    }

    #[test]
    fn test_assert_lt_1() {
        let mut cs = ConstraintSystem::new(|| "test_assert_lt_1");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let circuit = AssertLtCircuit::construct_circuit(&mut builder).unwrap();

        let raw_witin = circuit
            .assign_instances::<GoldilocksExt2>(
                builder.cs.num_witin as usize,
                vec![
                    AssertLtCircuitInput { a: 3, b: 5 },
                    AssertLtCircuitInput { a: 7, b: 11 },
                ],
            )
            .unwrap();

        MockProver::assert_satisfied(
            &mut builder,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            Some([1.into(), 1000.into()]),
        );
    }

    #[test]
    fn test_assert_lt_u32() {
        let mut cs = ConstraintSystem::new(|| "test_assert_lt_u32");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let circuit = AssertLtCircuit::construct_circuit(&mut builder).unwrap();
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
            )
            .unwrap();

        MockProver::assert_satisfied(
            &mut builder,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            Some([1.into(), 1000.into()]),
        );
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    struct LtCircuit {
        pub a: WitIn,
        pub b: WitIn,
        pub lt_wtns: ExprLtConfig,
    }

    struct LtCircuitInput {
        pub a: u64,
        pub b: u64,
    }

    impl LtCircuit {
        fn construct_circuit(cb: &mut CircuitBuilder<GoldilocksExt2>) -> Result<Self, ZKVMError> {
            let a = cb.create_witin(|| "a")?;
            let b = cb.create_witin(|| "b")?;
            let lt_wtns = cb.less_than(|| "lt", a.expr(), b.expr(), None)?;
            Ok(Self { a, b, lt_wtns })
        }

        fn assign_instance<E: ExtensionField>(
            &self,
            instance: &mut [MaybeUninit<E::BaseField>],
            input: LtCircuitInput,
        ) -> Result<(), ZKVMError> {
            set_val!(instance, self.a, input.a);
            set_val!(instance, self.b, input.b);
            ExprLtInput {
                lhs: input.a,
                rhs: input.b,
            }
            .assign(instance, &self.lt_wtns);

            Ok(())
        }

        fn assign_instances<E: ExtensionField>(
            &self,
            num_witin: usize,
            instances: Vec<LtCircuitInput>,
        ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
            let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(instances.len(), num_witin);
            let raw_witin_iter = raw_witin.par_iter_mut();

            raw_witin_iter
                .zip_eq(instances.into_par_iter())
                .map(|(instance, input)| self.assign_instance::<E>(instance, input))
                .collect::<Result<(), ZKVMError>>()?;

            Ok(raw_witin)
        }
    }

    #[test]
    fn test_lt_1() {
        let mut cs = ConstraintSystem::new(|| "test_lt_1");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let circuit = LtCircuit::construct_circuit(&mut builder).unwrap();

        let raw_witin = circuit
            .assign_instances::<GoldilocksExt2>(
                builder.cs.num_witin as usize,
                vec![
                    LtCircuitInput { a: 3, b: 5 },
                    LtCircuitInput { a: 7, b: 11 },
                ],
            )
            .unwrap();

        MockProver::assert_satisfied(
            &mut builder,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            Some([1.into(), 1000.into()]),
        );
    }

    #[test]
    fn test_lt_u32() {
        let mut cs = ConstraintSystem::new(|| "test_lt_u32");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let circuit = LtCircuit::construct_circuit(&mut builder).unwrap();

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
            )
            .unwrap();

        MockProver::assert_satisfied(
            &mut builder,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            Some([1.into(), 1000.into()]),
        );
    }
}
