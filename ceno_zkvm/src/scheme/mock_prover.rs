use super::utils::{eval_by_expr, wit_infer_by_expr};
use crate::{
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    expression::{fmt, Expression},
    scheme::utils::eval_by_expr_with_fixed,
    tables::{
        AndTable, LtuTable, OpsTable, OrTable, ProgramTableCircuit, RangeTable, TableCircuit,
        U16Table, U5Table, U8Table, XorTable,
    },
};
use ark_std::test_rng;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ceno_emul::{ByteAddr, CENO_PLATFORM};
use ff_ext::ExtensionField;
use generic_static::StaticTypeMap;
use itertools::Itertools;
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;
use std::{
    collections::HashSet,
    fs::{self, File},
    hash::Hash,
    io::{BufReader, ErrorKind},
    marker::PhantomData,
    ops::Neg,
    sync::OnceLock,
};

pub const MOCK_RS1: u32 = 2;
pub const MOCK_RS2: u32 = 3;
pub const MOCK_RD: u32 = 4;
pub const MOCK_IMM_3: u32 = 3;
pub const MOCK_IMM_31: u32 = 31;
pub const MOCK_IMM_NEG3: u32 = 32 - 3;
/// The program baked in the MockProver.
/// TODO: Make this a parameter?
#[allow(clippy::identity_op)]
#[allow(clippy::unusual_byte_groupings)]
pub const MOCK_PROGRAM: &[u32] = &[
    // R-Type
    // funct7 | rs2 | rs1 | funct3 | rd | opcode
    // -----------------------------------------
    // add x4, x2, x3
    0x00 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0x00 << 12 | MOCK_RD << 7 | 0x33,
    // sub  x4, x2, x3
    0x20 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0x00 << 12 | MOCK_RD << 7 | 0x33,
    // mul (0x01, 0x00, 0x33)
    0x01 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0x00 << 12 | MOCK_RD << 7 | 0x33,
    // and x4, x2, x3
    0x00 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b111 << 12 | MOCK_RD << 7 | 0x33,
    // or x4, x2, x3
    0x00 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b110 << 12 | MOCK_RD << 7 | 0x33,
    // xor x4, x2, x3
    0x00 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b100 << 12 | MOCK_RD << 7 | 0x33,
    // B-Type
    // beq x2, x3, 8
    0x00 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b000 << 12 | 0x08 << 7 | 0x63,
    // bne x2, x3, 8
    0x00 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b001 << 12 | 0x08 << 7 | 0x63,
    // blt x2, x3, -8
    0b_1_111111 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b_100 << 12 | 0b_1100_1 << 7 | 0x63,
    // divu (0x01, 0x05, 0x33)
    0x01 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b101 << 12 | MOCK_RD << 7 | 0x33,
    // srli x4, x2, 3
    0x00 << 25 | MOCK_IMM_3 << 20 | MOCK_RS1 << 15 | 0x05 << 12 | MOCK_RD << 7 | 0x13,
    // srli x4, x2, 31
    0x00 << 25 | MOCK_IMM_31 << 20 | MOCK_RS1 << 15 | 0x05 << 12 | MOCK_RD << 7 | 0x13,
    // sltu (0x00, 0x03, 0x33)
    0x00 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b011 << 12 | MOCK_RD << 7 | 0x33,
    // addi x4, x2, 3
    0x00 << 25 | MOCK_IMM_3 << 20 | MOCK_RS1 << 15 | 0x00 << 12 | MOCK_RD << 7 | 0x13,
    // addi x4, x2, -3, correc this below
    0b_1_111111 << 25 | MOCK_IMM_NEG3 << 20 | MOCK_RS1 << 15 | 0x00 << 12 | MOCK_RD << 7 | 0x13,
    // bltu x2, x3, -8
    0b_1_111111 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b_110 << 12 | 0b_1100_1 << 7 | 0x63,
    // bgeu x2, x3, -8
    0b_1_111111 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b_111 << 12 | 0b_1100_1 << 7 | 0x63,
    // bge x2, x3, -8
    0b_1_111111 << 25 | MOCK_RS2 << 20 | MOCK_RS1 << 15 | 0b_101 << 12 | 0b_1100_1 << 7 | 0x63,
];
// Addresses of particular instructions in the mock program.
pub const MOCK_PC_ADD: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start());
pub const MOCK_PC_SUB: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 4);
pub const MOCK_PC_MUL: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 8);
pub const MOCK_PC_AND: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 12);
pub const MOCK_PC_OR: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 16);
pub const MOCK_PC_XOR: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 20);
pub const MOCK_PC_BEQ: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 24);
pub const MOCK_PC_BNE: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 28);
pub const MOCK_PC_BLT: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 32);
pub const MOCK_PC_DIVU: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 36);
pub const MOCK_PC_SRLI: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 40);
pub const MOCK_PC_SRLI_31: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 44);
pub const MOCK_PC_SLTU: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 48);
pub const MOCK_PC_ADDI: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 52);
pub const MOCK_PC_ADDI_SUB: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 56);
pub const MOCK_PC_BLTU: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 60);
pub const MOCK_PC_BGEU: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 64);
pub const MOCK_PC_BGE: ByteAddr = ByteAddr(CENO_PLATFORM.pc_start() + 68);

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
    pub fn print(&self, wits_in: &[ArcMultilinearExtension<E>], wits_in_name: &[String]) {
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
                let eval_fmt = fmt::field(evaluated);
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
                let left_eval_fmt = fmt::field(left);
                let right_eval_fmt = fmt::field(right);
                println!(
                    "\nAssertEqualError {name:?}\n\
                    Left: {left_eval_fmt} != Right: {right_eval_fmt}\n\
                    Left Expression: {left_expression_fmt}\n\
                    Right Expression: {right_expression_fmt}\n\
                    Inst[{inst_id}]:\n{wtns_fmt}\n",
                );
            }
            Self::LookupError {
                expression,
                evaluated,
                name,
                inst_id,
            } => {
                let expression_fmt = fmt::expr(expression, &mut wtns, false);
                let wtns_fmt = fmt::wtns(&wtns, wits_in, *inst_id, wits_in_name);
                let eval_fmt = fmt::field(evaluated);
                println!(
                    "\nLookupError {name:#?}: Evaluated expression does not exist in T vector\n\
                    Expression: {expression_fmt}\n\
                    Evaluation: {eval_fmt}\n\
                    Inst[{inst_id}]:\n{wtns_fmt}\n",
                );
            }
        }
    }
}

pub(crate) struct MockProver<E: ExtensionField> {
    _phantom: PhantomData<E>,
}

fn load_tables<E: ExtensionField>(cb: &CircuitBuilder<E>, challenge: [E; 2]) -> HashSet<Vec<u64>> {
    fn load_range_table<RANGE: RangeTable, E: ExtensionField>(
        t_vec: &mut Vec<Vec<u64>>,
        cb: &CircuitBuilder<E>,
        challenge: [E; 2],
    ) {
        for i in RANGE::content() {
            let rlc_record =
                cb.rlc_chip_record(vec![(RANGE::ROM_TYPE as usize).into(), (i as usize).into()]);
            let rlc_record = eval_by_expr(&[], &challenge, &rlc_record);
            t_vec.push(rlc_record.to_canonical_u64_vec());
        }
    }

    fn load_op_table<OP: OpsTable, E: ExtensionField>(
        t_vec: &mut Vec<Vec<u64>>,
        cb: &CircuitBuilder<E>,
        challenge: [E; 2],
    ) {
        for [a, b, c] in OP::content() {
            let rlc_record = cb.rlc_chip_record(vec![
                (OP::ROM_TYPE as usize).into(),
                (a as usize).into(),
                (b as usize).into(),
                (c as usize).into(),
            ]);
            let rlc_record = eval_by_expr(&[], &challenge, &rlc_record);
            t_vec.push(rlc_record.to_canonical_u64_vec());
        }
    }

    fn load_program_table<E: ExtensionField>(
        t_vec: &mut Vec<Vec<u64>>,
        _cb: &CircuitBuilder<E>,
        challenge: [E; 2],
    ) {
        let mut cs = ConstraintSystem::<E>::new(|| "mock_program");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config = ProgramTableCircuit::construct_circuit(&mut cb).unwrap();
        let fixed =
            ProgramTableCircuit::<E>::generate_fixed_traces(&config, cs.num_fixed, MOCK_PROGRAM);
        for table_expr in &cs.lk_table_expressions {
            for row in fixed.iter_rows() {
                // TODO: Find a better way to obtain the row content.
                let row = row
                    .iter()
                    .map(|v| unsafe { (*v).assume_init() }.into())
                    .collect::<Vec<_>>();
                let rlc_record = eval_by_expr_with_fixed(&row, &[], &challenge, &table_expr.values);
                t_vec.push(rlc_record.to_canonical_u64_vec());
            }
        }
    }

    let mut table_vec = vec![];
    load_range_table::<U5Table, _>(&mut table_vec, cb, challenge);
    load_range_table::<U8Table, _>(&mut table_vec, cb, challenge);
    load_range_table::<U16Table, _>(&mut table_vec, cb, challenge);
    load_op_table::<AndTable, _>(&mut table_vec, cb, challenge);
    load_op_table::<OrTable, _>(&mut table_vec, cb, challenge);
    load_op_table::<XorTable, _>(&mut table_vec, cb, challenge);
    load_op_table::<LtuTable, _>(&mut table_vec, cb, challenge);
    load_program_table(&mut table_vec, cb, challenge);
    HashSet::from_iter(table_vec)
}

// load once per generic type E instantiation
// return challenge and table
#[allow(clippy::type_complexity)]
fn load_once_tables<E: ExtensionField + 'static + Sync + Send>(
    cb: &CircuitBuilder<E>,
) -> ([E; 2], &'static HashSet<Vec<u64>>) {
    static CACHE: OnceLock<StaticTypeMap<([Vec<u64>; 2], HashSet<Vec<u64>>)>> = OnceLock::new();
    let cache = CACHE.get_or_init(StaticTypeMap::new);

    let (challenges_repr, table) = cache.call_once::<E, _>(|| {
        let mut rng = test_rng();
        let challenge = [E::random(&mut rng), E::random(&mut rng)];
        let base64_encoded =
            STANDARD_NO_PAD.encode(serde_json::to_string(&challenge).unwrap().as_bytes());
        let file_path = format!("table_cache_dev_{:?}.json", base64_encoded);
        // Check if the cache file exists
        let table = match fs::metadata(file_path.clone()) {
            Ok(_) => {
                // if file exist, we deserialize from file to get table
                let file = File::open(file_path).unwrap();
                let reader = BufReader::new(file);
                serde_json::from_reader(reader).unwrap()
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // load new table and seserialize to file for later use
                let table = load_tables(cb, challenge);
                let file = File::create(file_path).unwrap();
                serde_json::to_writer(file, &table).unwrap();
                table
            }
            Err(e) => panic!("{:?}", e),
        };

        (challenge.map(|c| c.to_canonical_u64_vec()), table)
    });
    // reinitialize per generic type E
    (
        challenges_repr.clone().map(|repr| unsafe {
            let ptr = repr.as_slice().as_ptr() as *const E;
            *ptr
        }),
        table,
    )
}

impl<'a, E: ExtensionField + Hash> MockProver<E> {
    pub fn run_with_challenge(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        challenge: [E; 2],
    ) -> Result<(), Vec<MockProverError<E>>> {
        Self::run_maybe_challenge(cb, wits_in, Some(challenge))
    }

    pub fn run(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
    ) -> Result<(), Vec<MockProverError<E>>> {
        Self::run_maybe_challenge(cb, wits_in, None)
    }

    fn run_maybe_challenge(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        challenge: Option<[E; 2]>,
    ) -> Result<(), Vec<MockProverError<E>>> {
        let table = challenge.map(|challenge| load_tables(cb, challenge));
        let (challenge, table) = if let Some(challenge) = challenge {
            (challenge, table.as_ref().unwrap())
        } else {
            load_once_tables(cb)
        };
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
                if !table.contains(&element.to_canonical_u64_vec()) {
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

    pub fn assert_satisfied(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        challenge: Option<[E; 2]>,
    ) {
        let result = if let Some(challenge) = challenge {
            Self::run_with_challenge(cb, wits_in, challenge)
        } else {
            Self::run(cb, wits_in)
        };
        match result {
            Ok(_) => {}
            Err(errors) => {
                println!("======================================================");
                println!("Error: {} constraints not satisfied", errors.len());

                for error in errors {
                    error.print(wits_in, &cb.cs.witin_namespace_map);
                }
                println!("======================================================");
                panic!("Constraints not satisfied");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use super::*;
    use crate::{
        error::ZKVMError,
        expression::{ToExpr, WitIn},
        gadgets::IsLtConfig,
        set_val,
        witness::{LkMultiplicity, RowMajorMatrix},
    };
    use ff::Field;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use multilinear_extensions::mle::{IntoMLE, IntoMLEs};

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

        MockProver::assert_satisfied(&builder, &wits_in, None);
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
        MockProver::assert_satisfied(&builder, &wits_in, Some(challenge));
    }

    #[test]
    // TODO: add it back after the support of missing lookup
    fn test_lookup_error() {
        let mut cs = ConstraintSystem::new(|| "test_lookup_error");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let _ = RangeCheckCircuit::construct_circuit(&mut builder).unwrap();

        let wits_in = vec![vec![Goldilocks::from(123)].into_mle().into()];

        let challenge = [2.into(), 1000.into()];
        let result = MockProver::run_with_challenge(&builder, &wits_in, challenge);
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
        pub lt_wtns: IsLtConfig,
    }

    struct AssertLtCircuitInput {
        pub a: u64,
        pub b: u64,
    }

    impl AssertLtCircuit {
        fn construct_circuit(cb: &mut CircuitBuilder<GoldilocksExt2>) -> Result<Self, ZKVMError> {
            let a = cb.create_witin(|| "a")?;
            let b = cb.create_witin(|| "b")?;
            let lt_wtns = cb.less_than(|| "lt", a.expr(), b.expr(), Some(true), 1)?;
            Ok(Self { a, b, lt_wtns })
        }

        fn assign_instance<E: ExtensionField>(
            &self,
            instance: &mut [MaybeUninit<E::BaseField>],
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
            let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(instances.len(), num_witin);
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

        MockProver::assert_satisfied(
            &builder,
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

        MockProver::assert_satisfied(
            &builder,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            Some([1.into(), 1000.into()]),
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
            let a = cb.create_witin(|| "a")?;
            let b = cb.create_witin(|| "b")?;
            let lt_wtns = cb.less_than(|| "lt", a.expr(), b.expr(), None, 1)?;
            Ok(Self { a, b, lt_wtns })
        }

        fn assign_instance<E: ExtensionField>(
            &self,
            instance: &mut [MaybeUninit<E::BaseField>],
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
            let mut raw_witin = RowMajorMatrix::<E::BaseField>::new(instances.len(), num_witin);
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

        MockProver::assert_satisfied(
            &builder,
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

        MockProver::assert_satisfied(
            &builder,
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
