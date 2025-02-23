use super::{
    PublicValues,
    utils::{eval_by_expr, wit_infer_by_expr},
};
use crate::{
    ROMType,
    circuit_builder::{CircuitBuilder, ConstraintSystem},
    expression::{Expression, fmt},
    scheme::utils::{eval_by_expr_with_fixed, eval_by_expr_with_instance},
    state::{GlobalState, StateCircuit},
    structs::{ProgramParams, RAMType, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        AndTable, LtuTable, OpsTable, OrTable, PowTable, ProgramTableCircuit, RangeTable,
        TableCircuit, U5Table, U8Table, U14Table, U16Table, XorTable,
    },
    witness::{LkMultiplicity, LkMultiplicityRaw, RowMajorMatrix},
};
use ark_std::test_rng;
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ceno_emul::{ByteAddr, CENO_PLATFORM, Platform, Program};
use ff::Field;
use ff_ext::ExtensionField;
use generic_static::StaticTypeMap;
use goldilocks::{GoldilocksExt2, SmallField};
use itertools::{Itertools, chain, enumerate, izip};
use multilinear_extensions::{mle::IntoMLEs, virtual_poly::ArcMultilinearExtension};
use rand::thread_rng;
use std::{
    cmp::max,
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Debug,
    fs::File,
    hash::Hash,
    io::{BufReader, ErrorKind},
    marker::PhantomData,
    sync::OnceLock,
};
use strum::IntoEnumIterator;

const MAX_CONSTRAINT_DEGREE: usize = 2;
const MOCK_PROGRAM_SIZE: usize = 32;
pub const MOCK_PC_START: ByteAddr = ByteAddr({
    // This needs to be a static, because otherwise the compiler complains
    // that 'the destructor for [Platform] cannot be evaluated in constants'
    // The `static` keyword means that we keep exactly one copy of the variable
    // around per process, and never deallocate it.  Thus never having to call
    // the destructor.
    //
    // At least conceptually.  In practice with anything beyond -O0, the optimizer
    // will inline and fold constants and replace `MOCK_PC_START` with
    // a simple number.
    static CENO_PLATFORM: Platform = ceno_emul::CENO_PLATFORM;
    CENO_PLATFORM.pc_base()
});

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

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum MockProverError<E: ExtensionField, K: LkMultiplicityKey> {
    AssertZeroError {
        expression: Expression<E>,
        evaluated: E::BaseField,
        name: String,
        inst_id: usize,
    },
    AssertEqualError {
        left_expression: Expression<E>,
        right_expression: Expression<E>,
        left: E::BaseField,
        right: E::BaseField,
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
    // TODO later
    // r_expressions
    // w_expressions
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
                let eval_fmt = fmt::base_field(evaluated, false);
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
                let left_eval_fmt = fmt::base_field(left, false);
                let right_eval_fmt = fmt::base_field(right, false);
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
                let eval_fmt = fmt::field(evaluated);
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
                        ROMType::U5 | ROMType::U8 | ROMType::U14 | ROMType::U16 => {
                            format!("Element: {key:?}")
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
    fn load_range_table<RANGE: RangeTable, E: ExtensionField>(
        t_vec: &mut Vec<Vec<u64>>,
        cs: &ConstraintSystem<E>,
        challenge: [E; 2],
    ) {
        for i in RANGE::content() {
            let rlc_record =
                cs.rlc_chip_record(vec![(RANGE::ROM_TYPE as usize).into(), (i as usize).into()]);
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
    load_range_table::<U5Table, _>(&mut table_vec, cs, challenge);
    load_range_table::<U8Table, _>(&mut table_vec, cs, challenge);
    load_range_table::<U14Table, _>(&mut table_vec, cs, challenge);
    load_range_table::<U16Table, _>(&mut table_vec, cs, challenge);
    load_op_table::<AndTable, _>(&mut table_vec, cs, challenge);
    load_op_table::<OrTable, _>(&mut table_vec, cs, challenge);
    load_op_table::<XorTable, _>(&mut table_vec, cs, challenge);
    load_op_table::<LtuTable, _>(&mut table_vec, cs, challenge);
    load_op_table::<PowTable, _>(&mut table_vec, cs, challenge);

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
        let mut rng = test_rng();
        let challenge = [E::random(&mut rng), E::random(&mut rng)];
        let base64_encoded =
            STANDARD_NO_PAD.encode(serde_json::to_string(&challenge).unwrap().as_bytes());
        let file_path = format!("table_cache_dev_{:?}.json", base64_encoded);
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

        (challenge.map(|c| c.to_canonical_u64_vec()), table)
    });
    // reinitialize per generic type E
    (
        challenges_repr.clone().map(|repr| unsafe {
            let ptr = repr.as_slice().as_ptr() as *const E;
            *ptr
        }),
        table.clone(),
    )
}

impl<'a, E: ExtensionField + Hash> MockProver<E> {
    pub fn run_with_challenge(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        challenge: [E; 2],
        lkm: Option<LkMultiplicity>,
    ) -> Result<(), Vec<MockProverError<E, u64>>> {
        Self::run_maybe_challenge(cb, wits_in, &[], &[], Some(challenge), lkm)
    }

    pub fn run(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        program: &[ceno_emul::Instruction],
        lkm: Option<LkMultiplicity>,
    ) -> Result<(), Vec<MockProverError<E, u64>>> {
        Self::run_maybe_challenge(cb, wits_in, program, &[], None, lkm)
    }

    fn run_maybe_challenge(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        program: &[ceno_emul::Instruction],
        pi: &[ArcMultilinearExtension<'a, E>],
        challenge: Option<[E; 2]>,
        lkm: Option<LkMultiplicity>,
    ) -> Result<(), Vec<MockProverError<E, u64>>> {
        let program = Program::from(program);
        let (table, challenge) = Self::load_tables_with_program(cb.cs, &program, challenge);

        Self::run_maybe_challenge_with_table(cb.cs, &table, wits_in, pi, 1, challenge, lkm)
            .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    fn run_maybe_challenge_with_table(
        cs: &ConstraintSystem<E>,
        table: &HashSet<Vec<u64>>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        pi: &[ArcMultilinearExtension<'a, E>],
        num_instances: usize,
        challenge: [E; 2],
        expected_lkm: Option<LkMultiplicity>,
    ) -> Result<LkMultiplicityRaw<E>, Vec<MockProverError<E, u64>>> {
        let mut shared_lkm = LkMultiplicityRaw::<E>::default();
        let mut errors = vec![];

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

            // require_equal does not always have the form of Expr::Sum as
            // the sum of witness and constant is expressed as scaled sum
            if let Expression::Sum(left, right) = expr
                && name.contains("require_equal")
            {
                let right = -right.as_ref();

                let left_evaluated = wit_infer_by_expr(&[], wits_in, &[], pi, &challenge, left);
                let left_evaluated = left_evaluated.get_base_field_vec();

                let right_evaluated = wit_infer_by_expr(&[], wits_in, &[], pi, &challenge, &right);
                let right_evaluated = right_evaluated.get_base_field_vec();

                // left_evaluated.len() ?= right_evaluated.len() due to padding instance
                for (inst_id, (left_element, right_element)) in
                    izip!(left_evaluated, right_evaluated).enumerate()
                {
                    if left_element != right_element {
                        errors.push(MockProverError::AssertEqualError {
                            left_expression: *left.clone(),
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
                let expr_evaluated = wit_infer_by_expr(&[], wits_in, &[], pi, &challenge, expr);
                let expr_evaluated = expr_evaluated.get_base_field_vec();

                for (inst_id, element) in enumerate(expr_evaluated) {
                    if *element != E::BaseField::ZERO {
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
        for ((expr, name), (rom_type, _)) in cs
            .lk_expressions
            .iter()
            .zip_eq(cs.lk_expressions_namespace_map.iter())
            .zip_eq(cs.lk_expressions_items_map.iter())
        {
            let expr_evaluated = wit_infer_by_expr(&[], wits_in, &[], pi, &challenge, expr);
            let expr_evaluated = &expr_evaluated.get_ext_field_vec()[..num_instances];

            // Check each lookup expr exists in t vec
            for (inst_id, element) in enumerate(expr_evaluated) {
                if !table.contains(&element.to_canonical_u64_vec()) {
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
                shared_lkm.increment(*rom_type, *element);
            }
        }

        // LK Multiplicity check
        if let Some(lkm_from_assignment) = expected_lkm {
            // Infer LK Multiplicity from constraint system.
            let mut lkm_from_cs = LkMultiplicity::default();
            for (rom_type, args) in &cs.lk_expressions_items_map {
                let args_eval: Vec<_> = args
                    .iter()
                    .map(|arg_expr| {
                        let arg_eval =
                            wit_infer_by_expr(&[], wits_in, &[], pi, &challenge, arg_expr);
                        let mut arg_eval = arg_eval
                            .get_base_field_vec()
                            .iter()
                            .map(SmallField::to_canonical_u64)
                            .take(num_instances)
                            .collect_vec();

                        // Constant terms will have single element in `args_expr_evaluated`, so let's fix that.
                        if arg_expr.is_constant() {
                            assert_eq!(arg_eval.len(), 1);
                            arg_eval.resize(num_instances, arg_eval[0])
                        }
                        arg_eval
                    })
                    .collect();

                // Count lookups infered from ConstraintSystem from all instances into lkm_from_cs.
                for inst_id in 0..num_instances {
                    match rom_type {
                        ROMType::U5 => lkm_from_cs.assert_ux::<5>(args_eval[0][inst_id]),
                        ROMType::U8 => lkm_from_cs.assert_ux::<8>(args_eval[0][inst_id]),
                        ROMType::U14 => lkm_from_cs.assert_ux::<14>(args_eval[0][inst_id]),
                        ROMType::U16 => lkm_from_cs.assert_ux::<16>(args_eval[0][inst_id]),
                        ROMType::And => lkm_from_cs
                            .lookup_and_byte(args_eval[0][inst_id], args_eval[1][inst_id]),
                        ROMType::Or => {
                            lkm_from_cs.lookup_or_byte(args_eval[0][inst_id], args_eval[1][inst_id])
                        }
                        ROMType::Xor => lkm_from_cs
                            .lookup_xor_byte(args_eval[0][inst_id], args_eval[1][inst_id]),
                        ROMType::Ltu => lkm_from_cs
                            .lookup_ltu_byte(args_eval[0][inst_id], args_eval[1][inst_id]),
                        ROMType::Pow => {
                            assert_eq!(args_eval[0][inst_id], 2);
                            lkm_from_cs.lookup_pow2(args_eval[1][inst_id])
                        }
                        ROMType::Instruction => lkm_from_cs.fetch(args_eval[0][inst_id] as u32),
                    };
                }
            }

            errors.extend(compare_lkm(lkm_from_cs, lkm_from_assignment));
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
        let mut cb = CircuitBuilder::new_with_params(&mut cs, ProgramParams {
            platform: CENO_PLATFORM,
            program_size: max(program.instructions.len(), MOCK_PROGRAM_SIZE),
            ..ProgramParams::default()
        });
        let config = ProgramTableCircuit::<_>::construct_circuit(&mut cb).unwrap();
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

    /// Run and check errors
    ///
    /// Panic, unless we see exactly the expected errors.
    /// (Expecting no errors is a valid expectation.)
    pub fn assert_with_expected_errors(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        program: &[ceno_emul::Instruction],
        constraint_names: &[&str],
        challenge: Option<[E; 2]>,
        lkm: Option<LkMultiplicity>,
    ) {
        let error_groups = if let Some(challenge) = challenge {
            Self::run_with_challenge(cb, wits_in, challenge, lkm)
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
        raw_witin: RowMajorMatrix<E::BaseField>,
        program: &[ceno_emul::Instruction],
        challenge: Option<[E; 2]>,
        lkm: Option<LkMultiplicity>,
    ) {
        let wits_in = raw_witin
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec();
        Self::assert_satisfied(cb, &wits_in, program, challenge, lkm);
    }

    pub fn assert_satisfied(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        program: &[ceno_emul::Instruction],
        challenge: Option<[E; 2]>,
        lkm: Option<LkMultiplicity>,
    ) {
        Self::assert_with_expected_errors(cb, wits_in, program, &[], challenge, lkm);
    }

    pub fn assert_satisfied_full(
        cs: &ZKVMConstraintSystem<E>,
        mut fixed_trace: ZKVMFixedTraces<E>,
        witnesses: &ZKVMWitnesses<E>,
        pi: &PublicValues<u32>,
        program: &Program,
    ) where
        E: LkMultiplicityKey,
    {
        let instance = pi
            .to_vec::<E>()
            .concat()
            .into_iter()
            .map(|i| E::from(i))
            .collect_vec();
        let pi_mles = pi
            .to_vec::<E>()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec();
        let mut rng = thread_rng();
        let challenges = [0u8; 2].map(|_| E::random(&mut rng));

        // Load lookup table.
        let (lookup_table, _) = Self::load_tables_with_program(
            &ConstraintSystem::<E>::new(|| "temp for loading table"),
            program,
            Some(challenges),
        );

        let mut wit_mles = HashMap::new();
        let mut structural_wit_mles = HashMap::new();
        let mut fixed_mles = HashMap::new();
        let mut num_instances = HashMap::new();

        let mut lkm_tables = LkMultiplicityRaw::<E>::default();
        let mut lkm_opcodes = LkMultiplicityRaw::<E>::default();

        // Process all circuits.
        for (circuit_name, cs) in &cs.circuit_css {
            let is_opcode = cs.lk_table_expressions.is_empty()
                && cs.r_table_expressions.is_empty()
                && cs.w_table_expressions.is_empty();
            let witness = if is_opcode {
                witnesses
                    .get_opcode_witness(circuit_name)
                    .unwrap_or_else(|| panic!("witness for {} should not be None", circuit_name))
            } else {
                witnesses
                    .get_table_witness(circuit_name)
                    .unwrap_or_else(|| panic!("witness for {} should not be None", circuit_name))
            };
            let num_rows = witness.num_instances();

            if witness.num_instances() == 0 {
                wit_mles.insert(circuit_name.clone(), vec![]);
                structural_wit_mles.insert(circuit_name.clone(), vec![]);
                fixed_mles.insert(circuit_name.clone(), vec![]);
                num_instances.insert(circuit_name.clone(), num_rows);
                continue;
            }
            let mut witness = witness
                .into_mles()
                .into_iter()
                .map(|w| w.into())
                .collect_vec();
            let structural_witness = witness.split_off(cs.num_witin as usize);
            let fixed: Vec<_> = fixed_trace
                .circuit_fixed_traces
                .remove(circuit_name)
                .and_then(|fixed| fixed)
                .map_or(vec![], |fixed| {
                    fixed
                        .into_mles()
                        .into_iter()
                        .map(|f| f.into())
                        .collect_vec()
                });
            if is_opcode {
                tracing::info!(
                    "Mock proving opcode {} with {} entries",
                    circuit_name,
                    num_rows
                );
                // Assert opcode and check single opcode lk multiplicity
                // Also combine multiplicity in lkm_opcodes
                let lkm_from_assignments = witnesses
                    .get_lk_mlt(circuit_name)
                    .map(LkMultiplicityRaw::deep_clone);
                match Self::run_maybe_challenge_with_table(
                    cs,
                    &lookup_table,
                    &witness,
                    &[],
                    num_rows,
                    challenges,
                    lkm_from_assignments,
                ) {
                    Ok(multiplicities) => {
                        lkm_opcodes += multiplicities;
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
                for (expr, (rom_type, _)) in
                    izip!(&cs.lk_table_expressions, &cs.lk_expressions_items_map)
                {
                    let lk_table = wit_infer_by_expr(
                        &fixed,
                        &witness,
                        &structural_witness,
                        &pi_mles,
                        &challenges,
                        &expr.values,
                    )
                    .get_ext_field_vec()
                    .to_vec();

                    let multiplicity = wit_infer_by_expr(
                        &fixed,
                        &witness,
                        &structural_witness,
                        &pi_mles,
                        &challenges,
                        &expr.multiplicity,
                    )
                    .get_base_field_vec()
                    .to_vec();

                    for (key, multiplicity) in izip!(lk_table, multiplicity) {
                        lkm_tables.set_count(
                            *rom_type,
                            key,
                            multiplicity.to_canonical_u64() as usize,
                        );
                    }
                }
            }
            wit_mles.insert(circuit_name.clone(), witness);
            structural_wit_mles.insert(circuit_name.clone(), structural_witness);
            fixed_mles.insert(circuit_name.clone(), fixed);
            num_instances.insert(circuit_name.clone(), num_rows);
        }

        // Assert lkm between all tables and combined opcode circuits
        let errors: Vec<MockProverError<E, E>> = compare_lkm(lkm_tables, lkm_opcodes);

        if errors.is_empty() {
            tracing::info!("Mock proving successful for tables");
        } else {
            tracing::error!("Mock proving failed for tables - {} errors", errors.len());
            print_errors(&errors, &[], &[], true);
        }

        // find out r != w errors
        let mut num_rw_mismatch_errors = 0;

        macro_rules! derive_ram_rws {
            ($ram_type:expr) => {{
                let mut writes = HashSet::new();
                let mut writes_grp_by_annotations = HashMap::new();
                // store (pc, timestamp) for $ram_type == RAMType::GlobalState
                let mut gs = HashMap::new();
                for (circuit_name, cs) in &cs.circuit_css {
                    let fixed = fixed_mles.get(circuit_name).unwrap();
                    let witness = wit_mles.get(circuit_name).unwrap();
                    let num_rows = num_instances.get(circuit_name).unwrap();
                    if *num_rows == 0 {
                        continue;
                    }
                    for ((w_rlc_expr, annotation), (_, w_exprs)) in (cs
                        .w_expressions
                        .iter()
                        .chain(cs.w_table_expressions.iter().map(|expr| &expr.expr)))
                    .zip_eq(
                        cs.w_expressions_namespace_map
                            .iter()
                            .chain(cs.w_table_expressions_namespace_map.iter()),
                    )
                    .zip_eq(cs.w_ram_types.iter())
                    .filter(|((_, _), (ram_type, _))| *ram_type == $ram_type)
                    {
                        let write_rlc_records = (wit_infer_by_expr(
                            fixed,
                            witness,
                            &[],
                            &pi_mles,
                            &challenges,
                            w_rlc_expr,
                        )
                        .get_ext_field_vec())[..*num_rows]
                            .to_vec();

                        if $ram_type == RAMType::GlobalState {
                            // w_exprs = [GlobalState, pc, timestamp]
                            assert_eq!(w_exprs.len(), 3);
                            let w = w_exprs
                                .into_iter()
                                .skip(1)
                                .map(|expr| {
                                    let v = wit_infer_by_expr(
                                        fixed,
                                        witness,
                                        &[],
                                        &pi_mles,
                                        &challenges,
                                        expr,
                                    );
                                    v.get_base_field_vec()[..*num_rows].to_vec()
                                })
                                .collect_vec();
                            // convert [[pc], [timestamp]] into [[pc, timestamp]]
                            let w = (0..*num_rows)
                                // TODO: use transpose
                                .map(|row| w.iter().map(|w| w[row]).collect_vec())
                                .collect_vec();

                            assert!(gs.insert(circuit_name.clone(), w).is_none());
                        };
                        let mut records = vec![];
                        for (row, record_rlc) in enumerate(write_rlc_records) {
                            // TODO: report error
                            assert_eq!(writes.insert(record_rlc), true);
                            records.push((record_rlc, row));
                        }
                        writes_grp_by_annotations
                            .insert(annotation.clone(), (records, circuit_name.clone()));
                    }
                }

                let mut reads = HashSet::new();
                let mut reads_grp_by_annotations = HashMap::new();
                for (circuit_name, cs) in &cs.circuit_css {
                    let fixed = fixed_mles.get(circuit_name).unwrap();
                    let witness = wit_mles.get(circuit_name).unwrap();
                    let num_rows = num_instances.get(circuit_name).unwrap();
                    if *num_rows == 0 {
                        continue;
                    }
                    for ((r_expr, annotation), _) in (cs
                        .r_expressions
                        .iter()
                        .chain(cs.r_table_expressions.iter().map(|expr| &expr.expr)))
                    .zip_eq(
                        cs.r_expressions_namespace_map
                            .iter()
                            .chain(cs.r_table_expressions_namespace_map.iter()),
                    )
                    .zip_eq(cs.r_ram_types.iter())
                    .filter(|((_, _), (ram_type, _))| *ram_type == $ram_type)
                    {
                        let read_records =
                            wit_infer_by_expr(fixed, witness, &[], &pi_mles, &challenges, r_expr)
                                .get_ext_field_vec()[..*num_rows]
                                .to_vec();
                        let mut records = vec![];
                        for (row, record) in enumerate(read_records) {
                            // TODO: return error
                            assert_eq!(reads.insert(record), true);
                            records.push((record, row));
                        }
                        reads_grp_by_annotations
                            .insert(annotation.clone(), (records, circuit_name.clone()));
                    }
                }

                (
                    reads,
                    reads_grp_by_annotations,
                    writes,
                    writes_grp_by_annotations,
                    gs,
                )
            }};
        }
        macro_rules! find_rw_mismatch {
            ($reads:ident,$reads_grp_by_annotations:ident,$writes:ident,$writes_grp_by_annotations:ident,$ram_type:expr,$gs:expr) => {
                for (annotation, (reads, circuit_name)) in &$reads_grp_by_annotations {
                    // (pc, timestamp)
                    let gs_of_circuit = $gs.get(circuit_name);
                    let num_missing = reads
                        .iter()
                        .filter(|(read, _)| !$writes.contains(read))
                        .count();
                    let num_reads = reads.len();
                    reads
                        .iter()
                        .filter(|(read, _)| !$writes.contains(read))
                        .take(10)
                        .for_each(|(_, row)| {
                            let pc = gs_of_circuit.map_or(0, |gs| gs[*row][0].to_canonical_u64());
                            let ts = gs_of_circuit.map_or(0, |gs| gs[*row][1].to_canonical_u64());
                            tracing::error!(
                                "{} at row {} (pc={:x},ts={}) not found in {:?} writes",
                                annotation,
                                row,
                                pc,
                                ts,
                                $ram_type,
                            )
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
                for (annotation, (writes, circuit_name)) in &$writes_grp_by_annotations {
                    let gs_of_circuit = $gs.get(circuit_name);
                    let num_missing = writes
                        .iter()
                        .filter(|(write, _)| !$reads.contains(write))
                        .count();
                    let num_writes = writes.len();
                    writes
                        .iter()
                        .filter(|(write, _)| !$reads.contains(write))
                        .take(10)
                        .for_each(|(_, row)| {
                            let pc = gs_of_circuit.map_or(0, |gs| gs[*row][0].to_canonical_u64());
                            let ts = gs_of_circuit.map_or(0, |gs| gs[*row][1].to_canonical_u64());
                            tracing::error!(
                                "{} at row {} (pc={:x},ts={}) not found in {:?} reads",
                                annotation,
                                row,
                                pc,
                                ts,
                                $ram_type,
                            )
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
            };
        }
        // part1 global state
        let mut cs = ConstraintSystem::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);
        let gs_init = GlobalState::initial_global_state(&mut cb).unwrap();
        let gs_final = GlobalState::finalize_global_state(&mut cb).unwrap();

        let (mut gs_rs, rs_grp_by_anno, mut gs_ws, ws_grp_by_anno, gs) =
            derive_ram_rws!(RAMType::GlobalState);
        gs_rs.insert(eval_by_expr_with_instance(
            &[],
            &[],
            &[],
            &instance,
            &challenges,
            &gs_final,
        ));
        gs_ws.insert(eval_by_expr_with_instance(
            &[],
            &[],
            &[],
            &instance,
            &challenges,
            &gs_init,
        ));

        // gs stores { (pc, timestamp) }
        find_rw_mismatch!(
            gs_rs,
            rs_grp_by_anno,
            gs_ws,
            ws_grp_by_anno,
            RAMType::GlobalState,
            gs
        );

        // part2 registers
        let (reg_rs, rs_grp_by_anno, reg_ws, ws_grp_by_anno, _) =
            derive_ram_rws!(RAMType::Register);
        find_rw_mismatch!(
            reg_rs,
            rs_grp_by_anno,
            reg_ws,
            ws_grp_by_anno,
            RAMType::Register,
            gs
        );

        // part3 memory
        let (mem_rs, rs_grp_by_anno, mem_ws, ws_grp_by_anno, _) = derive_ram_rws!(RAMType::Memory);
        find_rw_mismatch!(
            mem_rs,
            rs_grp_by_anno,
            mem_ws,
            ws_grp_by_anno,
            RAMType::Memory,
            gs
        );

        if num_rw_mismatch_errors > 0 {
            panic!("found {} r/w mismatch errors", num_rw_mismatch_errors);
        }
    }
}

fn compare_lkm<E, K>(
    lkm_a: LkMultiplicityRaw<K>,
    lkm_b: LkMultiplicityRaw<K>,
) -> Vec<MockProverError<E, K>>
where
    E: ExtensionField,
    K: LkMultiplicityKey + Default + Ord,
{
    let lkm_a = lkm_a.into_finalize_result();
    let lkm_b = lkm_b.into_finalize_result();

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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        ROMType::U5,
        error::ZKVMError,
        expression::{ToExpr, WitIn},
        gadgets::{AssertLtConfig, IsLtConfig},
        instructions::InstancePaddingStrategy,
        set_val,
        witness::{LkMultiplicity, RowMajorMatrix},
    };
    use ff::Field;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use multilinear_extensions::mle::IntoMLE;

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

        MockProver::assert_satisfied(&builder, &wits_in, &[], None, None);
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
            vec![Goldilocks::from(3u64), Goldilocks::from(5u64)]
                .into_mle()
                .into(),
        ];

        let challenge = [1.into(), 1000.into()];
        MockProver::assert_satisfied(&builder, &wits_in, &[], Some(challenge), None);
    }

    #[test]
    // TODO: add it back after the support of missing lookup
    fn test_lookup_error() {
        let mut cs = ConstraintSystem::new(|| "test_lookup_error");
        let mut builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);

        let _ = RangeCheckCircuit::construct_circuit(&mut builder).unwrap();

        let wits_in = vec![vec![Goldilocks::from(123)].into_mle().into()];

        let challenge = [2.into(), 1000.into()];
        let result = MockProver::run_with_challenge(&builder, &wits_in, challenge, None);
        assert!(result.is_err(), "Expected error");
        let err = result.unwrap_err();
        assert_eq!(err, vec![MockProverError::LookupError {
            rom_type: ROMType::U5,
            expression: Expression::Sum(
                Box::new(Expression::ScaledSum(
                    Box::new(Expression::WitIn(0)),
                    Box::new(Expression::Challenge(
                        1,
                        1,
                        GoldilocksExt2::ONE,
                        GoldilocksExt2::ZERO,
                    )),
                    Box::new(Expression::Constant(Goldilocks::from(U5 as u64))),
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
        }]);
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
                vec![AssertLtCircuitInput { a: 3, b: 5 }, AssertLtCircuitInput {
                    a: 7,
                    b: 11,
                }],
                &mut lk_multiplicity,
            )
            .unwrap();

        MockProver::assert_satisfied_raw(
            &builder,
            raw_witin,
            &[],
            Some([1.into(), 1000.into()]),
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
            raw_witin,
            &[],
            Some([1.into(), 1000.into()]),
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
                vec![LtCircuitInput { a: 3, b: 5 }, LtCircuitInput {
                    a: 7,
                    b: 11,
                }],
                &mut lk_multiplicity,
            )
            .unwrap();

        MockProver::assert_satisfied_raw(
            &builder,
            raw_witin,
            &[],
            Some([1.into(), 1000.into()]),
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
            raw_witin,
            &[],
            Some([1.into(), 1000.into()]),
            None,
        );
    }
}
