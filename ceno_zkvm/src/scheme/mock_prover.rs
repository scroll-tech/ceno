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
    structs::{RAMType, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        AndTable, LtuTable, OpsTable, OrTable, PowTable, ProgramTableCircuit, RangeTable,
        TableCircuit, U5Table, U8Table, U14Table, U16Table, XorTable,
    },
    witness::{LkMultiplicity, RowMajorMatrix},
};
use ark_std::test_rng;
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ceno_emul::{ByteAddr, CENO_PLATFORM, PC_WORD_SIZE, Program};
use ff::Field;
use ff_ext::ExtensionField;
use generic_static::StaticTypeMap;
use goldilocks::SmallField;
use itertools::{Itertools, izip};
use multilinear_extensions::{mle::IntoMLEs, virtual_poly_v2::ArcMultilinearExtension};
use rand::thread_rng;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    hash::Hash,
    io::{BufReader, ErrorKind},
    marker::PhantomData,
    ops::Neg,
    sync::OnceLock,
};
use strum::IntoEnumIterator;

const MAX_CONSTRAINT_DEGREE: usize = 2;
const MOCK_PROGRAM_SIZE: usize = 32;
pub const MOCK_PC_START: ByteAddr = ByteAddr(CENO_PLATFORM.pc_base());

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum MockProverError<E: ExtensionField> {
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
        key: u64,
        count: isize, // +ve => missing in cs, -ve => missing in assignments
        inst_id: usize,
    },
}

impl<E: ExtensionField> PartialEq for MockProverError<E> {
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
            _ => false,
        }
    }
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
                let location = if *count > 0 {
                    "constraint system"
                } else {
                    "assignments"
                };
                let element = match rom_type {
                    ROMType::U5 | ROMType::U8 | ROMType::U14 | ROMType::U16 => {
                        format!("Element: {key}")
                    }
                    ROMType::And => {
                        let (a, b) = AndTable::unpack(*key);
                        format!("Element: {a} < {b}")
                    }
                    ROMType::Or => {
                        let (a, b) = OrTable::unpack(*key);
                        format!("Element: {a} || {b}")
                    }
                    ROMType::Xor => {
                        let (a, b) = XorTable::unpack(*key);
                        format!("Element: {a} ^ {b}")
                    }
                    ROMType::Ltu => {
                        let (a, b) = LtuTable::unpack(*key);
                        format!("Element: {a} < {b}")
                    }
                    ROMType::Pow => {
                        let (a, b) = PowTable::unpack(*key);
                        format!("Element: {a} ** {b}")
                    }
                    ROMType::Instruction => format!("PC: {key}"),
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
            | Self::LookupError { inst_id, .. }
            | Self::LkMultiplicityError { inst_id, .. } => *inst_id,
            Self::DegreeTooHigh { .. } => unreachable!(),
        }
    }

    fn contains(&self, constraint_name: &str) -> bool {
        format!("{:?}", self).contains(constraint_name)
    }
}

pub struct MockProver<E: ExtensionField> {
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

    let mut table_vec = vec![];
    load_range_table::<U5Table, _>(&mut table_vec, cb, challenge);
    load_range_table::<U8Table, _>(&mut table_vec, cb, challenge);
    load_range_table::<U14Table, _>(&mut table_vec, cb, challenge);
    load_range_table::<U16Table, _>(&mut table_vec, cb, challenge);
    load_op_table::<AndTable, _>(&mut table_vec, cb, challenge);
    load_op_table::<OrTable, _>(&mut table_vec, cb, challenge);
    load_op_table::<XorTable, _>(&mut table_vec, cb, challenge);
    load_op_table::<LtuTable, _>(&mut table_vec, cb, challenge);
    load_op_table::<PowTable, _>(&mut table_vec, cb, challenge);

    HashSet::from_iter(table_vec)
}

// load once per generic type E instantiation
// return challenge and table
#[allow(clippy::type_complexity)]
fn load_once_tables<E: ExtensionField + 'static + Sync + Send>(
    cb: &CircuitBuilder<E>,
) -> ([E; 2], HashSet<Vec<u64>>) {
    static CACHE: OnceLock<StaticTypeMap<([Vec<u64>; 2], HashSet<Vec<u64>>)>> = OnceLock::new();
    let cache = CACHE.get_or_init(StaticTypeMap::new);

    let (challenges_repr, table) = cache.call_once::<E, _>(|| {
        let mut rng = test_rng();
        let challenge = [E::random(&mut rng), E::random(&mut rng)];
        let base64_encoded =
            STANDARD_NO_PAD.encode(serde_json::to_string(&challenge).unwrap().as_bytes());
        let file_path = format!("table_cache_dev_{:?}.json", base64_encoded);
        let table = match File::open(file_path.clone()) {
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
                let table = load_tables(cb, challenge);
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
    ) -> Result<(), Vec<MockProverError<E>>> {
        Self::run_maybe_challenge(cb, wits_in, &[], &[], Some(challenge), lkm)
    }

    pub fn run(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        programs: &[u32],
        lkm: Option<LkMultiplicity>,
    ) -> Result<(), Vec<MockProverError<E>>> {
        Self::run_maybe_challenge(cb, wits_in, programs, &[], None, lkm)
    }

    fn run_maybe_challenge(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        input_programs: &[u32],
        pi: &[ArcMultilinearExtension<'a, E>],
        challenge: Option<[E; 2]>,
        lkm: Option<LkMultiplicity>,
    ) -> Result<(), Vec<MockProverError<E>>> {
        // fix the program table
        let instructions = input_programs
            .iter()
            .cloned()
            .chain(std::iter::repeat(0))
            .take(MOCK_PROGRAM_SIZE)
            .collect_vec();
        let image = instructions
            .iter()
            .enumerate()
            .map(|(insn_idx, &insn)| {
                (
                    CENO_PLATFORM.pc_base() + (insn_idx * PC_WORD_SIZE) as u32,
                    insn,
                )
            })
            .collect::<BTreeMap<u32, u32>>();
        let program = Program::new(
            CENO_PLATFORM.pc_base(),
            CENO_PLATFORM.pc_base(),
            instructions,
            image,
        );

        // load tables
        let (challenge, mut table) = if let Some(challenge) = challenge {
            (challenge, load_tables(cb, challenge))
        } else {
            load_once_tables(cb)
        };
        let mut prog_table = vec![];
        Self::load_program_table(&mut prog_table, &program, challenge);
        for prog in prog_table {
            table.insert(prog);
        }

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
            if expr.degree() > MAX_CONSTRAINT_DEGREE {
                errors.push(MockProverError::DegreeTooHigh {
                    expression: expr.clone(),
                    degree: expr.degree(),
                    name: name.clone(),
                });
            }

            // require_equal does not always have the form of Expr::Sum as
            // the sum of witness and constant is expressed as scaled sum
            if name.contains("require_equal") && expr.unpack_sum().is_some() {
                let (left, right) = expr.unpack_sum().unwrap();
                let right = right.neg();

                let left_evaluated = wit_infer_by_expr(&[], wits_in, pi, &challenge, &left);
                let left_evaluated = left_evaluated.get_base_field_vec();

                let right_evaluated = wit_infer_by_expr(&[], wits_in, pi, &challenge, &right);
                let right_evaluated = right_evaluated.get_base_field_vec();

                // left_evaluated.len() ?= right_evaluated.len() due to padding instance
                for (inst_id, (left_element, right_element)) in
                    izip!(left_evaluated, right_evaluated).enumerate()
                {
                    if left_element != right_element {
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
                let expr_evaluated = wit_infer_by_expr(&[], wits_in, pi, &challenge, expr);
                let expr_evaluated = expr_evaluated.get_base_field_vec();

                for (inst_id, element) in expr_evaluated.iter().enumerate() {
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
        for (expr, name) in cb
            .cs
            .lk_expressions
            .iter()
            .zip_eq(cb.cs.lk_expressions_namespace_map.iter())
        {
            let expr_evaluated = wit_infer_by_expr(&[], wits_in, pi, &challenge, expr);
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

        // LK Multiplicity check
        if let Some(lkm_from_assignment) = lkm {
            // Infer LK Multiplicity from constraint system.
            let lkm_from_cs = cb
                .cs
                .lk_expressions_items_map
                .iter()
                .map(|(rom_type, items)| {
                    (
                        rom_type,
                        items
                            .iter()
                            .map(|expr| {
                                // TODO generalized to all inst_id
                                let inst_id = 0;
                                wit_infer_by_expr(&[], wits_in, pi, &challenge, expr)
                                    .get_base_field_vec()[inst_id]
                                    .to_canonical_u64()
                            })
                            .collect::<Vec<u64>>(),
                    )
                })
                .fold(LkMultiplicity::default(), |mut lkm, (rom_type, args)| {
                    match rom_type {
                        ROMType::U5 => lkm.assert_ux::<5>(args[0]),
                        ROMType::U8 => lkm.assert_ux::<8>(args[0]),
                        ROMType::U14 => lkm.assert_ux::<14>(args[0]),
                        ROMType::U16 => lkm.assert_ux::<16>(args[0]),
                        ROMType::And => lkm.lookup_and_byte(args[0], args[1]),
                        ROMType::Or => lkm.lookup_or_byte(args[0], args[1]),
                        ROMType::Xor => lkm.lookup_xor_byte(args[0], args[1]),
                        ROMType::Ltu => lkm.lookup_ltu_byte(args[0], args[1]),
                        ROMType::Pow => {
                            assert_eq!(args[0], 2);
                            lkm.lookup_pow2(args[1])
                        }
                        ROMType::Instruction => lkm.fetch(args[0] as u32),
                    };

                    lkm
                });

            let lkm_from_cs = lkm_from_cs.into_finalize_result();
            let lkm_from_assignment = lkm_from_assignment.into_finalize_result();

            // Compare each LK Multiplicity.

            for (rom_type, cs_map, ass_map) in
                izip!(ROMType::iter(), &lkm_from_cs, &lkm_from_assignment)
            {
                if *cs_map != *ass_map {
                    let cs_keys: HashSet<_> = cs_map.keys().collect();
                    let ass_keys: HashSet<_> = ass_map.keys().collect();

                    // lookup missing in lkm Constraint System.
                    ass_keys.difference(&cs_keys).for_each(|k| {
                        let count_ass = ass_map.get(k).unwrap();
                        errors.push(MockProverError::LkMultiplicityError {
                            rom_type,
                            key: **k,
                            count: *count_ass as isize,
                            inst_id: 0,
                        })
                    });

                    // lookup missing in lkm Assignments.
                    cs_keys.difference(&ass_keys).for_each(|k| {
                        let count_cs = cs_map.get(k).unwrap();
                        errors.push(MockProverError::LkMultiplicityError {
                            rom_type,
                            key: **k,
                            count: -(*count_cs as isize),
                            inst_id: 0,
                        })
                    });

                    // count of specific lookup differ lkm assignments and lkm cs
                    cs_keys.intersection(&ass_keys).for_each(|k| {
                        let count_cs = cs_map.get(k).unwrap();
                        let count_ass = ass_map.get(k).unwrap();

                        if count_cs != count_ass {
                            errors.push(MockProverError::LkMultiplicityError {
                                rom_type,
                                key: **k,
                                count: (*count_ass as isize) - (*count_cs as isize),
                                inst_id: 0,
                            })
                        }
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

    fn load_program_table(t_vec: &mut Vec<Vec<u64>>, program: &Program, challenge: [E; 2]) {
        let mut cs = ConstraintSystem::<E>::new(|| "mock_program");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            ProgramTableCircuit::<_, MOCK_PROGRAM_SIZE>::construct_circuit(&mut cb).unwrap();
        let fixed = ProgramTableCircuit::<E, MOCK_PROGRAM_SIZE>::generate_fixed_traces(
            &config,
            cs.num_fixed,
            program,
        );
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

    /// Run and check errors
    ///
    /// Panic, unless we see exactly the expected errors.
    /// (Expecting no errors is a valid expectation.)
    pub fn assert_with_expected_errors(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        programs: &[u32],
        constraint_names: &[&str],
        challenge: Option<[E; 2]>,
        lkm: Option<LkMultiplicity>,
    ) {
        let error_groups = if let Some(challenge) = challenge {
            Self::run_with_challenge(cb, wits_in, challenge, lkm)
        } else {
            Self::run(cb, wits_in, programs, lkm)
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

            for (count, error) in errors.iter().dedup_with_count() {
                error.print(wits_in, &cb.cs.witin_namespace_map);
                if count > 1 {
                    println!("Error: {} duplicates hidden.", count - 1);
                }
            }
            println!("Error: {} constraints not satisfied", errors.len());
            println!("======================================================");
            panic!("(Unexpected) Constraints not satisfied");
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
        programs: &[u32],
        challenge: Option<[E; 2]>,
        lkm: Option<LkMultiplicity>,
    ) {
        let wits_in = raw_witin
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec();
        Self::assert_satisfied(cb, &wits_in, programs, challenge, lkm);
    }

    pub fn assert_satisfied(
        cb: &CircuitBuilder<E>,
        wits_in: &[ArcMultilinearExtension<'a, E>],
        programs: &[u32],
        challenge: Option<[E; 2]>,
        lkm: Option<LkMultiplicity>,
    ) {
        Self::assert_with_expected_errors(cb, wits_in, programs, &[], challenge, lkm);
    }

    pub fn assert_satisfied_full(
        cs: ZKVMConstraintSystem<E>,
        mut fixed_trace: ZKVMFixedTraces<E>,
        witnesses: &ZKVMWitnesses<E>,
        pi: &PublicValues<u32>,
    ) {
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

        let mut wit_mles = HashMap::new();
        let mut fixed_mles = HashMap::new();
        let mut num_instances = HashMap::new();
        // Lookup errors
        let mut rom_inputs =
            HashMap::<ROMType, Vec<(Vec<E>, String, String, Vec<Expression<E>>)>>::new();
        let mut rom_tables = HashMap::<ROMType, HashMap<E, E::BaseField>>::new();
        for (circuit_name, cs) in cs.circuit_css.iter() {
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
                fixed_mles.insert(circuit_name.clone(), vec![]);
                num_instances.insert(circuit_name.clone(), num_rows);
                continue;
            }
            let witness = witness
                .into_mles()
                .into_iter()
                .map(|w| w.into())
                .collect_vec();
            let fixed: Vec<_> = fixed_trace
                .circuit_fixed_traces
                .remove(circuit_name)
                .and_then(|fixed| fixed)
                // .expect(format!("circuit {}'s fixed traces should not be None", circuit_name).as_str())
                .map_or(vec![], |fixed| {
                    fixed
                        .into_mles()
                        .into_iter()
                        .map(|f| f.into())
                        .collect_vec()
                });
            if is_opcode {
                tracing::info!(
                    "preprocessing opcode {} with {} entries",
                    circuit_name,
                    num_rows
                );
                // gather lookup inputs
                for ((expr, annotation), (rom_type, values)) in cs
                    .lk_expressions
                    .iter()
                    .zip(cs.lk_expressions_namespace_map.clone().into_iter())
                    .zip(cs.lk_expressions_items_map.clone().into_iter())
                {
                    let lk_input =
                        (wit_infer_by_expr(&fixed, &witness, &pi_mles, &challenges, expr)
                            .get_ext_field_vec())[..num_rows]
                            .to_vec();
                    rom_inputs.entry(rom_type).or_default().push((
                        lk_input,
                        circuit_name.clone(),
                        annotation,
                        values,
                    ));
                }
            } else {
                tracing::info!(
                    "preprocessing table {} with {} entries",
                    circuit_name,
                    num_rows
                );
                // gather lookup tables
                for (expr, (rom_type, _)) in cs
                    .lk_table_expressions
                    .iter()
                    .zip(cs.lk_expressions_items_map.clone().into_iter())
                {
                    let lk_table =
                        wit_infer_by_expr(&fixed, &witness, &pi_mles, &challenges, &expr.values)
                            .get_ext_field_vec()
                            .to_vec();

                    let multiplicity = wit_infer_by_expr(
                        &fixed,
                        &witness,
                        &pi_mles,
                        &challenges,
                        &expr.multiplicity,
                    )
                    .get_base_field_vec()
                    .to_vec();

                    assert!(
                        rom_tables
                            .insert(
                                rom_type,
                                lk_table
                                    .into_iter()
                                    .zip(multiplicity.into_iter())
                                    .collect::<HashMap<_, _>>(),
                            )
                            .is_none(),
                        "cannot assign to rom table {:?} twice",
                        rom_type
                    );
                }
            }
            wit_mles.insert(circuit_name.clone(), witness);
            fixed_mles.insert(circuit_name.clone(), fixed);
            num_instances.insert(circuit_name.clone(), num_rows);
        }

        for (rom_type, inputs) in rom_inputs.into_iter() {
            let table = rom_tables.get_mut(&rom_type).unwrap();
            for (lk_input_values, circuit_name, lk_input_annotation, input_value_exprs) in inputs {
                // counting multiplicity in rom_input
                let mut lk_input_values_multiplicity = HashMap::new();
                for (row, input_value) in lk_input_values.iter().enumerate() {
                    // we only keep first row to restore debug information
                    lk_input_values_multiplicity
                        .entry(input_value)
                        .or_insert([0u64, row as u64])[0] += 1;
                }

                for (k, [input_multiplicity, row]) in lk_input_values_multiplicity {
                    let table_multiplicity = if let Some(table_multiplicity) = table.get_mut(k) {
                        if input_multiplicity <= table_multiplicity.to_canonical_u64() {
                            *table_multiplicity -= E::BaseField::from(input_multiplicity);
                            continue;
                        }
                        table_multiplicity.to_canonical_u64()
                    } else {
                        0
                    };
                    // log mismatch error
                    let witness = wit_mles
                        .get(&circuit_name)
                        .map(|mles| {
                            mles.iter()
                                .map(|mle| E::from(mle.get_base_field_vec()[row as usize]))
                                .collect_vec()
                        })
                        .unwrap();
                    let values = input_value_exprs
                        .iter()
                        .map(|expr| {
                            eval_by_expr_with_instance(
                                &[],
                                &witness,
                                &instance,
                                challenges.as_slice(),
                                expr,
                            )
                            .as_bases()[0]
                        })
                        .collect_vec();
                    tracing::error!(
                        "{}: value {:x?} mismatch lk_multiplicity: real {:x} > remaining {:x} in {:?} table",
                        lk_input_annotation,
                        values,
                        input_multiplicity,
                        table_multiplicity,
                        rom_type,
                    );
                }
            }
            // each table entry's multiplicity should equal to 0
            for (k, multiplicity) in table {
                if !multiplicity.is_zero_vartime() {
                    tracing::error!(
                        "table {:?}: {:x?} multiplicity = {:x}",
                        rom_type,
                        k,
                        multiplicity.to_canonical_u64()
                    );
                }
            }
        }

        // find out r != w errors
        let mut num_rw_mismatch_errors = 0;

        macro_rules! derive_ram_rws {
            ($ram_type:expr) => {{
                let mut writes = HashSet::new();
                let mut writes_grp_by_annotations = HashMap::new();
                // store (pc, timestamp) for $ram_type == RAMType::GlobalState
                let mut gs = HashMap::new();
                for (circuit_name, cs) in cs.circuit_css.iter() {
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
                    .zip(
                        cs.w_expressions_namespace_map
                            .iter()
                            .chain(cs.w_table_expressions_namespace_map.iter()),
                    )
                    .zip(cs.w_ram_types.iter())
                    .filter(|((_, _), (ram_type, _))| *ram_type == $ram_type)
                    {
                        let write_rlc_records =
                            (wit_infer_by_expr(fixed, witness, &pi_mles, &challenges, w_rlc_expr)
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
                        for (row, record_rlc) in write_rlc_records.into_iter().enumerate() {
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
                for (circuit_name, cs) in cs.circuit_css.iter() {
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
                    .zip(
                        cs.r_expressions_namespace_map
                            .iter()
                            .chain(cs.r_table_expressions_namespace_map.iter()),
                    )
                    .zip(cs.r_ram_types.iter())
                    .filter(|((_, _), (ram_type, _))| *ram_type == $ram_type)
                    {
                        let read_records =
                            wit_infer_by_expr(fixed, witness, &pi_mles, &challenges, r_expr)
                                .get_ext_field_vec()[..*num_rows]
                                .to_vec();
                        let mut records = vec![];
                        for (row, record) in read_records.into_iter().enumerate() {
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
                for (annotation, (reads, circuit_name)) in $reads_grp_by_annotations.iter() {
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
                for (annotation, (writes, circuit_name)) in $writes_grp_by_annotations.iter() {
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
            &instance,
            &challenges,
            &gs_final,
        ));
        gs_ws.insert(eval_by_expr_with_instance(
            &[],
            &[],
            &instance,
            &challenges,
            &gs_init,
        ));

        // gs stores { (pc, timestamp) }
        let gs_clone = gs.clone();
        find_rw_mismatch!(
            gs_rs,
            rs_grp_by_anno,
            gs_ws,
            ws_grp_by_anno,
            RAMType::GlobalState,
            gs_clone
        );

        // part2 registers
        let (reg_rs, rs_grp_by_anno, reg_ws, ws_grp_by_anno, _) =
            derive_ram_rws!(RAMType::Register);
        let gs_clone = gs.clone();
        find_rw_mismatch!(
            reg_rs,
            rs_grp_by_anno,
            reg_ws,
            ws_grp_by_anno,
            RAMType::Register,
            gs_clone
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

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use super::*;
    use crate::{
        ROMType::U5,
        error::ZKVMError,
        expression::{ToExpr, WitIn},
        gadgets::{AssertLTConfig, IsLtConfig},
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
            expression: Expression::Sum(
                Box::new(Expression::ScaledSum(
                    Box::new(Expression::WitIn(0)),
                    Box::new(Expression::Challenge(
                        1,
                        1,
                        GoldilocksExt2::ONE,
                        GoldilocksExt2::ZERO,
                    )),
                    Box::new(Expression::Constant(
                        <GoldilocksExt2 as ff_ext::ExtensionField>::BaseField::from(U5 as u64)
                    )),
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
        pub lt_wtns: AssertLTConfig,
    }

    struct AssertLtCircuitInput {
        pub a: u64,
        pub b: u64,
    }

    impl AssertLtCircuit {
        fn construct_circuit(cb: &mut CircuitBuilder<GoldilocksExt2>) -> Result<Self, ZKVMError> {
            let a = cb.create_witin(|| "a");
            let b = cb.create_witin(|| "b");
            let lt_wtns = AssertLTConfig::construct_circuit(cb, || "lt", a.expr(), b.expr(), 1)?;
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
