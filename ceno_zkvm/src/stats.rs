use crate::{
    circuit_builder::{ConstraintSystem, NameSpace},
    expression::Expression,
    structs::{ZKVMConstraintSystem, ZKVMWitnesses},
    utils,
};
use ff_ext::ExtensionField;
use itertools::Itertools;
use prettytable::{Table, row};
use serde_json::json;
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Write,
};
#[derive(Clone, Debug, serde::Serialize, Default)]
pub struct OpCodeStats {
    namespace: NameSpace,
    witnesses: usize,
    reads: usize,
    writes: usize,
    lookups: usize,
    // store degrees as frequency maps
    assert_zero_expr_degrees: HashMap<usize, usize>,
    assert_zero_sumcheck_expr_degrees: HashMap<usize, usize>,
}

impl std::ops::Add for OpCodeStats {
    type Output = OpCodeStats;
    fn add(self, rhs: Self) -> Self::Output {
        OpCodeStats {
            namespace: NameSpace::default(),
            witnesses: self.witnesses + rhs.witnesses,
            reads: self.reads + rhs.reads,
            writes: self.writes + rhs.writes,
            lookups: self.lookups + rhs.lookups,
            assert_zero_expr_degrees: utils::merge_frequency_tables(
                self.assert_zero_expr_degrees,
                rhs.assert_zero_expr_degrees,
            ),
            assert_zero_sumcheck_expr_degrees: utils::merge_frequency_tables(
                self.assert_zero_sumcheck_expr_degrees,
                rhs.assert_zero_sumcheck_expr_degrees,
            ),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TableStats {
    table_len: usize,
}

#[derive(Clone, Debug, serde::Serialize)]
pub enum CircuitStats {
    OpCode(OpCodeStats),
    Table(TableStats),
}

impl Default for CircuitStats {
    fn default() -> Self {
        CircuitStats::OpCode(OpCodeStats::default())
    }
}

// logic to aggregate two circuit stats; ignore tables
impl std::ops::Add for CircuitStats {
    type Output = CircuitStats;
    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (CircuitStats::Table(_), CircuitStats::Table(_)) => {
                CircuitStats::OpCode(OpCodeStats::default())
            }
            (CircuitStats::Table(_), rhs) => rhs,
            (lhs, CircuitStats::Table(_)) => lhs,
            (CircuitStats::OpCode(lhs), CircuitStats::OpCode(rhs)) => {
                CircuitStats::OpCode(lhs + rhs)
            }
        }
    }
}

impl CircuitStats {
    pub fn new<E: ExtensionField>(system: &ConstraintSystem<E>) -> Self {
        let just_degrees_grouped = |exprs: &Vec<Expression<E>>| {
            let mut counter = HashMap::new();
            for expr in exprs {
                *counter.entry(expr.degree()).or_insert(0) += 1;
            }
            counter
        };
        let is_opcode = system.lk_table_expressions.is_empty()
            && system.r_table_expressions.is_empty()
            && system.w_table_expressions.is_empty();
        // distinguishing opcodes from tables as done in ZKVMProver::create_proof
        if is_opcode {
            CircuitStats::OpCode(OpCodeStats {
                namespace: system.ns.clone(),
                witnesses: system.num_witin as usize,
                reads: system.r_expressions.len(),
                writes: system.w_expressions.len(),
                lookups: system.lk_expressions.len(),
                assert_zero_expr_degrees: just_degrees_grouped(&system.assert_zero_expressions),
                assert_zero_sumcheck_expr_degrees: just_degrees_grouped(
                    &system.assert_zero_sumcheck_expressions,
                ),
            })
        } else {
            let table_len = if !system.lk_table_expressions.is_empty() {
                system.lk_table_expressions[0].table_spec.len.unwrap_or(0)
            } else {
                0
            };
            CircuitStats::Table(TableStats { table_len })
        }
    }
}

pub struct Report<INFO> {
    metadata: BTreeMap<String, String>,
    circuits: Vec<(String, INFO)>,
}

impl<INFO> Report<INFO>
where
    INFO: serde::Serialize,
{
    pub fn get(&self, circuit_name: &str) -> Option<&INFO> {
        self.circuits.iter().find_map(|(name, info)| {
            if name == circuit_name {
                Some(info)
            } else {
                None
            }
        })
    }

    pub fn save_json(&self, filename: &str) {
        let json_data = json!({
            "metadata": self.metadata,
            "circuits": self.circuits,
        });

        let mut file = File::create(filename).expect("Unable to create file");
        file.write_all(serde_json::to_string_pretty(&json_data).unwrap().as_bytes())
            .expect("Unable to write data");
    }
}
pub type StaticReport = Report<CircuitStats>;

impl Report<CircuitStats> {
    pub fn new<E: ExtensionField>(zkvm_system: &ZKVMConstraintSystem<E>) -> Self {
        Report {
            metadata: BTreeMap::default(),
            circuits: zkvm_system
                .get_css()
                .iter()
                .map(|(k, v)| (k.clone(), CircuitStats::new(v)))
                .collect_vec(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, Default)]
pub struct CircuitStatsTrace {
    static_stats: CircuitStats,
    num_instances: usize,
}

impl CircuitStatsTrace {
    pub fn new(static_stats: CircuitStats, num_instances: usize) -> Self {
        CircuitStatsTrace {
            static_stats,
            num_instances,
        }
    }
}

pub type TraceReport = Report<CircuitStatsTrace>;

impl Report<CircuitStatsTrace> {
    pub fn new(
        static_report: &Report<CircuitStats>,
        num_instances: BTreeMap<String, usize>,
        program_name: &str,
    ) -> Self {
        let mut metadata = static_report.metadata.clone();
        // Note where the num_instances are extracted from
        metadata.insert("PROGRAM_NAME".to_owned(), program_name.to_owned());

        // Ensure we recognize all circuits from the num_instances map
        num_instances.keys().for_each(|key| {
            assert!(static_report.get(key).is_some(), r"unrecognized key {key}.");
        });

        // Stitch num instances to corresponding entries. Sort by num instances
        let mut circuits = static_report
            .circuits
            .iter()
            .map(|(key, value)| {
                (
                    key.to_owned(),
                    CircuitStatsTrace::new(value.clone(), *num_instances.get(key).unwrap_or(&0)),
                )
            })
            .sorted_by(|lhs, rhs| rhs.1.num_instances.cmp(&lhs.1.num_instances))
            .collect_vec();

        // aggregate results (for opcode circuits only)
        let mut total = CircuitStatsTrace::default();
        for (_, circuit) in &circuits {
            if let CircuitStats::OpCode(_) = &circuit.static_stats {
                total = CircuitStatsTrace {
                    num_instances: total.num_instances + circuit.num_instances,
                    static_stats: total.static_stats + circuit.static_stats.clone(),
                }
            }
        }
        circuits.insert(0, ("OPCODES TOTAL".to_owned(), total));
        Report { metadata, circuits }
    }

    // Extract num_instances from witness data
    pub fn new_via_witnesses<E: ExtensionField>(
        static_report: &Report<CircuitStats>,
        zkvm_witnesses: &ZKVMWitnesses<E>,
        program_name: &str,
    ) -> Self {
        let num_instances = zkvm_witnesses
            .clone()
            .into_iter_sorted()
            .map(|(key, value)| (key, value.num_instances()))
            .collect::<BTreeMap<_, _>>();
        Self::new(static_report, num_instances, program_name)
    }

    pub fn save_table(&self, filename: &str) {
        let mut opcodes_table = Table::new();
        opcodes_table.add_row(row![
            "opcode_name",
            "num_instances",
            "lookups",
            "reads",
            "witnesses",
            "writes",
            "0_expr_deg",
            "0_expr_sumcheck_deg"
        ]);
        let mut tables_table = Table::new();
        tables_table.add_row(row!["table_name", "num_instances", "table_len"]);

        for (name, circuit) in &self.circuits {
            match &circuit.static_stats {
                CircuitStats::OpCode(opstats) => {
                    opcodes_table.add_row(row![
                        name.to_owned(),
                        circuit.num_instances,
                        opstats.lookups,
                        opstats.reads,
                        opstats.witnesses,
                        opstats.writes,
                        utils::display_hashmap(&opstats.assert_zero_expr_degrees),
                        utils::display_hashmap(&opstats.assert_zero_sumcheck_expr_degrees)
                    ]);
                }
                CircuitStats::Table(tablestats) => {
                    tables_table.add_row(row![
                        name.to_owned(),
                        circuit.num_instances,
                        tablestats.table_len
                    ]);
                }
            }
        }
        let mut file = File::create(filename).expect("Unable to create file");
        _ = opcodes_table.print(&mut file);
        _ = tables_table.print(&mut file);
    }
}
