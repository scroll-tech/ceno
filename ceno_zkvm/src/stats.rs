use crate::{
    circuit_builder::{ConstraintSystem, NameSpace},
    expression::Expression,
    structs::{ZKVMConstraintSystem, ZKVMWitnesses},
};
use ff_ext::ExtensionField;
use itertools::Itertools;
use serde_json::json;
use std::{collections::BTreeMap, fs::File, io::Write};

#[derive(Clone, Debug, serde::Serialize)]
pub struct OpCodeStats {
    namespace: NameSpace,
    witnesses: usize,
    reads: usize,
    writes: usize,
    lookups: usize,
    assert_zero_expr_degrees: Vec<usize>,
    assert_zero_sumcheck_expr_degrees: Vec<usize>,
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

impl CircuitStats {
    pub fn new<E: ExtensionField>(system: &ConstraintSystem<E>) -> Self {
        let just_degrees =
            |exprs: &Vec<Expression<E>>| exprs.iter().map(|e| e.degree()).collect_vec();
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
                assert_zero_expr_degrees: just_degrees(&system.assert_zero_expressions),
                assert_zero_sumcheck_expr_degrees: just_degrees(
                    &system.assert_zero_sumcheck_expressions,
                ),
            })
        } else {
            let table_len = if system.lk_table_expressions.len() > 0 {
                system.lk_table_expressions[0].table_len
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

#[derive(Clone, Debug, serde::Serialize)]
pub struct CircuitStatsTrace {
    static_stats: CircuitStats,
    num_instances: usize,
}

impl CircuitStatsTrace {
    pub fn new(static_stats: CircuitStats, num_instances: usize) -> Self {
        return CircuitStatsTrace {
            static_stats,
            num_instances,
        };
    }
}

pub type TraceReport = Report<CircuitStatsTrace>;

impl Report<CircuitStatsTrace> {
    pub fn new<E: ExtensionField>(
        static_report: &Report<CircuitStats>,
        num_instances: BTreeMap<String, usize>,
        program_name: &str,
    ) -> Self {
        let mut metadata = static_report.metadata.clone();
        // Note where the num_instances are extracted from
        metadata.insert("PROGRAM_NAME".to_owned(), program_name.to_owned());

        // Ensure we recognize all circuits from the num_instances map
        num_instances.keys().for_each(|key| {
            assert!(
                matches!(static_report.get(key), Some(_)),
                r"unrecognized key {key}."
            );
        });

        // Stitch num instances to corresponding entries. Sort by num instances
        let circuits = static_report
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
        Self::new::<E>(static_report, num_instances, program_name)
    }
}
