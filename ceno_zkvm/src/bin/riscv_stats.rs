use std::{collections::BTreeMap, fs::File, io::Write};

use ceno_zkvm::{
    instructions::riscv::{MmuConfig, Rv32imConfig},
    stats::{StaticReport, TraceReport, degree_audit},
    structs::ZKVMConstraintSystem,
};
use ff_ext::BabyBearExt4;
type E = BabyBearExt4;
fn main() {
    let mut zkvm_cs = ZKVMConstraintSystem::default();

    let _ = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let _ = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    let static_report = StaticReport::new(&zkvm_cs);
    let report = TraceReport::new(&static_report, BTreeMap::new(), "no program");
    report.save_table("riscv_stats.txt");

    let mut degree_audit_file = File::create("riscv_degree_audit.csv").unwrap();
    writeln!(
        degree_audit_file,
        "chip,max_constraint_degree,max_main_sumcheck_degree,cubic_constraints,witness_columns,trace_weighted_witness_cells"
    )
    .unwrap();
    for row in degree_audit(&zkvm_cs, &BTreeMap::new()) {
        writeln!(
            degree_audit_file,
            "{},{},{},{},{},{}",
            row.chip,
            row.max_constraint_degree,
            row.max_main_sumcheck_degree,
            row.cubic_constraints,
            row.witness_columns,
            row.trace_weighted_witness_cells,
        )
        .unwrap();
    }
    println!("INFO: generated riscv_stats.txt and riscv_degree_audit.csv");
}
