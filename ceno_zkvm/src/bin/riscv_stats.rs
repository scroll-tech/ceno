use std::collections::BTreeMap;

use ceno_zkvm::{
    instructions::riscv::Rv32imConfig,
    stats::{StaticReport, TraceReport},
    structs::ZKVMConstraintSystem,
};
use goldilocks::GoldilocksExt2;
type E = GoldilocksExt2;
fn main() {
    let mut zkvm_cs = ZKVMConstraintSystem::default();

    let _ = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let static_report = StaticReport::new(&zkvm_cs);
    let report = TraceReport::new(&static_report, BTreeMap::new(), "no program");
    report.save_table("riscv_stats.txt");
    println!("INFO: generated riscv_stats.txt");
}
