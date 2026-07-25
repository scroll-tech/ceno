use crate::InsnKind;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct GuestFunctionSymbol {
    pub start: u32,
    pub end: u32,
    pub name: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GuestFunctionProfileEntry {
    pub rank: usize,
    pub function: String,
    pub pc_start: u32,
    pub pc_end: u32,
    pub instructions: u64,
    pub estimated_cells: u64,
    pub percent_instructions: f64,
    pub percent_cells: f64,
    pub ecall_steps: u64,
    pub top_opcodes: Vec<(String, u64)>,
    pub suspected_crypto: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GuestFunctionProfileReport {
    pub total_non_ecall_instructions: u64,
    pub total_estimated_cells: u64,
    pub total_ecall_steps: u64,
    pub top_functions: Vec<GuestFunctionProfileEntry>,
}

#[derive(Clone, Debug, Default)]
struct GuestFunctionCounters {
    instructions: u64,
    estimated_cells: u64,
    ecall_steps: u64,
    opcodes: BTreeMap<String, u64>,
}

#[derive(Clone, Debug)]
pub struct GuestFunctionProfiler {
    symbols: Vec<GuestFunctionSymbol>,
    counters: Vec<GuestFunctionCounters>,
    unknown: GuestFunctionCounters,
    last_symbol_index: Option<usize>,
}

impl GuestFunctionProfiler {
    pub fn new(symbols: Vec<GuestFunctionSymbol>) -> Self {
        let counters = vec![GuestFunctionCounters::default(); symbols.len()];
        Self {
            symbols,
            counters,
            unknown: GuestFunctionCounters::default(),
            last_symbol_index: None,
        }
    }

    #[inline(always)]
    pub fn observe(&mut self, pc: u32, kind: InsnKind, estimated_cells: u64) {
        let counters = match self.symbol_index(pc) {
            Some(idx) => &mut self.counters[idx],
            None => &mut self.unknown,
        };

        if matches!(kind, InsnKind::ECALL) {
            counters.ecall_steps += 1;
            return;
        }

        counters.instructions += 1;
        counters.estimated_cells += estimated_cells;
        *counters.opcodes.entry(kind.to_string()).or_default() += 1;
    }

    pub fn report(&self, top_n: usize) -> GuestFunctionProfileReport {
        let total_non_ecall_instructions = self
            .counters
            .iter()
            .map(|counters| counters.instructions)
            .sum::<u64>()
            + self.unknown.instructions;
        let total_estimated_cells = self
            .counters
            .iter()
            .map(|counters| counters.estimated_cells)
            .sum::<u64>()
            + self.unknown.estimated_cells;
        let total_ecall_steps = self
            .counters
            .iter()
            .map(|counters| counters.ecall_steps)
            .sum::<u64>()
            + self.unknown.ecall_steps;

        let mut entries = self
            .symbols
            .iter()
            .zip(&self.counters)
            .map(|(symbol, counters)| {
                self.entry(
                    symbol.name.clone(),
                    symbol.start,
                    symbol.end,
                    counters,
                    total_non_ecall_instructions,
                    total_estimated_cells,
                )
            })
            .collect::<Vec<_>>();

        if self.unknown.instructions > 0 || self.unknown.ecall_steps > 0 {
            entries.push(self.entry(
                "<unknown>".to_string(),
                0,
                0,
                &self.unknown,
                total_non_ecall_instructions,
                total_estimated_cells,
            ));
        }

        entries.sort_by(|a, b| {
            b.estimated_cells
                .cmp(&a.estimated_cells)
                .then_with(|| b.instructions.cmp(&a.instructions))
        });
        entries.truncate(top_n);
        for (idx, entry) in entries.iter_mut().enumerate() {
            entry.rank = idx + 1;
        }

        GuestFunctionProfileReport {
            total_non_ecall_instructions,
            total_estimated_cells,
            total_ecall_steps,
            top_functions: entries,
        }
    }

    pub fn write_reports(&self, path: &Path, top_n: usize) -> std::io::Result<()> {
        let report = self.report(top_n);
        let (json_path, md_path) = report_paths(path);
        if let Some(parent) = json_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_vec_pretty(&report).map_err(std::io::Error::other)?;
        std::fs::write(&json_path, json)?;
        std::fs::write(&md_path, render_markdown(&report))?;
        tracing::info!(
            "wrote guest function profile to {} and {}",
            json_path.display(),
            md_path.display()
        );
        Ok(())
    }

    #[inline(always)]
    fn symbol_index(&mut self, pc: u32) -> Option<usize> {
        if let Some(idx) = self.last_symbol_index {
            let symbol = &self.symbols[idx];
            if symbol.start <= pc && pc < symbol.end {
                return Some(idx);
            }
        }

        let idx = self
            .symbols
            .partition_point(|symbol| symbol.start <= pc)
            .checked_sub(1)?;
        let symbol = &self.symbols[idx];
        if pc < symbol.end {
            self.last_symbol_index = Some(idx);
            Some(idx)
        } else {
            self.last_symbol_index = None;
            None
        }
    }

    fn entry(
        &self,
        function: String,
        pc_start: u32,
        pc_end: u32,
        counters: &GuestFunctionCounters,
        total_instructions: u64,
        total_cells: u64,
    ) -> GuestFunctionProfileEntry {
        let mut top_opcodes = counters
            .opcodes
            .iter()
            .map(|(kind, count)| (kind.clone(), *count))
            .collect::<Vec<_>>();
        top_opcodes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top_opcodes.truncate(8);

        GuestFunctionProfileEntry {
            rank: 0,
            suspected_crypto: suspected_crypto(&function),
            function,
            pc_start,
            pc_end,
            instructions: counters.instructions,
            estimated_cells: counters.estimated_cells,
            percent_instructions: percent(counters.instructions, total_instructions),
            percent_cells: percent(counters.estimated_cells, total_cells),
            ecall_steps: counters.ecall_steps,
            top_opcodes,
        }
    }
}

fn percent(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

fn report_paths(path: &Path) -> (PathBuf, PathBuf) {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("md") => (path.with_extension("json"), path.to_path_buf()),
        Some("json") => (path.to_path_buf(), path.with_extension("md")),
        _ => (path.with_extension("json"), path.with_extension("md")),
    }
}

fn suspected_crypto(function: &str) -> Option<String> {
    let lower = function.to_ascii_lowercase();
    for (needle, label) in [
        ("keccak", "keccak"),
        ("sha", "sha"),
        ("secp256k1", "secp256k1"),
        ("secp256r1", "secp256r1"),
        ("bn254", "bn254"),
        ("bls", "bls"),
        ("modexp", "modexp"),
        ("mulmod", "mulmod"),
        ("uint256", "uint256"),
        ("hash", "hash"),
        ("trie", "trie"),
        ("rlp", "rlp"),
    ] {
        if lower.contains(needle) {
            return Some(label.to_string());
        }
    }
    None
}

fn render_markdown(report: &GuestFunctionProfileReport) -> String {
    let mut out = String::new();
    out.push_str("# Guest Function Profile\n\n");
    out.push_str(&format!(
        "- total non-ecall instructions: {}\n- total estimated cells: {}\n- total ecall steps: {}\n\n",
        report.total_non_ecall_instructions,
        report.total_estimated_cells,
        report.total_ecall_steps
    ));
    out.push_str("| rank | function | instructions | cells | inst % | cell % | ecall steps | top opcodes | tag |\n");
    out.push_str("| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |\n");
    for entry in &report.top_functions {
        let opcodes = entry
            .top_opcodes
            .iter()
            .map(|(kind, count)| format!("{kind}:{count}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "| {} | `{}` | {} | {} | {:.2} | {:.2} | {} | {} | {} |\n",
            entry.rank,
            entry.function.replace('|', "\\|"),
            entry.instructions,
            entry.estimated_cells,
            entry.percent_instructions,
            entry.percent_cells,
            entry.ecall_steps,
            opcodes,
            entry.suspected_crypto.as_deref().unwrap_or("")
        ));
    }
    out
}
