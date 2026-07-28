//! Optional, low-frequency markers for phase-accurate host CPU profiling.
//!
//! Set `CENO_CPU_PROFILE_PHASES=1` to emit paired log records and call the
//! stable marker symbols. The symbols are suitable uprobe targets; normal
//! execution pays only one cached boolean check at each coarse phase boundary.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

static ENABLED: OnceLock<bool> = OnceLock::new();
static PERF_CONTROL: OnceLock<Option<Mutex<File>>> = OnceLock::new();
static PERF_CONTROL_PHASE: OnceLock<String> = OnceLock::new();

pub(crate) fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os("CENO_CPU_PROFILE_PHASES")
            .is_some_and(|value| !matches!(value.to_str(), Some("") | Some("0") | Some("false")))
    })
}

fn perf_control(phase: &str, command: &[u8]) {
    let selected_phase = PERF_CONTROL_PHASE.get_or_init(|| {
        std::env::var("CENO_CPU_PROFILE_CONTROL_PHASE").unwrap_or_else(|_| "aot_execute".to_owned())
    });
    if phase != selected_phase {
        return;
    }
    let control = PERF_CONTROL.get_or_init(|| {
        std::env::var_os("CENO_CPU_PROFILE_CONTROL_FIFO").map(|path| {
            let path = PathBuf::from(path);
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap_or_else(|err| panic!("open perf control FIFO {}: {err}", path.display()));
            Mutex::new(file)
        })
    });
    if let Some(control) = control {
        let mut control = control.lock().expect("perf control FIFO mutex poisoned");
        control
            .write_all(command)
            .expect("write perf control command");
        control.flush().expect("flush perf control command");
    }
}

macro_rules! marker {
    ($name:ident, $id:expr) => {
        #[unsafe(no_mangle)]
        #[inline(never)]
        pub extern "C" fn $name() {
            std::hint::black_box($id);
        }
    };
}

marker!(ceno_cpu_profile_aot_execute_begin, 1u8);
marker!(ceno_cpu_profile_aot_execute_end, 2u8);
marker!(ceno_cpu_profile_fulltracer_replay_begin, 3u8);
marker!(ceno_cpu_profile_fulltracer_replay_end, 4u8);
marker!(ceno_cpu_profile_witness_assignment_begin, 5u8);
marker!(ceno_cpu_profile_witness_assignment_end, 6u8);

/// RAII phase boundary used only for coarse profiling regions.
pub struct CpuProfileGuard {
    name: &'static str,
    started: Instant,
    end_marker: extern "C" fn(),
}

impl CpuProfileGuard {
    fn new(
        name: &'static str,
        begin_marker: extern "C" fn(),
        end_marker: extern "C" fn(),
    ) -> Option<Self> {
        enabled().then(|| {
            begin_marker();
            perf_control(name, b"enable\n");
            tracing::info!(target: "ceno_cpu_profile", phase = name, event = "begin");
            Self {
                name,
                started: Instant::now(),
                end_marker,
            }
        })
    }

    pub fn aot_execute() -> Option<Self> {
        Self::new(
            "aot_execute",
            ceno_cpu_profile_aot_execute_begin,
            ceno_cpu_profile_aot_execute_end,
        )
    }

    pub fn fulltracer_replay() -> Option<Self> {
        Self::new(
            "fulltracer_replay",
            ceno_cpu_profile_fulltracer_replay_begin,
            ceno_cpu_profile_fulltracer_replay_end,
        )
    }

    pub fn witness_assignment() -> Option<Self> {
        Self::new(
            "witness_assignment",
            ceno_cpu_profile_witness_assignment_begin,
            ceno_cpu_profile_witness_assignment_end,
        )
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

impl Drop for CpuProfileGuard {
    fn drop(&mut self) {
        perf_control(self.name, b"disable\n");
        (self.end_marker)();
        tracing::info!(
            target: "ceno_cpu_profile",
            phase = self.name,
            event = "end",
            elapsed = ?self.elapsed(),
        );
    }
}
