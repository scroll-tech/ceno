//! Memory-aware parallel chip proof scheduler.
//!
//! This module implements a greedy backfilling algorithm for scheduling chip proofs
//! on the GPU with preemptive memory reservation. The scheduler:
//!
//! 1. Sorts tasks by memory requirement descending (big rocks first)
//! 2. Tries to fit the largest task first; if it doesn't fit, skips and tries smaller
//! 3. Blocks only when nothing fits and waits for a running task to complete
//!
//! This approach eliminates long-tail latency by prioritizing large tasks and
//! maximizes GPU utilization through backfilling with smaller tasks.

use crate::{
    error::ZKVMError,
    scheme::{
        ZKVMChipProof,
        hal::{MainConstraintJob, MainSumcheckEvals, ProofInput},
    },
    structs::ProvingKey,
};
use ff_ext::ExtensionField;
use gkr_iop::hal::ProverBackend;
use mpcs::Point;
use std::sync::OnceLock;
#[cfg(feature = "gpu")]
use std::time::Instant;
use transcript::Transcript;
static CHIP_PROVING_MODE: OnceLock<ChipSchedulerMode> = OnceLock::new();

#[cfg(feature = "gpu")]
const DEFAULT_CHIP_PROVING_LANES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChipProvingMode {
    Sequential,
    Concurrent,
}

pub fn get_chip_proving_mode() -> ChipProvingMode {
    match get_chip_scheduler_mode() {
        ChipSchedulerMode::Sequential => ChipProvingMode::Sequential,
        ChipSchedulerMode::Lanes => ChipProvingMode::Concurrent,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ChipSchedulerMode {
    Sequential,
    Lanes,
}

fn get_chip_scheduler_mode() -> ChipSchedulerMode {
    *CHIP_PROVING_MODE.get_or_init(|| {
        parse_chip_proving_mode(std::env::var("CENO_CHIP_PROVING_MODE").ok().as_deref())
    })
}

fn parse_chip_proving_mode(mode: Option<&str>) -> ChipSchedulerMode {
    match mode {
        Some("sequential") => ChipSchedulerMode::Sequential,
        Some("lanes") => ChipSchedulerMode::Lanes,
        Some(mode) => {
            panic!("invalid CENO_CHIP_PROVING_MODE={mode:?}; expected sequential or lanes")
        }
        None => ChipSchedulerMode::Lanes,
    }
}

#[cfg(feature = "gpu")]
fn parse_chip_proving_lanes(value: Option<&str>) -> Result<usize, String> {
    let value = match value {
        Some(value) => value,
        None => return Ok(DEFAULT_CHIP_PROVING_LANES),
    };
    let lanes = value.parse::<usize>().map_err(|_| {
        format!("invalid CENO_CHIP_PROVING_LANES={value:?}; expected an integer from 1 through 8")
    })?;
    if !(1..=8).contains(&lanes) {
        return Err(format!(
            "invalid CENO_CHIP_PROVING_LANES={value:?}; expected an integer from 1 through 8"
        ));
    }
    Ok(lanes)
}

#[cfg(feature = "gpu")]
fn configured_chip_proving_lanes() -> usize {
    parse_chip_proving_lanes(std::env::var("CENO_CHIP_PROVING_LANES").ok().as_deref())
        .unwrap_or_else(|message| panic!("{message}"))
}

#[cfg(feature = "gpu")]
fn validate_unique_stream_id(stream_ids: &[u64], stream_id: u64) -> Result<(), String> {
    if stream_ids.contains(&stream_id) {
        Err(format!(
            "CUDA stream ID {stream_id} was assigned to multiple lanes"
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "gpu")]
use gkr_iop::{error::BackendError, gpu::gpu_prover::*};
#[cfg(feature = "gpu")]
use std::sync::{Arc, Mutex, mpsc};

/// A chip proving task with its memory requirement
pub struct ChipTask<'a, PB: ProverBackend> {
    /// Unique task identifier (for result ordering)
    pub task_id: usize,
    /// Circuit name for debugging/logging
    pub circuit_name: String,
    /// Index in the circuit_pks map
    pub circuit_idx: usize,
    /// Reference to the proving key
    pub pk: &'a ProvingKey<PB::E>,
    /// Proof input data
    pub input: ProofInput<'static, PB>,
    /// Estimated GPU memory requirement in bytes
    pub estimated_memory_bytes: u64,
    /// Scheduler-only booked GPU memory in bytes (may include extra concurrency margin)
    pub booked_memory_bytes: u64,
    /// Whether this circuit has witness or fixed polynomials
    pub has_witness_or_fixed: bool,
    /// Challenges for this proof
    pub challenges: [PB::E; 2],
    /// Deferred witness extraction: trace index in pcs_data (None if num_witin == 0)
    pub witness_trace_idx: Option<usize>,
    /// Actual witness trace rows used for cache-none extraction estimates.
    #[cfg(feature = "gpu")]
    pub witness_trace_rows: Option<usize>,
    /// Expected number of witness polynomials for this circuit
    pub num_witin: usize,
    /// CPU-side structural witness RowMajorMatrix, transported to GPU on-demand
    pub structural_rmm: Option<witness::RowMajorMatrix<<PB::E as ExtensionField>::BaseField>>,
}

/// Result from a completed chip proof task
pub struct ChipTaskResult<'a, PB: ProverBackend> {
    /// Task ID for ordering
    pub task_id: usize,
    /// Circuit index for proof collection
    pub circuit_idx: usize,
    /// The generated proof
    pub proof: ZKVMChipProof<PB::E>,
    /// Prover-only opening evaluations split by witness/fixed/pi domains.
    pub opening_evals: MainSumcheckEvals<PB::E>,
    /// Opening point for this proof
    pub input_opening_point: Point<PB::E>,
    /// Deferred main-constraint proving job.
    pub main_constraint_job: Option<MainConstraintJob<'a, PB>>,
    /// Whether this circuit has witness or fixed polynomials
    pub has_witness_or_fixed: bool,
}

/// Message sent from worker to scheduler on task completion
#[cfg(feature = "gpu")]
struct CompletionMessage<'a, PB: ProverBackend> {
    /// The result of the proof
    result: Result<ChipTaskResult<'a, PB>, ZKVMError>,
    /// Memory that was reserved for this task (to release)
    memory_reserved: u64,
    /// Task ID for ordering
    task_id: usize,
    /// Circuit name for telemetry
    circuit_name: String,
    /// Sampled value from the forked transcript (for gather phase)
    forked_sample: PB::E,
    lane_id: usize,
    stream_id: Option<u64>,
    queue_delay_ms: f64,
    host_execution_ms: f64,
    event_wait_ms: f64,
    completion_ms: f64,
}

#[cfg(feature = "gpu")]
struct ScheduledTask<'a, PB: ProverBackend> {
    task: ChipTask<'a, PB>,
    queued_at: Instant,
}

#[cfg(feature = "gpu")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchedulerWaitReason {
    WorkerLimit,
    MemoryLimit,
    CompletionDrain,
}

#[cfg(feature = "gpu")]
fn scheduler_wait_reason(tasks_inflight: usize, worker_limit: usize) -> SchedulerWaitReason {
    if tasks_inflight >= worker_limit {
        SchedulerWaitReason::WorkerLimit
    } else {
        SchedulerWaitReason::MemoryLimit
    }
}

/// Memory-aware parallel chip proof scheduler
#[derive(Default)]
pub struct ChipScheduler;

impl ChipScheduler {
    /// Create a new scheduler
    pub fn new() -> Self {
        Self
    }

    /// Unified entry point for chip proof execution.
    ///
    /// On GPU: uses four memory-aware CUDA lanes by default. Set
    /// `CENO_CHIP_PROVING_MODE=sequential` for the control path or `lanes` to
    /// select the bounded lane scheduler explicitly.
    /// `CENO_CHIP_PROVING_LANES` selects 1 through 8 lanes and defaults to 4.
    /// On CPU: always executes sequentially.
    ///
    /// Handles transcript forking internally. Returns `(results, forked_samples)`
    /// both sorted by task_id.
    #[allow(clippy::type_complexity)]
    pub fn execute<'a, PB, T, F>(
        &self,
        tasks: Vec<ChipTask<'a, PB>>,
        transcript: &T,
        execute_task: F,
    ) -> Result<(Vec<ChipTaskResult<'a, PB>>, Vec<PB::E>), ZKVMError>
    where
        PB: ProverBackend + 'static,
        PB::E: Send + 'static,
        T: Transcript<PB::E> + Clone,
        F: Fn(ChipTask<'a, PB>, &mut T) -> Result<ChipTaskResult<'a, PB>, ZKVMError> + Send + Sync,
    {
        #[cfg(feature = "gpu")]
        {
            match get_chip_scheduler_mode() {
                ChipSchedulerMode::Lanes => {
                    // Resolve benchmark configuration before touching the CUDA stream pool.
                    let lane_count = configured_chip_proving_lanes();
                    tracing::info!("[scheduler] resolved CENO_CHIP_PROVING_LANES={lane_count}");
                    return self.execute_concurrently(tasks, transcript, execute_task, lane_count);
                }
                ChipSchedulerMode::Sequential => {}
            }
            tracing::info!("[scheduler] using sequential chip proving");
        }
        self.execute_sequentially(tasks, transcript, execute_task)
    }

    /// Check if concurrent mode is enabled (GPU only).
    #[cfg(feature = "gpu")]
    pub(crate) fn is_concurrent_mode() -> bool {
        get_chip_scheduler_mode() == ChipSchedulerMode::Lanes
    }

    /// Execute tasks sequentially with automatic transcript forking and sampling.
    ///
    /// Each task gets a transcript cloned from `parent_transcript`.
    /// Task-specific transcript appends are performed by the task closure.
    /// Returns `(results, forked_samples)` both sorted by task_id.
    #[allow(clippy::type_complexity)]
    pub(crate) fn execute_sequentially<'a, PB, T, F>(
        &self,
        tasks: Vec<ChipTask<'a, PB>>,
        parent_transcript: &T,
        execute_task: F,
    ) -> Result<(Vec<ChipTaskResult<'a, PB>>, Vec<PB::E>), ZKVMError>
    where
        PB: ProverBackend + 'static,
        PB::E: Send + 'static,
        T: Transcript<PB::E> + Clone,
        F: Fn(ChipTask<'a, PB>, &mut T) -> Result<ChipTaskResult<'a, PB>, ZKVMError>,
    {
        if tasks.is_empty() {
            return Ok((vec![], vec![]));
        }

        for task in &tasks {
            tracing::debug!(
                "[scheduler] Task {} ({}): {}MB",
                task.task_id,
                task.circuit_name,
                task.estimated_memory_bytes / (1024 * 1024)
            );
        }

        let mut results = Vec::with_capacity(tasks.len());
        let mut samples: Vec<(usize, PB::E)> = Vec::with_capacity(tasks.len());

        for task in tasks {
            let task_id = task.task_id;
            // Fork: clone parent transcript template.
            let mut forked = parent_transcript.clone();

            let result = execute_task(task, &mut forked)?;
            results.push(result);

            // Sample from forked transcript
            samples.push((task_id, forked.sample_vec(1)[0]));
        }

        // Sort by task_id to restore original order
        results.sort_by_key(|r| r.task_id);
        samples.sort_by_key(|(id, _)| *id);
        let forked_samples = samples.into_iter().map(|(_, s)| s).collect();

        Ok((results, forked_samples))
    }

    /// Execute all chip proof tasks using the greedy backfilling algorithm.
    ///
    /// Tasks are sorted by memory requirement (descending) and scheduled to
    /// maximize GPU utilization while respecting memory constraints.
    ///
    /// Each worker thread clones the parent `transcript`. After proving, the worker
    /// samples one extension-field element from its local transcript and returns it.
    /// This avoids sending non-`Send` transcript objects across threads.
    ///
    /// Returns `(results, forked_samples)` both sorted by task_id.
    #[cfg(feature = "gpu")]
    #[allow(clippy::type_complexity)]
    fn execute_concurrently<'a, PB, T, F>(
        &self,
        mut tasks: Vec<ChipTask<'a, PB>>,
        transcript: &T,
        execute_task: F,
        lane_count: usize,
    ) -> Result<(Vec<ChipTaskResult<'a, PB>>, Vec<PB::E>), ZKVMError>
    where
        PB: ProverBackend + 'static,
        PB::E: Send + 'static,
        T: Transcript<PB::E> + Clone,
        F: Fn(ChipTask<'a, PB>, &mut T) -> Result<ChipTaskResult<'a, PB>, ZKVMError> + Send + Sync,
    {
        if tasks.is_empty() {
            return Ok((vec![], vec![]));
        }

        let cuda_hal = get_cuda_hal().expect("Failed to get CUDA HAL");
        let worker_limit = lane_count;

        // must call `init_booking_baseline` before concurrent execution
        let mem_pool = cuda_hal.inner().mem_pool();
        mem_pool
            .init_booking_baseline()
            .expect("Failed to init booking baseline");
        let booking_baseline = mem_pool.get_booked_total();

        // 1. Sort by memory descending (big rocks first)
        tasks.sort_by(|a, b| b.estimated_memory_bytes.cmp(&a.estimated_memory_bytes));

        let total_tasks = tasks.len();

        tracing::info!(
            "[scheduler] Starting {} tasks, mode={}, workers={}, booking_baseline={:.2}MB, mem_pool_max={}GB",
            total_tasks,
            "lanes",
            worker_limit,
            booking_baseline as f64 / (1024.0 * 1024.0),
            mem_pool.get_max_size() / (1024 * 1024 * 1024)
        );

        for task in &tasks {
            tracing::debug!(
                "[scheduler] Task {} ({}): {}MB",
                task.task_id,
                task.circuit_name,
                task.estimated_memory_bytes / (1024 * 1024)
            );
        }

        // 2. Create channels
        //    Scheduler -> Worker: task only (transcript is cloned inside worker)
        //    Worker -> Scheduler: CompletionMessage (includes sampled value)
        let (task_tx, task_rx) = mpsc::channel::<ScheduledTask<'a, PB>>();
        let task_rx = Arc::new(Mutex::new(task_rx));
        let (done_tx, done_rx) = mpsc::channel::<CompletionMessage<'a, PB>>();

        // 3. State tracking
        let mut tasks_inflight = 0usize;
        let mut results: Vec<ChipTaskResult<'a, PB>> = Vec::with_capacity(total_tasks);
        let mut samples: Vec<(usize, PB::E)> = Vec::with_capacity(total_tasks);

        // Helper to handle a completion message
        let mut handle_completion = |msg: CompletionMessage<'a, PB>,
                                     mem_pool: &ceno_gpu::common::mem_pool::CudaMemPool,
                                     tasks_inflight: &mut usize,
                                     label: &str|
         -> Result<(), ZKVMError> {
            mem_pool.unbook_capacity(msg.memory_reserved);
            *tasks_inflight -= 1;
            let pool_used = mem_pool.get_used_size().unwrap_or(0);
            let pool_reserved = mem_pool.get_reserved_size().unwrap_or(0);
            tracing::info!(
                "[scheduler] Task completed{}, task_id={}, circuit={}, lane={}, stream_id={:?}, queue_delay={:.3}ms, host_execution={:.3}ms, event_wait={:.3}ms, completion={:.3}ms, unbooked={:.2}MB, pool_used={:.2}MB, pool_reserved={:.2}MB, pool_booked={:.2}MB, inflight={}",
                label,
                msg.task_id,
                msg.circuit_name,
                msg.lane_id,
                msg.stream_id,
                msg.queue_delay_ms,
                msg.host_execution_ms,
                msg.event_wait_ms,
                msg.completion_ms,
                msg.memory_reserved as f64 / (1024.0 * 1024.0),
                pool_used as f64 / (1024.0 * 1024.0),
                pool_reserved as f64 / (1024.0 * 1024.0),
                mem_pool.get_booked_total() as f64 / (1024.0 * 1024.0),
                *tasks_inflight
            );
            crate::scheme::gpu::log_gpu_device_state(&format!(
                "task_done{}:{}",
                label.replace(' ', ""),
                msg.task_id
            ));
            samples.push((msg.task_id, msg.forked_sample));
            match msg.result {
                Ok(r) => {
                    results.push(r);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        };

        // SAFETY: transcript is only read (via clone) during concurrent execution.
        // Workers never mutate the shared reference; each clone is thread-local.
        use crate::scheme::utils::SyncRef;
        let transcript_ref = SyncRef(transcript);
        let scheduler_start = Instant::now();

        // Acquire the explicit non-default streams before admitting work. Holding one guard per
        // worker gives each lane a stable stream and makes duplicate/default assignment fatal.
        let mut lane_streams = Vec::with_capacity(worker_limit.min(total_tasks));
        let mut stream_ids = Vec::with_capacity(worker_limit.min(total_tasks));
        for lane_id in 0..worker_limit.min(total_tasks) {
            let stream = cuda_hal.inner().get_pool_stream().map_err(|err| {
                mem_pool.reset_booking();
                ZKVMError::BackendError(BackendError::CircuitError(
                    format!("failed to acquire CUDA stream for lane {lane_id}: {err}")
                        .into_boxed_str(),
                ))
            })?;
            let raw_stream = stream.stream().cu_stream();
            if raw_stream.is_null() {
                mem_pool.reset_booking();
                return Err(ZKVMError::BackendError(BackendError::CircuitError(
                    format!("chip scheduler lane {lane_id} acquired the default stream")
                        .into_boxed_str(),
                )));
            }
            let mut stream_id = 0u64;
            let status = unsafe { cudarc::driver::sys::cuStreamGetId(raw_stream, &mut stream_id) };
            if status != cudarc::driver::sys::CUresult::CUDA_SUCCESS {
                mem_pool.reset_booking();
                return Err(ZKVMError::BackendError(BackendError::CircuitError(
                    format!("failed to query CUDA stream ID for lane {lane_id}: {status:?}")
                        .into_boxed_str(),
                )));
            }
            if let Err(message) = validate_unique_stream_id(&stream_ids, stream_id) {
                mem_pool.reset_booking();
                return Err(ZKVMError::BackendError(BackendError::CircuitError(
                    message.into_boxed_str(),
                )));
            }
            stream_ids.push(stream_id);
            lane_streams.push((Some(stream), Some(stream_id)));
        }

        // 4. Use thread::scope for borrowing references
        let _fallback_guard = gkr_iop::gpu::forbid_default_stream_fallback();
        let scope_result: Result<(), ZKVMError> = std::thread::scope(|s| {
            for (lane_id, (lane_stream, stream_id)) in lane_streams.drain(..).enumerate() {
                let rx = Arc::clone(&task_rx);
                let tx = done_tx.clone();
                let execute_fn = &execute_task;
                let tr = &transcript_ref;

                s.spawn(move || {
                    nvtx::name_thread!("ceno-chip-lane-{}", lane_id);
                    loop {
                        let scheduled = {
                            let lock = rx.lock().unwrap();
                            match lock.recv() {
                                Ok(t) => t,
                                Err(_) => break,
                            }
                        };
                        let queue_delay_ms = scheduled.queued_at.elapsed().as_secs_f64() * 1000.0;
                        let task = scheduled.task;
                        let memory = task.estimated_memory_bytes;
                        let booked_memory = task.booked_memory_bytes;
                        let task_id = task.task_id;
                        let circuit_name = task.circuit_name.clone();
                        tracing::info!(
                            "[scheduler] worker starting task {} ({}), lane={}, stream_id={:?}, queue_delay={:.3}ms, estimated={:.2}MB, reserved={:.2}MB",
                            task_id,
                            circuit_name,
                            lane_id,
                            stream_id,
                            queue_delay_ms,
                            memory as f64 / (1024.0 * 1024.0),
                            booked_memory as f64 / (1024.0 * 1024.0)
                        );
                        crate::scheme::gpu::log_gpu_device_state(&format!(
                            "task_start:{}:{}",
                            task_id, circuit_name
                        ));
                        let _chip_range = nvtx::range!(
                            "ceno.chip circuit={} lane={} stream_id={}",
                            circuit_name,
                            lane_id,
                            stream_id
                                .map(|id| id.to_string())
                                .unwrap_or_else(|| "default".to_string())
                        );

                        // Catch panics so a single worker crash doesn't deadlock
                        // the scheduler (which would block forever on done_rx.recv()
                        // waiting for a CompletionMessage that never arrives).
                        let host_start = Instant::now();
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                let _lane_binding = lane_stream.as_ref().map(|stream| {
                                    gkr_iop::gpu::bind_thread_stream(stream.stream().clone())
                                });
                                // Fork locally: clone parent transcript template.
                                let mut local_transcript = tr.0.clone();
                                let result = execute_fn(task, &mut local_transcript);

                                // Sample from the forked transcript for gather phase
                                let forked_sample = local_transcript.sample_vec(1)[0];
                                (result, forked_sample)
                            }));
                        let host_execution_ms = host_start.elapsed().as_secs_f64() * 1000.0;

                        let (result, forked_sample) = match outcome {
                            Ok((r, s)) => (r, s),
                            Err(panic_info) => {
                                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                                    format!(
                                        "Worker panicked on task {task_id} ({circuit_name}): {s}"
                                    )
                                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                                    format!(
                                        "Worker panicked on task {task_id} ({circuit_name}): {s}"
                                    )
                                } else {
                                    format!("Worker panicked on task {task_id} ({circuit_name})")
                                };
                                tracing::error!("{}", msg);
                                (
                                    Err(ZKVMError::BackendError(BackendError::CircuitError(
                                        msg.into_boxed_str(),
                                    ))),
                                    <PB::E as p3::field::PrimeCharacteristicRing>::ZERO,
                                )
                            }
                        };

                        // The scheduler may release neither the reservation nor this lane until
                        // all work submitted by the chip reaches a stream-local completion event.
                        let event_wait_start = Instant::now();
                        let _event_wait_range = nvtx::range!("ceno.phase.completion-event-wait");
                        let completion_error = lane_stream.as_ref().and_then(|stream| {
                            stream
                                .stream()
                                .record_event(None)
                                .and_then(|event| event.synchronize())
                                .err()
                        });
                        let event_wait_ms = event_wait_start.elapsed().as_secs_f64() * 1000.0;
                        drop(_event_wait_range);
                        let result = match completion_error {
                            Some(err) => Err(ZKVMError::BackendError(BackendError::CircuitError(
                                format!(
                                    "CUDA completion event failed for task {task_id} ({circuit_name}) on lane {lane_id}: {err}"
                                )
                                .into_boxed_str(),
                            ))),
                            None => result,
                        };
                        let completion_ms = queue_delay_ms + host_execution_ms + event_wait_ms;

                        let _ = tx.send(CompletionMessage {
                            result,
                            memory_reserved: booked_memory,
                            task_id,
                            circuit_name,
                            forked_sample,
                            lane_id,
                            stream_id,
                            queue_delay_ms,
                            host_execution_ms,
                            event_wait_ms,
                            completion_ms,
                        });
                    }
                });
            }
            drop(done_tx);

            // 5. Scheduling loop (greedy backfilling)
            let mut pending: Vec<ChipTask<'a, PB>> = tasks;

            while !pending.is_empty() || tasks_inflight > 0 {
                // First drain any completions already available to free memory immediately.
                // This non-blocking path keeps utilization high (and covers the initial loop
                // iteration when nothing is running yet), so we handle completions here.
                while let Ok(msg) = done_rx.try_recv() {
                    if let Err(e) = handle_completion(msg, mem_pool, &mut tasks_inflight, "") {
                        drop(task_tx);
                        return Err(e);
                    }
                }

                // Launch the first pending task whose memory fits; otherwise fall through to wait.
                if tasks_inflight < worker_limit
                    && let Some(vec_idx) = pending.iter().position(|task| {
                        mem_pool
                            .try_book_capacity(task.booked_memory_bytes)
                            .is_some()
                    })
                {
                    let task = pending.remove(vec_idx);
                    let booked_mem = task.booked_memory_bytes;
                    let pool_used = mem_pool.get_used_size().unwrap_or(0);
                    let pool_reserved = mem_pool.get_reserved_size().unwrap_or(0);
                    tracing::info!(
                        "[scheduler] Launching task_id={}, circuit={}, estimated_mem={:.2}MB, booked_mem={:.2}MB, pool_used={:.2}MB, pool_reserved={:.2}MB, pool_booked={:.2}MB",
                        task.task_id,
                        task.circuit_name,
                        task.estimated_memory_bytes as f64 / (1024.0 * 1024.0),
                        booked_mem as f64 / (1024.0 * 1024.0),
                        pool_used as f64 / (1024.0 * 1024.0),
                        pool_reserved as f64 / (1024.0 * 1024.0),
                        mem_pool.get_booked_total() as f64 / (1024.0 * 1024.0)
                    );
                    crate::scheme::gpu::log_gpu_device_state(&format!(
                        "launch:{}:{}",
                        task.task_id, task.circuit_name
                    ));
                    tasks_inflight += 1;
                    if task_tx
                        .send(ScheduledTask {
                            task,
                            queued_at: scheduler_start,
                        })
                        .is_err()
                    {
                        mem_pool.unbook_capacity(booked_mem);
                        tasks_inflight -= 1;
                        drop(task_tx);
                        return Err(ZKVMError::BackendError(BackendError::CircuitError(
                            "Worker channel closed: all workers have died"
                                .to_string()
                                .into_boxed_str(),
                        )));
                    }
                    continue;
                }

                // No task launched: either nothing fits (so wait) or we are deadlocked.
                if tasks_inflight == 0 {
                    // Not a deadlock — the non-blocking try_recv above may have
                    // drained the final completion in the same iteration that
                    // the outer `while` condition still held. With `pending`
                    // empty and `tasks_inflight` now 0 we're simply done; let
                    // the outer condition re-check and exit cleanly.
                    if pending.is_empty() {
                        continue;
                    }
                    tracing::error!(
                        "Deadlock: {} remaining tasks are too big for the memory pool \
                         (pool_booked={:.2}MB):",
                        pending.len(),
                        mem_pool.get_booked_total() as f64 / (1024.0 * 1024.0),
                    );
                    for (i, task) in pending.iter().enumerate() {
                        tracing::error!(
                            "  task[{}]: id={}, circuit={}, estimated_mem={:.2}MB, booked_mem={:.2}MB",
                            i,
                            task.task_id,
                            task.circuit_name,
                            task.estimated_memory_bytes as f64 / (1024.0 * 1024.0),
                            task.booked_memory_bytes as f64 / (1024.0 * 1024.0),
                        );
                    }
                    let max_size = mem_pool.get_max_size();
                    let booked_total = mem_pool.get_booked_total();
                    let available = max_size.saturating_sub(booked_total);
                    let pending_summary = pending
                        .iter()
                        .map(|task| {
                            format!(
                                "id={} circuit={} estimated={:.2}MB booked={:.2}MB",
                                task.task_id,
                                task.circuit_name,
                                task.estimated_memory_bytes as f64 / (1024.0 * 1024.0),
                                task.booked_memory_bytes as f64 / (1024.0 * 1024.0),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(ZKVMError::BackendError(BackendError::CircuitError(
                        format!(
                            "Deadlock: Remaining tasks are too big for the memory pool: available={:.2}MB, max={:.2}MB, booked={:.2}MB, pending=[{}]",
                            available as f64 / (1024.0 * 1024.0),
                            max_size as f64 / (1024.0 * 1024.0),
                            booked_total as f64 / (1024.0 * 1024.0),
                            pending_summary,
                        )
                        .into_boxed_str(),
                    )));
                }

                let wait_reason = if pending.is_empty() {
                    SchedulerWaitReason::CompletionDrain
                } else {
                    scheduler_wait_reason(tasks_inflight, worker_limit)
                };
                tracing::info!(
                    "[scheduler] Waiting for task completion, reason={:?}, pool_booked={:.2}MB, inflight={}, worker_limit={}",
                    wait_reason,
                    mem_pool.get_booked_total() as f64 / (1024.0 * 1024.0),
                    tasks_inflight,
                    worker_limit,
                );
                crate::scheme::gpu::log_gpu_device_state("pool_full_wait");

                // Second call site blocks instead of busy-waiting when the pool is full; this
                // waits for the next completion to free memory before trying to launch again.
                match done_rx.recv() {
                    Ok(msg) => {
                        if let Err(e) =
                            handle_completion(msg, mem_pool, &mut tasks_inflight, " (blocked)")
                        {
                            drop(task_tx);
                            return Err(e);
                        }
                    }
                    Err(_) => {
                        if tasks_inflight > 0 {
                            return Err(ZKVMError::BackendError(BackendError::CircuitError(
                                "Completion channel closed with tasks still in-flight"
                                    .to_string()
                                    .into_boxed_str(),
                            )));
                        }
                        break;
                    }
                }
            }

            drop(task_tx);
            Ok(())
        });

        let scope_result = scope_result;
        mem_pool.reset_booking();
        scope_result?;

        // 6. Sort by task_id to restore original order
        results.sort_by_key(|r| r.task_id);
        samples.sort_by_key(|(id, _)| *id);
        let forked_samples: Vec<PB::E> = samples.into_iter().map(|(_, s)| s).collect();

        Ok((results, forked_samples))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chip_proving_modes_use_bounded_lanes_by_default() {
        assert_eq!(
            parse_chip_proving_mode(Some("sequential")),
            ChipSchedulerMode::Sequential
        );
        assert_eq!(
            parse_chip_proving_mode(Some("lanes")),
            ChipSchedulerMode::Lanes
        );
        assert_eq!(parse_chip_proving_mode(None), ChipSchedulerMode::Lanes);
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn scheduler_wait_reasons_distinguish_worker_and_memory_limits() {
        assert_eq!(
            scheduler_wait_reason(DEFAULT_CHIP_PROVING_LANES, DEFAULT_CHIP_PROVING_LANES),
            SchedulerWaitReason::WorkerLimit
        );
        assert_eq!(
            scheduler_wait_reason(1, DEFAULT_CHIP_PROVING_LANES),
            SchedulerWaitReason::MemoryLimit
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn chip_proving_lane_configuration_accepts_only_one_through_eight() {
        assert_eq!(parse_chip_proving_lanes(None), Ok(4));
        for lanes in 1..=8 {
            assert_eq!(
                parse_chip_proving_lanes(Some(&lanes.to_string())),
                Ok(lanes)
            );
        }
        for invalid in ["0", "not-a-number", "9"] {
            assert!(parse_chip_proving_lanes(Some(invalid)).is_err());
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn explicit_lane_stream_ids_must_be_unique() {
        let mut stream_ids = Vec::new();
        for stream_id in 17..=20 {
            validate_unique_stream_id(&stream_ids, stream_id).unwrap();
            stream_ids.push(stream_id);
        }
        assert!(validate_unique_stream_id(&stream_ids, 18).is_err());
    }
}
