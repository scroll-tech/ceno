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
    scheme::{ZKVMChipProof, hal::ProofInput},
    structs::ProvingKey,
};
use ff_ext::ExtensionField;
use gkr_iop::hal::ProverBackend;
use mpcs::Point;
use p3::field::FieldAlgebra;
use std::collections::HashMap;
use transcript::Transcript;

#[cfg(feature = "gpu")]
use gkr_iop::error::BackendError;
#[cfg(feature = "gpu")]
use std::sync::{Arc, Mutex, OnceLock, mpsc};
#[cfg(feature = "gpu")]
const CONCURRENT_PROVING_WORKERS: usize = 8;

#[cfg(feature = "gpu")]
static CHIP_PROVING_MODE: OnceLock<ChipProvingMode> = OnceLock::new();

#[cfg(feature = "gpu")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChipProvingMode {
    Sequential,
    Concurrent,
}

#[cfg(feature = "gpu")]
pub fn get_chip_proving_mode() -> ChipProvingMode {
    *CHIP_PROVING_MODE.get_or_init(|| {
        match std::env::var("CENO_CONCURRENT_CHIP_PROVING").as_deref() {
            Ok("0") => ChipProvingMode::Sequential,
            _ => ChipProvingMode::Concurrent,
        }
    })
}

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
    /// Whether this circuit has witness or fixed polynomials
    pub has_witness_or_fixed: bool,
    /// Challenges for this proof
    pub challenges: [PB::E; 2],
    /// Deferred witness extraction: trace index in pcs_data (None if num_witin == 0)
    pub witness_trace_idx: Option<usize>,
    /// Expected number of witness polynomials for this circuit
    pub num_witin: usize,
    /// CPU-side structural witness RowMajorMatrix, transported to GPU on-demand
    pub structural_rmm: Option<witness::RowMajorMatrix<<PB::E as ExtensionField>::BaseField>>,
}

/// Result from a completed chip proof task
pub struct ChipTaskResult<E: ExtensionField> {
    /// Task ID for ordering
    pub task_id: usize,
    /// Circuit index for proof collection
    pub circuit_idx: usize,
    /// The generated proof
    pub proof: ZKVMChipProof<E>,
    /// Public input evaluations
    pub pi_in_evals: HashMap<usize, E>,
    /// Opening point for this proof
    pub input_opening_point: Point<E>,
    /// Whether this circuit has witness or fixed polynomials
    pub has_witness_or_fixed: bool,
}

/// Message sent from worker to scheduler on task completion
#[cfg(feature = "gpu")]
struct CompletionMessage<E: ExtensionField> {
    /// The result of the proof
    result: Result<ChipTaskResult<E>, ZKVMError>,
    /// Memory that was reserved for this task (to release)
    memory_reserved: u64,
    /// Task ID for ordering
    task_id: usize,
    /// Sampled value from the forked transcript (for gather phase)
    forked_sample: E,
}

/// Get a CUDA memory pool from the global CUDA HAL singleton.
#[cfg(feature = "gpu")]
fn get_cuda_pool() -> std::sync::Arc<ceno_gpu::common::mem_pool::CudaMemPool> {
    use gkr_iop::gpu::gpu_prover::CudaHal;
    let cuda_hal = gkr_iop::gpu::get_cuda_hal().expect("Failed to get CUDA HAL");
    let p = cuda_hal.inner().mem_pool().clone();
    p.init_booking_baseline()
        .expect("Failed to init booking baseline");
    p
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
    /// On GPU: uses concurrent scheduling by default. Set
    /// `CENO_CONCURRENT_CHIP_PROVING=0` to force sequential execution.
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
    ) -> Result<(Vec<ChipTaskResult<PB::E>>, Vec<PB::E>), ZKVMError>
    where
        PB: ProverBackend + 'static,
        PB::E: Send + 'static,
        T: Transcript<PB::E> + Clone,
        F: Fn(ChipTask<'a, PB>, &mut T) -> Result<ChipTaskResult<PB::E>, ZKVMError> + Send + Sync,
    {
        #[cfg(feature = "gpu")]
        {
            if get_chip_proving_mode() == ChipProvingMode::Concurrent {
                let pool = get_cuda_pool();
                return self.execute_concurrently(tasks, transcript, &pool, execute_task);
            }
            tracing::info!(
                "[scheduler] CENO_CONCURRENT_CHIP_PROVING=0, using sequential execution"
            );
        }
        self.execute_sequentially(tasks, transcript, execute_task)
    }

    /// Check if concurrent mode is enabled (GPU only).
    #[cfg(feature = "gpu")]
    pub(crate) fn is_concurrent_mode() -> bool {
        get_chip_proving_mode() == ChipProvingMode::Concurrent
    }

    /// Execute tasks sequentially with automatic transcript forking and sampling.
    ///
    /// Each task gets a transcript cloned from `parent_transcript` with `task_id`
    /// appended (identical to `ForkableTranscript::fork` default impl).
    /// Returns `(results, forked_samples)` both sorted by task_id.
    #[allow(clippy::type_complexity)]
    pub(crate) fn execute_sequentially<'a, PB, T, F>(
        &self,
        tasks: Vec<ChipTask<'a, PB>>,
        parent_transcript: &T,
        execute_task: F,
    ) -> Result<(Vec<ChipTaskResult<PB::E>>, Vec<PB::E>), ZKVMError>
    where
        PB: ProverBackend + 'static,
        PB::E: Send + 'static,
        T: Transcript<PB::E> + Clone,
        F: Fn(ChipTask<'a, PB>, &mut T) -> Result<ChipTaskResult<PB::E>, ZKVMError>,
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
            // Fork: clone parent + append task_id
            // (identical to ForkableTranscript::fork default impl)
            let mut forked = parent_transcript.clone();
            forked.append_field_element(&<PB::E as ExtensionField>::BaseField::from_canonical_u64(
                task_id as u64,
            ));

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
    /// Each worker thread clones the parent `transcript` and appends its task_id
    /// (reproducing `ForkableTranscript::fork` locally). After proving, the worker
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
        pool: &ceno_gpu::common::mem_pool::CudaMemPool,
        execute_task: F,
    ) -> Result<(Vec<ChipTaskResult<PB::E>>, Vec<PB::E>), ZKVMError>
    where
        PB: ProverBackend + 'static,
        PB::E: Send + 'static,
        T: Transcript<PB::E> + Clone,
        F: Fn(ChipTask<'a, PB>, &mut T) -> Result<ChipTaskResult<PB::E>, ZKVMError> + Send + Sync,
    {
        if tasks.is_empty() {
            return Ok((vec![], vec![]));
        }

        // For single task, just execute directly (no threading overhead)
        if tasks.len() == 1 {
            let task = tasks.remove(0);
            let mut fork = transcript.clone();
            fork.append_field_element(&<PB::E as ExtensionField>::BaseField::from_canonical_u64(
                task.task_id as u64,
            ));
            let result = execute_task(task, &mut fork)?;
            let sample = fork.sample_vec(1)[0];
            return Ok((vec![result], vec![sample]));
        }

        // 1. Sort by memory descending (big rocks first)
        tasks.sort_by(|a, b| b.estimated_memory_bytes.cmp(&a.estimated_memory_bytes));

        let total_tasks = tasks.len();

        tracing::info!(
            "[scheduler] Starting {} tasks, workers={}, pool_max={}GB",
            total_tasks,
            CONCURRENT_PROVING_WORKERS,
            pool.get_max_size() / (1024 * 1024 * 1024)
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
        let (task_tx, task_rx) = mpsc::channel::<ChipTask<'a, PB>>();
        let task_rx = Arc::new(Mutex::new(task_rx));
        let (done_tx, done_rx) = mpsc::channel::<CompletionMessage<PB::E>>();

        // 3. State tracking
        let mut tasks_inflight = 0usize;
        let mut results: Vec<ChipTaskResult<PB::E>> = Vec::with_capacity(total_tasks);
        let mut samples: Vec<(usize, PB::E)> = Vec::with_capacity(total_tasks);

        // Helper to handle a completion message
        let mut handle_completion = |msg: CompletionMessage<PB::E>,
                                     pool: &ceno_gpu::common::mem_pool::CudaMemPool,
                                     tasks_inflight: &mut usize,
                                     label: &str|
         -> Result<(), ZKVMError> {
            pool.unbook_capacity(msg.memory_reserved);
            *tasks_inflight -= 1;
            tracing::info!(
                "[scheduler] Task completed{}, unbooked={:.2}MB, pool_booked={:.2}MB, inflight={}",
                label,
                msg.memory_reserved as f64 / (1024.0 * 1024.0),
                pool.get_booked_total() as f64 / (1024.0 * 1024.0),
                *tasks_inflight
            );
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

        // 4. Use thread::scope for borrowing references
        let scope_result: Result<(), ZKVMError> = std::thread::scope(|s| {
            let num_workers = CONCURRENT_PROVING_WORKERS.min(total_tasks);
            for _worker_id in 0..num_workers {
                let rx = Arc::clone(&task_rx);
                let tx = done_tx.clone();
                let execute_fn = &execute_task;
                let tr = &transcript_ref;

                s.spawn(move || {
                    loop {
                        let task = {
                            let lock = rx.lock().unwrap();
                            match lock.recv() {
                                Ok(t) => t,
                                Err(_) => break,
                            }
                        };
                        let memory = task.estimated_memory_bytes;
                        let task_id = task.task_id;

                        // Catch panics so a single worker crash doesn't deadlock
                        // the scheduler (which would block forever on done_rx.recv()
                        // waiting for a CompletionMessage that never arrives).
                        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            // Fork locally: clone parent transcript + append task_id
                            // (identical to ForkableTranscript::fork default impl)
                            let mut local_transcript = tr.0.clone();
                            local_transcript.append_field_element(
                                &<PB::E as ExtensionField>::BaseField::from_canonical_u64(
                                    task_id as u64,
                                ),
                            );

                            let result = execute_fn(task, &mut local_transcript);

                            // Sample from the forked transcript for gather phase
                            let forked_sample = local_transcript.sample_vec(1)[0];
                            (result, forked_sample)
                        }));

                        let (result, forked_sample) = match outcome {
                            Ok((r, s)) => (r, s),
                            Err(panic_info) => {
                                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                                    format!("Worker panicked on task {task_id}: {s}")
                                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                                    format!("Worker panicked on task {task_id}: {s}")
                                } else {
                                    format!("Worker panicked on task {task_id}")
                                };
                                tracing::error!("{}", msg);
                                (
                                    Err(ZKVMError::BackendError(BackendError::CircuitError(
                                        msg.into_boxed_str(),
                                    ))),
                                    PB::E::ZERO,
                                )
                            }
                        };

                        let _ = tx.send(CompletionMessage {
                            result,
                            memory_reserved: memory,
                            task_id,
                            forked_sample,
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
                    if let Err(e) = handle_completion(msg, pool, &mut tasks_inflight, "") {
                        drop(task_tx);
                        return Err(e);
                    }
                }

                // Launch the first pending task whose memory fits; otherwise fall through to wait.
                if tasks_inflight < CONCURRENT_PROVING_WORKERS
                    && let Some(vec_idx) = pending.iter().position(|task| {
                        pool.try_book_capacity(task.estimated_memory_bytes)
                            .is_some()
                    })
                {
                    let task = pending.remove(vec_idx);
                    let booked_mem = task.estimated_memory_bytes;
                    tracing::info!(
                        "[scheduler] Launching circuit={}, estimated_mem={:.2}MB, pool_booked={:.2}MB",
                        task.circuit_name,
                        booked_mem as f64 / (1024.0 * 1024.0),
                        pool.get_booked_total() as f64 / (1024.0 * 1024.0)
                    );
                    tasks_inflight += 1;
                    if task_tx.send(task).is_err() {
                        pool.unbook_capacity(booked_mem);
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
                    tracing::error!("Deadlock: Remaining tasks are too big for the memory pool!");
                    return Err(ZKVMError::BackendError(BackendError::CircuitError(
                        "Deadlock: Remaining tasks are too big for the memory pool!"
                            .to_string()
                            .into_boxed_str(),
                    )));
                }

                tracing::info!(
                    "[scheduler] Pool full, waiting for task completion... pool_booked={:.2}MB, inflight={}",
                    pool.get_booked_total() as f64 / (1024.0 * 1024.0),
                    tasks_inflight
                );

                // Second call site blocks instead of busy-waiting when the pool is full; this
                // waits for the next completion to free memory before trying to launch again.
                match done_rx.recv() {
                    Ok(msg) => {
                        if let Err(e) =
                            handle_completion(msg, pool, &mut tasks_inflight, " (blocked)")
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

        scope_result?;

        // 6. Sort by task_id to restore original order
        results.sort_by_key(|r| r.task_id);
        samples.sort_by_key(|(id, _)| *id);
        let forked_samples: Vec<PB::E> = samples.into_iter().map(|(_, s)| s).collect();

        Ok((results, forked_samples))
    }
}
