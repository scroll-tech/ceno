use std::{
    any::Any,
    collections::HashSet,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    thread,
    time::Instant,
};

use eyre::{Result, eyre};
use openvm_cuda_backend::BabyBearPoseidon2GpuEngine;
use openvm_stark_backend::proof::Proof;
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;

use crate::system::{RecursionProof, RecursionVk, warm_child_vk_digest_cache};

use super::{
    AggregationOptions, ChildVkKind, GpuRecursionProver, RecursionHostAssets,
    RecursionHostAssetsTemplate, RecursionNodeKind, RecursionPlan, RecursionScheduler,
    RecursionTask, RecursionTaskResult, RecursionWorkerError, RecursionWorkerMetrics,
    RecursionWorkerPhase, RootProof, RootProvingOutput, run_scheduler_worker, verify_root_proof,
};

type InternalProof = Proof<BabyBearPoseidon2Config>;
type GpuScheduler = RecursionScheduler<RecursionProof, InternalProof, RootProof>;
type GpuWorkerHandle =
    thread::JoinHandle<std::result::Result<RecursionWorkerMetrics, RecursionWorkerError>>;
type HostAssets<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> =
    RecursionHostAssets<LEAF_FANIN, INTERNAL_FANIN>;
type HostAssetsTemplate<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> =
    RecursionHostAssetsTemplate<LEAF_FANIN, INTERNAL_FANIN>;
type HostAssetsBuilder<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> = thread::JoinHandle<
    Result<(
        Arc<HostAssets<LEAF_FANIN, INTERNAL_FANIN>>,
        HostAssetBuildTimings,
    )>,
>;

#[derive(Clone, Copy)]
struct HostAssetBuildTimings {
    template: std::time::Duration,
    template_wait: std::time::Duration,
    bind: std::time::Duration,
}

pub struct RecursionHostAssetsBuilder<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> {
    child_vk_digest: [crate::system::RecursionField; ceno_zkvm::structs::VK_DIGEST_LEN],
    handle: thread::JoinHandle<
        Result<(
            Arc<HostAssetsTemplate<LEAF_FANIN, INTERNAL_FANIN>>,
            std::time::Duration,
        )>,
    >,
}

impl<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize>
    RecursionHostAssetsBuilder<LEAF_FANIN, INTERNAL_FANIN>
{
    pub fn spawn(
        child_vk: Arc<RecursionVk>,
        child_vk_digest: [crate::system::RecursionField; ceno_zkvm::structs::VK_DIGEST_LEN],
        options: AggregationOptions,
    ) -> Result<Self> {
        let handle = thread::Builder::new()
            .name("recursion-host-template".to_owned())
            .spawn(move || {
                let started = Instant::now();
                warm_child_vk_digest_cache(&child_vk);
                let template = Arc::new(RecursionHostAssetsTemplate::new(child_vk, &options)?);
                Ok((template, started.elapsed()))
            })?;
        Ok(Self {
            child_vk_digest,
            handle,
        })
    }

    pub fn validate_child_vk_digest(
        &self,
        child_vk_digest: &[crate::system::RecursionField; ceno_zkvm::structs::VK_DIGEST_LEN],
    ) -> Result<()> {
        if &self.child_vk_digest != child_vk_digest {
            return Err(eyre!(
                "prebuilt recursion host assets do not match the proving app VK"
            ));
        }
        Ok(())
    }

    fn bind(
        self,
        total_shards: usize,
    ) -> Result<(
        Arc<HostAssets<LEAF_FANIN, INTERNAL_FANIN>>,
        HostAssetBuildTimings,
    )> {
        let wait_started = Instant::now();
        let (template, template_time) = self.handle.join().map_err(|payload| {
            eyre!(
                "recursion host-asset template builder panicked: {}",
                panic_message(payload)
            )
        })??;
        let template_wait = wait_started.elapsed();
        let bind_started = Instant::now();
        let assets = Arc::new(template.bind(total_shards)?);
        Ok((
            assets,
            HostAssetBuildTimings {
                template: template_time,
                template_wait,
                bind: bind_started.elapsed(),
            },
        ))
    }
}

pub struct GpuRecursionBatchOutput {
    pub root_output: RootProvingOutput,
    pub worker_metrics: Vec<RecursionWorkerMetrics>,
    pub root_verification_time: std::time::Duration,
}

pub struct GpuRecursionSession<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> {
    scheduler: Arc<GpuScheduler>,
    assets: Option<Arc<HostAssets<LEAF_FANIN, INTERNAL_FANIN>>>,
    assets_builder: Option<HostAssetsBuilder<LEAF_FANIN, INTERNAL_FANIN>>,
    released_devices: HashSet<usize>,
    workers: Vec<GpuWorkerHandle>,
}

impl<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize>
    GpuRecursionSession<LEAF_FANIN, INTERNAL_FANIN>
{
    pub fn new_with_assets_builder(
        total_shards: usize,
        assets_template: RecursionHostAssetsBuilder<LEAF_FANIN, INTERNAL_FANIN>,
    ) -> Result<Self> {
        let scheduler = Arc::new(GpuScheduler::new(RecursionPlan::new(
            total_shards,
            LEAF_FANIN,
            INTERNAL_FANIN,
        )?));
        let assets_builder = thread::Builder::new()
            .name("recursion-host-assets".to_owned())
            .spawn(move || assets_template.bind(total_shards))?;
        Ok(Self {
            scheduler,
            assets: None,
            assets_builder: Some(assets_builder),
            released_devices: HashSet::new(),
            workers: Vec::new(),
        })
    }

    fn resolve_assets(&mut self) -> Result<Arc<HostAssets<LEAF_FANIN, INTERNAL_FANIN>>> {
        if let Some(assets) = &self.assets {
            return Ok(assets.clone());
        }
        let wait_started = Instant::now();
        let builder = self
            .assets_builder
            .take()
            .ok_or_else(|| eyre!("recursion host-asset builder is unavailable"))?;
        let (assets, timings) = builder.join().map_err(|payload| {
            eyre!(
                "recursion host-asset builder panicked: {}",
                panic_message(payload)
            )
        })??;
        tracing::info!(
            target: "ceno_multi_gpu",
            template_build_ms = timings.template.as_millis(),
            template_wait_ms = timings.template_wait.as_millis(),
            bind_ms = timings.bind.as_millis(),
            release_wait_ms = wait_started.elapsed().as_millis(),
            phase = "recursion_host_assets_ready",
            "recursion host assets ready"
        );
        self.assets = Some(assets.clone());
        Ok(assets)
    }

    pub fn accept_base_proof(&self, shard_id: usize, proof: RecursionProof) -> Result<()> {
        self.scheduler.accept_base_proof(shard_id, proof)?;
        tracing::info!(
            target: "ceno_multi_gpu",
            shard_id,
            phase = "recursion_base_proof_queued",
            "metadata-valid base proof entered recursion scheduler"
        );
        Ok(())
    }

    pub fn release_device(&mut self, device_id: usize) -> Result<()> {
        register_released_device(&mut self.released_devices, device_id)?;
        let scheduler = self.scheduler.clone();
        let assets = self.resolve_assets().inspect_err(|error| {
            self.scheduler.cancel(error.to_string());
        })?;
        // The base owner has already synchronized, dropped device state, and trimmed this GPU.
        // Hydration therefore happens on the worker thread after binding the released device.
        let worker = thread::Builder::new()
            .name(format!("recursion-gpu-{device_id}"))
            .spawn(move || {
                match catch_unwind(AssertUnwindSafe(|| {
                    run_gpu_worker(device_id, &scheduler, &assets)
                })) {
                    Ok(result) => result,
                    Err(payload) => {
                        let error = worker_error(
                            device_id,
                            RecursionWorkerPhase::Panic,
                            panic_message(payload),
                        );
                        scheduler.cancel(error.to_string());
                        Err(error)
                    }
                }
            })
            .map_err(|err| {
                self.scheduler
                    .cancel(format!("failed to spawn recursion GPU {device_id}: {err}"));
                eyre!("failed to spawn recursion GPU {device_id}: {err}")
            })?;
        self.workers.push(worker);
        tracing::info!(
            target: "ceno_multi_gpu",
            device_id,
            active_recursion_workers = self.workers.len(),
            phase = "device_role_transition",
            "released base GPU started recursion work"
        );
        Ok(())
    }

    pub fn cancel(&self, error: impl Into<String>) {
        self.scheduler.cancel(error);
    }

    pub fn finish(mut self) -> Result<GpuRecursionBatchOutput> {
        let assets = self.resolve_assets()?;
        if self.workers.is_empty() {
            return Err(eyre!("no base GPU was released for recursion"));
        }
        let mut worker_metrics = Vec::with_capacity(self.workers.len());
        let mut worker_errors = Vec::new();
        for worker in self.workers.drain(..) {
            match worker.join() {
                Ok(Ok(metrics)) => worker_metrics.push(metrics),
                Ok(Err(err)) => worker_errors.push(err.to_string()),
                Err(payload) => {
                    worker_errors.push(format!("worker join panic: {}", panic_message(payload)))
                }
            }
        }
        if let Some(error) = self.scheduler.cancellation_error() {
            return Err(eyre!(error));
        }
        if !worker_errors.is_empty() {
            return Err(eyre!(worker_errors.join("; ")));
        }
        let root_proof = self
            .scheduler
            .take_root_proof()?
            .ok_or_else(|| eyre!("recursion workers exited without a root proof"))?;
        drop(self.scheduler.take_base_proofs()?);
        let root_vk = assets.root_vk().as_ref().clone();
        let first_device = *self
            .released_devices
            .iter()
            .min()
            .expect("at least one released device was checked");
        openvm_cuda_common::common::set_device_by_id(i32::try_from(first_device)?)?;
        let root_verification_started = Instant::now();
        verify_root_proof(&root_vk, &root_proof)?;
        let root_verification_time = root_verification_started.elapsed();
        worker_metrics.sort_by_key(|metrics| metrics.device_id);
        Ok(GpuRecursionBatchOutput {
            root_output: RootProvingOutput {
                root_vk,
                root_proof,
            },
            worker_metrics,
            root_verification_time,
        })
    }
}

fn register_released_device(released_devices: &mut HashSet<usize>, device_id: usize) -> Result<()> {
    if !released_devices.insert(device_id) {
        return Err(eyre!("recursion GPU device {device_id} was released twice"));
    }
    Ok(())
}

#[cfg(test)]
pub fn prove_batch_with_gpu_workers<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize>(
    child_vk: Arc<RecursionVk>,
    shard_proofs: Vec<RecursionProof>,
    options: AggregationOptions,
    device_ids: &[usize],
) -> Result<GpuRecursionBatchOutput> {
    if shard_proofs.is_empty() {
        return Err(eyre!("no shard proofs to aggregate"));
    }
    if device_ids.is_empty() {
        return Err(eyre!("at least one recursion GPU device is required"));
    }
    if device_ids.iter().copied().collect::<HashSet<_>>().len() != device_ids.len() {
        return Err(eyre!("recursion GPU device IDs must be unique"));
    }

    let mut session = GpuRecursionSession::<LEAF_FANIN, INTERNAL_FANIN>::new_with_assets_builder(
        shard_proofs.len(),
        RecursionHostAssetsBuilder::spawn(
            child_vk.clone(),
            crate::system::child_vk_digest(&child_vk),
            options,
        )?,
    )?;
    for (shard_id, proof) in shard_proofs.into_iter().enumerate() {
        session.accept_base_proof(shard_id, proof)?;
    }
    for &device_id in device_ids {
        session.release_device(device_id)?;
    }
    session.finish()
}

fn run_gpu_worker<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize>(
    device_id: usize,
    scheduler: &GpuScheduler,
    assets: &RecursionHostAssets<LEAF_FANIN, INTERNAL_FANIN>,
) -> std::result::Result<RecursionWorkerMetrics, RecursionWorkerError> {
    let cuda_device_id = i32::try_from(device_id).map_err(|_| {
        worker_error(
            device_id,
            RecursionWorkerPhase::Execute,
            "invalid CUDA device ID".to_string(),
        )
    })?;
    if let Err(err) = openvm_cuda_common::common::set_device_by_id(cuda_device_id) {
        let error = worker_error(device_id, RecursionWorkerPhase::Execute, err.to_string());
        scheduler.cancel(error.to_string());
        return Err(error);
    }

    let mut active = None;
    let result = catch_unwind(AssertUnwindSafe(|| {
        run_scheduler_worker(device_id, scheduler, |task, metrics| {
            execute_gpu_task(device_id, assets, &mut active, task, metrics)
        })
    }));
    let result = match result {
        Ok(result) => result,
        Err(payload) => {
            let error = worker_error(
                device_id,
                RecursionWorkerPhase::Panic,
                panic_message(payload),
            );
            scheduler.cancel(error.to_string());
            Err(error)
        }
    };
    drop(active);
    let trim_result = u32::try_from(device_id)
        .map_err(|_| "invalid CUDA device ID".to_string())
        .and_then(|device_id| {
            openvm_cuda_common::memory_manager::synchronize_and_trim_device(device_id)
                .map_err(|err| err.to_string())
        });
    match (result, trim_result) {
        (Ok(metrics), Ok(())) => Ok(metrics),
        (Err(error), _) => Err(error),
        (Ok(_), Err(message)) => {
            let error = worker_error(device_id, RecursionWorkerPhase::Teardown, message);
            scheduler.cancel(error.to_string());
            Err(error)
        }
    }
}

fn execute_gpu_task<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize>(
    device_id: usize,
    assets: &RecursionHostAssets<LEAF_FANIN, INTERNAL_FANIN>,
    active: &mut Option<(
        RecursionNodeKind,
        GpuRecursionProver<LEAF_FANIN, INTERNAL_FANIN>,
    )>,
    task: RecursionTask<RecursionProof, InternalProof>,
    metrics: &mut RecursionWorkerMetrics,
) -> Result<RecursionTaskResult<RecursionProof, InternalProof, RootProof>> {
    let kind = task.node().kind;
    if active.as_ref().map(|(active_kind, _)| *active_kind) != Some(kind) {
        if active.take().is_some() {
            // Proving keys are device-local. Finish and release the previous circuit kind before
            // hydrating the next one so allocations never cross contexts or overlap peak pools.
            openvm_cuda_common::memory_manager::synchronize_and_trim_device(u32::try_from(
                device_id,
            )?)?;
            metrics.asset_switches += 1;
        }
        let hydration_started = Instant::now();
        *active = Some((kind, assets.hydrate_gpu_on(device_id, kind)?));
        metrics.hydration_time += hydration_started.elapsed();
        metrics.asset_hydrations += 1;
    }
    let prover = &active.as_ref().expect("active prover was just hydrated").1;
    Ok(match (task, prover) {
        (RecursionTask::Leaf { node, proofs }, GpuRecursionProver::Leaf(prover)) => {
            let proof =
                prover.agg_prove_no_def::<BabyBearPoseidon2GpuEngine>(&proofs, ChildVkKind::App)?;
            RecursionTaskResult::Leaf {
                node: node.id,
                proof,
                base_proofs: proofs,
            }
        }
        (RecursionTask::Intermediate { node, proofs }, GpuRecursionProver::LeafBridge(prover))
            if node.kind == RecursionNodeKind::LeafBridge =>
        {
            RecursionTaskResult::Intermediate {
                node: node.id,
                proof: prover.prove(&proofs)?,
            }
        }
        (RecursionTask::Intermediate { node, proofs }, GpuRecursionProver::Recursive(prover))
            if matches!(node.kind, RecursionNodeKind::Recursive { .. }) =>
        {
            RecursionTaskResult::Intermediate {
                node: node.id,
                proof: prover.prove(&proofs)?,
            }
        }
        (RecursionTask::Root { node, proof }, GpuRecursionProver::Root(prover)) => {
            RecursionTaskResult::Root {
                node: node.id,
                proof: RootProof {
                    proof: prover.prove(proof)?,
                },
            }
        }
        (task, _) => {
            return Err(eyre!(
                "hydrated prover does not match {:?}",
                task.node().kind
            ));
        }
    })
}

fn worker_error(
    device_id: usize,
    phase: RecursionWorkerPhase,
    message: String,
) -> RecursionWorkerError {
    RecursionWorkerError {
        device_id,
        node: None,
        phase,
        message,
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic payload".to_string())
}

#[cfg(test)]
mod tests {
    use super::register_released_device;
    use std::collections::HashSet;

    #[test]
    fn duplicate_device_release_is_rejected() {
        let mut released = HashSet::new();
        register_released_device(&mut released, 7).unwrap();
        let error = register_released_device(&mut released, 7)
            .unwrap_err()
            .to_string();
        assert!(error.contains("released twice"));
        assert_eq!(released, HashSet::from([7]));
    }
}
