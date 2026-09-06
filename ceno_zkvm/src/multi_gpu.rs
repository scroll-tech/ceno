use std::{collections::HashSet, sync::Arc};

pub use ceno_gpu::device::discover_cuda_devices;
use ceno_gpu::{
    CudaHal,
    bb31::CudaHalBB31,
    device::{CudaDeviceInfo, EmbeddedFatbinVariant},
};

const FIXED_BUFFER_BYTES: usize = 512 * 1024 * 1024;
const SHARD_CELL_BYTES: usize = std::mem::size_of::<u32>();

fn conservative_shard_cap(
    usable_memory_bytes: impl IntoIterator<Item = usize>,
) -> Result<u64, String> {
    usable_memory_bytes
        .into_iter()
        .map(|usable| {
            usable
                .checked_sub(FIXED_BUFFER_BYTES)
                .map(|bytes| (bytes / SHARD_CELL_BYTES) as u64)
                .ok_or_else(|| {
                    "GPU has insufficient usable memory for fixed prover buffers".to_owned()
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min()
        .ok_or_else(|| "GPU device list must not be empty".to_owned())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShardAssignmentPolicy {
    #[default]
    RoundRobin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiGpuConfig {
    pub device_ids: Vec<usize>,
    pub shard_policy: ShardAssignmentPolicy,
    pub replay_queue_depth: usize,
    pub recursion_device: usize,
    /// Exclusive logical CPU sets, one per selected GPU worker.
    pub worker_cpu_affinity: Option<Vec<Vec<usize>>>,
}

impl MultiGpuConfig {
    pub fn new(device_ids: Vec<usize>) -> Result<Self, String> {
        let recursion_device = *device_ids
            .first()
            .ok_or("GPU device list must not be empty")?;
        let config = Self {
            device_ids,
            shard_policy: ShardAssignmentPolicy::RoundRobin,
            replay_queue_depth: 1,
            recursion_device,
            worker_cpu_affinity: None,
        };
        config.validate_shape()?;
        Ok(config)
    }

    pub fn with_recursion_device(mut self, device_id: usize) -> Result<Self, String> {
        self.recursion_device = device_id;
        self.validate_shape()?;
        Ok(self)
    }

    pub fn with_worker_cpu_affinity(
        mut self,
        worker_cpu_affinity: Vec<Vec<usize>>,
    ) -> Result<Self, String> {
        self.worker_cpu_affinity = Some(worker_cpu_affinity);
        self.validate_shape()?;
        Ok(self)
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if self.device_ids.is_empty() {
            return Err("GPU device list must not be empty".to_owned());
        }
        if self.replay_queue_depth != 1 {
            return Err("Stage 1 requires replay_queue_depth=1".to_owned());
        }
        let mut unique = HashSet::with_capacity(self.device_ids.len());
        for device_id in &self.device_ids {
            if !unique.insert(*device_id) {
                return Err(format!("duplicate GPU device {device_id}"));
            }
        }
        if !unique.contains(&self.recursion_device) {
            return Err(format!(
                "recursion GPU {} is not in the selected device list",
                self.recursion_device
            ));
        }
        if let Some(affinity) = &self.worker_cpu_affinity {
            if affinity.len() != self.device_ids.len() {
                return Err(format!(
                    "GPU worker CPU affinity has {} entries, expected {}",
                    affinity.len(),
                    self.device_ids.len()
                ));
            }
            let mut assigned = HashSet::new();
            for (worker, cpus) in affinity.iter().enumerate() {
                if cpus.is_empty() {
                    return Err(format!("GPU worker {worker} CPU set must not be empty"));
                }
                for cpu in cpus {
                    if !assigned.insert(*cpu) {
                        return Err(format!(
                            "logical CPU {cpu} appears in more than one exclusive GPU worker set"
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn owner_index(&self, shard_id: usize) -> usize {
        match self.shard_policy {
            ShardAssignmentPolicy::RoundRobin => shard_id % self.device_ids.len(),
        }
    }

    pub fn prepare(&self, requested_max_cells: u64) -> Result<PreparedMultiGpu, String> {
        self.validate_shape()?;
        if let Some(affinity) = &self.worker_cpu_affinity {
            validate_worker_cpu_affinity(affinity, &available_logical_cpus()?)?;
        }
        let discovered = discover_cuda_devices().map_err(|error| error.to_string())?;
        let (selected, max_cell_per_shard) =
            self.validate_device_profiles(&discovered, requested_max_cells)?;
        let mut workers = Vec::with_capacity(self.device_ids.len());
        for (device_id, info) in self.device_ids.iter().zip(selected) {
            tracing::info!(
                device_id = info.logical_ordinal,
                model = %info.name,
                compute_capability = ?info.compute_capability,
                total_memory_bytes = info.total_memory_bytes,
                free_memory_bytes = info.free_memory_bytes,
                usable_memory_bytes = info.usable_memory_bytes,
                memory_pool_supported = info.memory_pool_supported,
                concurrent_kernels_supported = info.concurrent_kernels_supported,
                peer_access = ?info.peer_access,
                embedded_fatbin_variant = ?info.embedded_fatbin_variant,
                runtime_safety_headroom_bytes = ceno_gpu::device::DEVICE_MEMORY_HEADROOM_BYTES,
                fixed_buffer_bytes = FIXED_BUFFER_BYTES,
                "selected CUDA device profile"
            );
            let hal = Arc::new(CudaHalBB31::new(*device_id).map_err(|error| {
                format!("failed to construct HAL for GPU device {device_id}: {error}")
            })?);
            hal.inner().synchronize().map_err(|error| {
                format!("failed HAL smoke test for GPU device {device_id}: {error}")
            })?;
            workers.push(PreparedGpu { info, hal });
        }
        Ok(PreparedMultiGpu {
            workers,
            max_cell_per_shard,
        })
    }

    fn validate_device_profiles(
        &self,
        discovered: &[CudaDeviceInfo],
        requested_max_cells: u64,
    ) -> Result<(Vec<CudaDeviceInfo>, u64), String> {
        self.validate_shape()?;
        let mut selected = Vec::with_capacity(self.device_ids.len());
        for device_id in &self.device_ids {
            let info = discovered.get(*device_id).ok_or_else(|| {
                format!(
                    "GPU device {device_id} is out of range 0..{}",
                    discovered.len()
                )
            })?;
            if info.logical_ordinal != *device_id {
                return Err(format!(
                    "GPU discovery profile at index {device_id} reports logical ordinal {}",
                    info.logical_ordinal
                ));
            }
            if !info.memory_pool_supported || !info.concurrent_kernels_supported {
                return Err(format!(
                    "GPU device {device_id} lacks required memory-pool or concurrent-stream support"
                ));
            }
            if matches!(
                info.embedded_fatbin_variant,
                EmbeddedFatbinVariant::Unsupported
            ) {
                return Err(format!(
                    "GPU device {device_id} compute capability {}.{} is unsupported by embedded architectures {}",
                    info.compute_capability.0,
                    info.compute_capability.1,
                    ceno_gpu::device::PACKAGED_CUDA_ARCHES,
                ));
            }
            selected.push(info.clone());
        }
        let common_max_cells =
            conservative_shard_cap(selected.iter().map(|info| info.usable_memory_bytes))?;
        let max_cell_per_shard = if requested_max_cells == u64::MAX {
            common_max_cells
        } else if requested_max_cells > common_max_cells {
            return Err(format!(
                "requested max_cell_per_shard {requested_max_cells} exceeds conservative multi-GPU cap {common_max_cells}"
            ));
        } else {
            requested_max_cells
        };
        tracing::info!(
            conservative_max_cell_per_shard = common_max_cells,
            selected_max_cell_per_shard = max_cell_per_shard,
            "conservative multi-GPU shard cap"
        );
        Ok((selected, max_cell_per_shard))
    }
}

pub fn parse_worker_cpu_affinity(values: &[String]) -> Result<Option<Vec<Vec<usize>>>, String> {
    if values.is_empty() {
        return Ok(None);
    }
    values
        .iter()
        .enumerate()
        .map(|(worker, value)| {
            if value.is_empty() {
                return Err(format!("GPU worker {worker} CPU set must not be empty"));
            }
            value
                .split(',')
                .map(|cpu| {
                    cpu.parse::<usize>()
                        .map_err(|_| format!("invalid logical CPU {cpu:?} for GPU worker {worker}"))
                })
                .collect()
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn validate_worker_cpu_affinity(
    affinity: &[Vec<usize>],
    available: &[usize],
) -> Result<(), String> {
    let available = available.iter().copied().collect::<HashSet<_>>();
    for (worker, cpus) in affinity.iter().enumerate() {
        for cpu in cpus {
            if !available.contains(cpu) {
                return Err(format!(
                    "logical CPU {cpu} for GPU worker {worker} is unavailable to this process"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn available_logical_cpus() -> Result<Vec<usize>, String> {
    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) } != 0 {
        return Err(format!(
            "failed to query logical CPU affinity: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((0..libc::CPU_SETSIZE as usize)
        .filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &set) })
        .collect())
}

#[cfg(not(target_os = "linux"))]
pub fn available_logical_cpus() -> Result<Vec<usize>, String> {
    Err("GPU worker CPU affinity is supported only on Linux".to_owned())
}

#[cfg(target_os = "linux")]
pub(crate) fn pin_current_thread(cpus: &[usize]) -> Result<Vec<usize>, String> {
    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    unsafe { libc::CPU_ZERO(&mut set) };
    for cpu in cpus {
        unsafe { libc::CPU_SET(*cpu, &mut set) };
    }
    if unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) } != 0 {
        return Err(format!(
            "failed to pin current thread to CPUs {cpus:?}: {}",
            std::io::Error::last_os_error()
        ));
    }
    available_logical_cpus()
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn pin_current_thread(_cpus: &[usize]) -> Result<Vec<usize>, String> {
    Err("GPU worker CPU affinity is supported only on Linux".to_owned())
}

pub struct PreparedGpu {
    pub info: CudaDeviceInfo,
    pub hal: Arc<CudaHalBB31>,
}

pub struct PreparedMultiGpu {
    pub workers: Vec<PreparedGpu>,
    pub max_cell_per_shard: u64,
}

pub fn select_device_ids(
    explicit: Option<&[usize]>,
    count: Option<usize>,
    available: usize,
) -> Result<Vec<usize>, String> {
    let selected = if let Some(explicit) = explicit {
        if explicit.is_empty() {
            return Err("GPU device list must not be empty".to_owned());
        }
        explicit.to_vec()
    } else if let Some(count) = count {
        if count == 0 {
            return Err("GPU count must be greater than zero".to_owned());
        }
        (0..count).collect()
    } else {
        vec![0]
    };
    if let Some(device_id) = selected.iter().find(|device_id| **device_id >= available) {
        return Err(format!(
            "GPU device {device_id} is out of range 0..{available}"
        ));
    }
    MultiGpuConfig::new(selected.clone())?;
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(
        logical_ordinal: usize,
        usable_memory_bytes: usize,
        memory_pool_supported: bool,
        concurrent_kernels_supported: bool,
        embedded_fatbin_variant: EmbeddedFatbinVariant,
    ) -> CudaDeviceInfo {
        CudaDeviceInfo {
            logical_ordinal,
            name: format!("synthetic-{logical_ordinal}"),
            compute_capability: (8, 9),
            total_memory_bytes: usable_memory_bytes
                + ceno_gpu::device::DEVICE_MEMORY_HEADROOM_BYTES,
            free_memory_bytes: usable_memory_bytes + ceno_gpu::device::DEVICE_MEMORY_HEADROOM_BYTES,
            usable_memory_bytes,
            memory_pool_supported,
            concurrent_kernels_supported,
            peer_access: vec![true],
            embedded_fatbin_variant,
        }
    }

    #[test]
    fn device_selection_precedence() {
        assert_eq!(
            select_device_ids(Some(&[2, 0]), Some(1), 3).unwrap(),
            vec![2, 0]
        );
        assert_eq!(select_device_ids(None, Some(2), 3).unwrap(), vec![0, 1]);
        assert_eq!(select_device_ids(None, None, 3).unwrap(), vec![0]);
    }

    #[test]
    fn invalid_device_selections() {
        assert!(select_device_ids(Some(&[]), None, 2).is_err());
        assert!(select_device_ids(Some(&[0, 0]), None, 2).is_err());
        assert!(select_device_ids(Some(&[2]), None, 2).is_err());
        assert!(select_device_ids(None, Some(0), 2).is_err());
    }

    #[test]
    fn round_robin_coverage() {
        let config = MultiGpuConfig::new(vec![4, 7]).unwrap();
        assert_eq!(
            (0..6).map(|id| config.owner_index(id)).collect::<Vec<_>>(),
            vec![0, 1, 0, 1, 0, 1]
        );
    }

    #[test]
    fn recursion_device_must_be_selected() {
        assert!(
            MultiGpuConfig::new(vec![0, 1])
                .unwrap()
                .with_recursion_device(2)
                .is_err()
        );
    }

    #[test]
    fn worker_cpu_affinity_is_exclusive_and_matches_workers() {
        let valid = MultiGpuConfig::new(vec![0, 1])
            .unwrap()
            .with_worker_cpu_affinity(vec![vec![2, 3], vec![4]])
            .unwrap();
        assert_eq!(valid.worker_cpu_affinity, Some(vec![vec![2, 3], vec![4]]));
        assert!(
            MultiGpuConfig::new(vec![0, 1])
                .unwrap()
                .with_worker_cpu_affinity(vec![vec![2]])
                .is_err()
        );
        assert!(
            MultiGpuConfig::new(vec![0, 1])
                .unwrap()
                .with_worker_cpu_affinity(vec![vec![2], vec![2]])
                .is_err()
        );
        assert!(
            MultiGpuConfig::new(vec![0])
                .unwrap()
                .with_worker_cpu_affinity(vec![vec![]])
                .is_err()
        );
        assert!(validate_worker_cpu_affinity(&[vec![7]], &[2, 3, 4]).is_err());
    }

    #[test]
    fn worker_cpu_affinity_cli_shape_parses_repeated_sets() {
        assert_eq!(
            parse_worker_cpu_affinity(&["2,3".to_owned(), "4".to_owned()]).unwrap(),
            Some(vec![vec![2, 3], vec![4]])
        );
        assert!(parse_worker_cpu_affinity(&["2,x".to_owned()]).is_err());
        assert_eq!(parse_worker_cpu_affinity(&[]).unwrap(), None);
    }

    #[test]
    fn conservative_cap_uses_least_capable_device() {
        let gib = 1024 * 1024 * 1024;
        assert_eq!(
            conservative_shard_cap([16 * gib, 8 * gib]).unwrap(),
            ((8 * gib - FIXED_BUFFER_BYTES) / SHARD_CELL_BYTES) as u64
        );
        assert!(conservative_shard_cap([FIXED_BUFFER_BYTES - 1]).is_err());
    }

    #[test]
    fn synthetic_profiles_use_least_device_and_reject_unsupported_capabilities() {
        let gib = 1024 * 1024 * 1024;
        let config = MultiGpuConfig::new(vec![0, 1]).unwrap();
        let profiles = vec![
            profile(0, 16 * gib, true, true, EmbeddedFatbinVariant::Sass(89)),
            profile(1, 8 * gib, true, true, EmbeddedFatbinVariant::Sass(89)),
        ];
        let (_, cap) = config
            .validate_device_profiles(&profiles, u64::MAX)
            .unwrap();
        assert_eq!(
            cap,
            ((8 * gib - FIXED_BUFFER_BYTES) / SHARD_CELL_BYTES) as u64
        );
        assert!(config.validate_device_profiles(&profiles, cap + 1).is_err());

        let mut unsupported = profiles.clone();
        unsupported[1].embedded_fatbin_variant = EmbeddedFatbinVariant::Unsupported;
        assert!(
            config
                .validate_device_profiles(&unsupported, 1)
                .unwrap_err()
                .contains("unsupported by embedded architectures")
        );
        let mut missing_stream_support = profiles;
        missing_stream_support[0].concurrent_kernels_supported = false;
        assert!(
            config
                .validate_device_profiles(&missing_stream_support, 1)
                .unwrap_err()
                .contains("lacks required memory-pool or concurrent-stream support")
        );
    }
}
