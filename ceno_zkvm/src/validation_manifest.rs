//! Opt-in, deterministic witness manifests used to compare independent runs.
//!
//! This module is deliberately private and cold: when
//! `CENO_VALIDATION_MANIFEST_DIR` is absent, callers retain no configuration
//! and do no hashing, device synchronization, D2H, or filesystem work.

use crate::{e2e::ShardContext, scheme::PublicValues, structs::ZKVMWitnesses};
use ff_ext::{ExtensionField, SmallField};
#[cfg(feature = "gpu")]
use std::ffi::OsString;
use std::{
    env,
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use tiny_keccak::{Hasher, Keccak};
use witness::{DeviceMatrixLayout, RowMajorMatrix};

const MANIFEST_ENV: &str = "CENO_VALIDATION_MANIFEST_DIR";
#[cfg(feature = "gpu")]
const POST_WITGEN_MEM_ENV: &str = "CENO_GPU_LOG_POST_WITGEN_MEM";
const MAGIC: &[u8] = b"CENO_VALIDATION_MANIFEST\0";
const SCHEMA_VERSION: u32 = 1;
#[cfg(feature = "gpu")]
const MIN_VALIDATION_FREE_VRAM: usize = 1 << 30;

const SHARD_RAM_NAME: &str = "ShardRamCircuit";
const CONTINUATION_NAMES: &[&str] = &[
    "LocalRAMTableFinal",
    "ShardRamCircuit",
    "ShardRamEcTreeCircuit",
    "ECALL_STATE_CONTINUATION",
];

#[derive(Clone, Debug)]
pub(crate) struct ValidationManifestConfig {
    output_dir: PathBuf,
}

#[derive(Debug)]
pub(crate) struct ManifestError(String);

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ManifestError {}

impl From<io::Error> for ManifestError {
    fn from(value: io::Error) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug)]
pub(crate) struct ManifestReport {
    pub path: PathBuf,
    pub root_digest: [u8; 32],
    pub matrix_count: u64,
    pub lookup_entry_count: u64,
    pub address_count: u64,
    pub elapsed_millis: u128,
}

impl ValidationManifestConfig {
    pub(crate) fn from_env() -> Result<Option<Self>, ManifestError> {
        let Some(raw) = env::var_os(MANIFEST_ENV) else {
            return Ok(None);
        };
        if raw.is_empty() {
            return Err(ManifestError(format!("{MANIFEST_ENV} must not be empty")));
        }
        let output_dir = PathBuf::from(raw);
        fs::create_dir_all(&output_dir).map_err(|err| {
            ManifestError(format!(
                "failed to create validation manifest directory {}: {err}",
                output_dir.display()
            ))
        })?;
        if !output_dir.is_dir() {
            return Err(ManifestError(format!(
                "validation manifest path is not a directory: {}",
                output_dir.display()
            )));
        }
        Ok(Some(Self { output_dir }))
    }

    pub(crate) fn with_enabled<T>(
        config: Option<&Self>,
        action: impl FnOnce(&Self) -> T,
    ) -> Option<T> {
        config.map(action)
    }
}

#[cfg(feature = "gpu")]
pub(crate) fn post_witgen_memory_enabled(validation_enabled: bool) -> bool {
    validation_enabled || env_flag(POST_WITGEN_MEM_ENV)
}

#[cfg(feature = "gpu")]
fn env_flag(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| value != OsString::from("0") && !value.is_empty())
}

#[cfg(feature = "gpu")]
pub(crate) fn log_post_witgen_vram(
    shard_id: usize,
    enforce_validation_minimum: bool,
) -> Result<(), ManifestError> {
    use gkr_iop::gpu::get_cuda_hal;

    let hal =
        get_cuda_hal().map_err(|err| ManifestError(format!("CUDA HAL unavailable: {err}")))?;
    hal.inner
        .synchronize()
        .map_err(|err| ManifestError(format!("post-witgen CUDA synchronization failed: {err}")))?;
    let (free_bytes, total_bytes) = ceno_gpu::get_cuda_mem_info()
        .map_err(|err| ManifestError(format!("cudaMemGetInfo failed: {err}")))?;
    let used_bytes = total_bytes.saturating_sub(free_bytes);
    tracing::info!(
        target: "ceno_validation",
        shard_id,
        free_bytes,
        total_bytes,
        used_bytes,
        "synchronized post-witgen CUDA memory headroom"
    );
    if enforce_validation_minimum && free_bytes < MIN_VALIDATION_FREE_VRAM {
        return Err(ManifestError(format!(
            "validation shard {shard_id} has only {free_bytes} free CUDA bytes; at least {MIN_VALIDATION_FREE_VRAM} required"
        )));
    }
    Ok(())
}

pub(crate) fn write_shard<E: ExtensionField>(
    config: &ValidationManifestConfig,
    shard_id: usize,
    witnesses: &ZKVMWitnesses<E>,
    shard_ctx: &ShardContext<'_>,
    public_values: &PublicValues,
) -> Result<ManifestReport, ManifestError> {
    let start = Instant::now();
    let mut sections = Vec::with_capacity(7);

    sections.push(section("public_values", |out| {
        encode_public_values(out, public_values)
    })?);

    let lookup_tables = witnesses.combined_lk_mlt().ok_or_else(|| {
        ManifestError("validation manifest requested before lookup finalization".into())
    })?;
    let lookup_entry_count = lookup_tables.iter().map(|table| table.len() as u64).sum();
    sections.push(section("lookup_multiplicities", |out| {
        out.u32(lookup_tables.len())?;
        for table in lookup_tables {
            let mut entries: Vec<_> = table.iter().map(|(&key, &value)| (key, value)).collect();
            entries.sort_unstable_by_key(|&(key, _)| key);
            out.u64(entries.len())?;
            let total = entries.iter().try_fold(0u64, |total, &(_, value)| {
                total
                    .checked_add(value as u64)
                    .ok_or_else(|| ManifestError("lookup multiplicity total overflow".into()))
            })?;
            out.u64(total)?;
            for (key, value) in entries {
                out.u64(key)?;
                out.u64(value)?;
            }
        }
        Ok(())
    })?);

    let mut addresses: Vec<u32> = shard_ctx
        .get_addr_accessed()
        .into_iter()
        .map(Into::into)
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    let address_count = addresses.len() as u64;
    sections.push(section("accessed_addresses", |out| {
        encode_addresses(out, &addresses)
    })?);

    let matrix_count = count_matrices(witnesses, |_| true);
    sections.push(section("witness_matrices", |out| {
        encode_matrices(out, witnesses, |_| true)
    })?);
    sections.push(section("ordered_shard_ram", |out| {
        encode_matrices(out, witnesses, |name| name == SHARD_RAM_NAME)
    })?);
    sections.push(section("continuation_matrices", |out| {
        encode_matrices(out, witnesses, |name| CONTINUATION_NAMES.contains(&name))
    })?);
    sections.push(section("final_continuation_state", |out| {
        encode_final_continuation(out, public_values)
    })?);

    let (canonical, root_digest) = encode_manifest_summary(&sections)?;
    let final_path = config
        .output_dir
        .join(format!("shard-{shard_id:06}.manifest"));
    publish_atomic_no_replace(&final_path, &canonical)?;

    Ok(ManifestReport {
        path: final_path,
        root_digest,
        matrix_count,
        lookup_entry_count,
        address_count,
        elapsed_millis: start.elapsed().as_millis(),
    })
}

struct SectionSummary {
    tag: &'static str,
    payload_len: u64,
    digest: [u8; 32],
}

struct DigestEncoder {
    hasher: Keccak,
    len: u64,
}

impl DigestEncoder {
    fn new() -> Self {
        Self {
            hasher: Keccak::v256(),
            len: 0,
        }
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), ManifestError> {
        self.len = self
            .len
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| ManifestError("validation section length overflow".into()))?;
        self.hasher.update(bytes);
        Ok(())
    }

    fn u32(&mut self, value: impl TryInto<u32>) -> Result<(), ManifestError> {
        let value = value
            .try_into()
            .map_err(|_| ManifestError("validation value does not fit u32".into()))?;
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: impl TryInto<u64>) -> Result<(), ManifestError> {
        let value = value
            .try_into()
            .map_err(|_| ManifestError("validation value does not fit u64".into()))?;
        self.bytes(&value.to_le_bytes())
    }

    fn string(&mut self, value: &str) -> Result<(), ManifestError> {
        self.u32(value.len())?;
        self.bytes(value.as_bytes())
    }

    fn finish(self) -> (u64, [u8; 32]) {
        let mut digest = [0u8; 32];
        self.hasher.finalize(&mut digest);
        (self.len, digest)
    }
}

fn section(
    tag: &'static str,
    encode: impl FnOnce(&mut DigestEncoder) -> Result<(), ManifestError>,
) -> Result<SectionSummary, ManifestError> {
    let mut out = DigestEncoder::new();
    encode(&mut out)?;
    let (payload_len, digest) = out.finish();
    Ok(SectionSummary {
        tag,
        payload_len,
        digest,
    })
}

fn encode_manifest_summary(
    sections: &[SectionSummary],
) -> Result<(Vec<u8>, [u8; 32]), ManifestError> {
    let mut bytes = Vec::with_capacity(128 + sections.len() * 80);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(sections.len())
            .map_err(|_| ManifestError("too many manifest sections".into()))?
            .to_le_bytes(),
    );
    for section in sections {
        bytes.extend_from_slice(
            &u32::try_from(section.tag.len())
                .map_err(|_| ManifestError("manifest section tag too long".into()))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(section.tag.as_bytes());
        bytes.extend_from_slice(&section.payload_len.to_le_bytes());
        bytes.extend_from_slice(&section.digest);
    }
    let root_digest = keccak256(&bytes);
    bytes.extend_from_slice(b"root_digest");
    bytes.extend_from_slice(&root_digest);
    Ok((bytes, root_digest))
}

fn encode_public_values(out: &mut DigestEncoder, pi: &PublicValues) -> Result<(), ManifestError> {
    out.u32(pi.exit_code)?;
    out.u32(pi.init_pc)?;
    out.u64(pi.init_cycle)?;
    out.u32(pi.end_pc)?;
    out.u64(pi.end_cycle)?;
    out.u32(pi.shard_id)?;
    out.u32(pi.heap_start_addr)?;
    out.u32(pi.heap_shard_len)?;
    out.u32(pi.hint_start_addr)?;
    out.u32(pi.hint_shard_len)?;
    for word in pi.public_io_digest {
        out.u32(word)?;
    }
    for word in pi.shard_rw_sum {
        out.u32(word)?;
    }
    Ok(())
}

fn encode_final_continuation(
    out: &mut DigestEncoder,
    pi: &PublicValues,
) -> Result<(), ManifestError> {
    let heap_end = pi
        .heap_shard_len
        .checked_mul(4)
        .and_then(|len| pi.heap_start_addr.checked_add(len))
        .ok_or_else(|| ManifestError("heap continuation end overflow".into()))?;
    let hint_end = pi
        .hint_shard_len
        .checked_mul(4)
        .and_then(|len| pi.hint_start_addr.checked_add(len))
        .ok_or_else(|| ManifestError("hint continuation end overflow".into()))?;
    out.u32(pi.end_pc)?;
    out.u64(pi.end_cycle)?;
    out.u32(heap_end)?;
    out.u32(hint_end)?;
    for word in pi.shard_rw_sum {
        out.u32(word)?;
    }
    Ok(())
}

fn encode_addresses(out: &mut DigestEncoder, addresses: &[u32]) -> Result<(), ManifestError> {
    let mut canonical = addresses.to_vec();
    canonical.sort_unstable();
    canonical.dedup();
    out.u64(canonical.len())?;
    for address in canonical {
        out.u32(address)?;
    }
    Ok(())
}

fn count_matrices<E: ExtensionField>(
    witnesses: &ZKVMWitnesses<E>,
    include: impl Fn(&str) -> bool,
) -> u64 {
    witnesses
        .witnesses
        .iter()
        .filter(|(name, _)| include(name))
        .map(|(_, inputs)| inputs.len() as u64 * 2)
        .sum()
}

fn encode_matrices<E: ExtensionField>(
    out: &mut DigestEncoder,
    witnesses: &ZKVMWitnesses<E>,
    include: impl Fn(&str) -> bool,
) -> Result<(), ManifestError> {
    let chips: Vec<_> = witnesses
        .witnesses
        .iter()
        .filter(|(name, _)| include(name))
        .collect();
    out.u32(chips.len())?;
    for (chip_name, inputs) in chips {
        out.string(chip_name)?;
        out.u64(inputs.len())?;
        for input in inputs {
            out.string(&input.name)?;
            out.u64(input.num_instances[0])?;
            out.u64(input.num_instances[1])?;
            for (role, rmm) in input.witness_rmms.iter().enumerate() {
                encode_matrix(out, role, rmm)?;
            }
        }
    }
    Ok(())
}

fn encode_matrix<F: SmallField + 'static>(
    out: &mut DigestEncoder,
    role: usize,
    matrix: &RowMajorMatrix<F>,
) -> Result<(), ManifestError> {
    out.u32(role)?;
    out.u64(matrix.num_instances())?;
    out.u64(matrix.occupied_physical_rows())?;
    out.u64(matrix.height())?;
    out.u64(matrix.width())?;

    match matrix.device_backing_layout() {
        None => {
            let values = matrix.values();
            let expected = matrix.height().checked_mul(matrix.width()).ok_or_else(|| {
                ManifestError("host validation matrix dimensions overflow".into())
            })?;
            if values.len() != expected {
                return Err(ManifestError(format!(
                    "host validation matrix has {} values, expected {expected}",
                    values.len()
                )));
            }
            for col in 0..matrix.width() {
                for row in 0..matrix.height() {
                    out.u64(values[row * matrix.width() + col].to_canonical_u64())?;
                }
            }
            Ok(())
        }
        Some(DeviceMatrixLayout::RowMajor) => Err(ManifestError(
            "row-major device-backed validation matrices are unsupported".into(),
        )),
        Some(DeviceMatrixLayout::ColMajor) => encode_col_major_device_matrix(out, matrix),
    }
}

#[cfg(any(feature = "gpu", test))]
fn encode_col_major_values<F: SmallField>(
    out: &mut DigestEncoder,
    values: &[F],
    present_rows: usize,
    padded_height: usize,
    width: usize,
) -> Result<(), ManifestError> {
    if present_rows > padded_height {
        return Err(ManifestError(format!(
            "validation matrix has {present_rows} present rows but padded height is {padded_height}"
        )));
    }
    let expected = present_rows
        .checked_mul(width)
        .ok_or_else(|| ManifestError("validation matrix dimensions overflow".into()))?;
    if values.len() != expected {
        return Err(ManifestError(format!(
            "validation matrix has {} values, expected {expected}",
            values.len()
        )));
    }
    for col in 0..width {
        let start = col
            .checked_mul(present_rows)
            .ok_or_else(|| ManifestError("validation column offset overflow".into()))?;
        let end = start
            .checked_add(present_rows)
            .ok_or_else(|| ManifestError("validation column end overflow".into()))?;
        for value in &values[start..end] {
            out.u64(value.to_canonical_u64())?;
        }
        for _ in present_rows..padded_height {
            out.u64(F::default().to_canonical_u64())?;
        }
    }
    Ok(())
}

#[cfg(feature = "gpu")]
fn encode_col_major_device_matrix<F: SmallField + 'static>(
    out: &mut DigestEncoder,
    matrix: &RowMajorMatrix<F>,
) -> Result<(), ManifestError> {
    use ceno_gpu::{Buffer, common::buffer::BufferImpl};
    use p3::babybear::BabyBear;
    use std::any::TypeId;

    if TypeId::of::<F>() != TypeId::of::<BabyBear>() {
        return Err(ManifestError(
            "GPU validation manifests only support BabyBear witness matrices".into(),
        ));
    }
    let device = matrix
        .device_backing_ref::<BufferImpl<'static, BabyBear>>()
        .ok_or_else(|| ManifestError("col-major device backing type mismatch".into()))?;
    let full_len = matrix
        .height()
        .checked_mul(matrix.width())
        .ok_or_else(|| ManifestError("device validation matrix dimensions overflow".into()))?;
    let compact_len = matrix
        .occupied_physical_rows()
        .checked_mul(matrix.width())
        .ok_or_else(|| {
            ManifestError("compact device validation matrix dimensions overflow".into())
        })?;
    let present_rows = match device.len() {
        len if len == full_len => matrix.height(),
        len if len == compact_len => matrix.occupied_physical_rows(),
        len => {
            return Err(ManifestError(format!(
                "device validation matrix has {len} values, expected full {full_len} or compact {compact_len}"
            )));
        }
    };
    if present_rows > matrix.height() {
        return Err(ManifestError(format!(
            "device validation matrix has {present_rows} present rows but padded height is {}",
            matrix.height()
        )));
    }
    let column_bytes = present_rows
        .checked_mul(std::mem::size_of::<BabyBear>())
        .ok_or_else(|| ManifestError("device validation column byte length overflow".into()))?;
    for col in 0..matrix.width() {
        let start = col
            .checked_mul(column_bytes)
            .ok_or_else(|| ManifestError("device validation column byte offset overflow".into()))?;
        let end = start
            .checked_add(column_bytes)
            .ok_or_else(|| ManifestError("device validation column byte end overflow".into()))?;
        let values = device
            .owned_subrange(start..end)
            .to_vec()
            .map_err(|err| ManifestError(format!("validation matrix D2H failed: {err}")))?;
        encode_col_major_values(out, &values, present_rows, matrix.height(), 1)?;
    }
    Ok(())
}

#[cfg(not(feature = "gpu"))]
fn encode_col_major_device_matrix<F: SmallField + 'static>(
    _out: &mut DigestEncoder,
    _matrix: &RowMajorMatrix<F>,
) -> Result<(), ManifestError> {
    Err(ManifestError(
        "device-backed validation matrix requires the gpu feature".into(),
    ))
}

fn publish_atomic_no_replace(final_path: &Path, bytes: &[u8]) -> Result<(), ManifestError> {
    if final_path.exists() {
        return Err(ManifestError(format!(
            "refusing to overwrite validation manifest {}",
            final_path.display()
        )));
    }
    let file_name = final_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ManifestError("invalid validation manifest filename".into()))?;
    let temp_path = final_path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    let result = (|| -> Result<(), ManifestError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temp_path, final_path).map_err(|err| {
            ManifestError(format!(
                "failed to publish validation manifest {} without replacement: {err}",
                final_path.display()
            ))
        })?;
        Ok(())
    })();
    let _ = fs::remove_file(&temp_path);
    result
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0; 32];
    hasher.finalize(&mut digest);
    digest
}

pub(crate) fn hex_digest(digest: &[u8; 32]) -> String {
    let mut result = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::GlobalState,
        tables::{LocalFinalCircuit, ShardRamCircuit, ShardRamEcTreeCircuit, TableCircuit},
    };
    use ff_ext::BabyBearExt4;
    use p3::field::PrimeCharacteristicRing;
    use rustc_hash::FxHashMap;
    use witness::InstancePaddingStrategy;

    type E = BabyBearExt4;
    type F = <E as ExtensionField>::BaseField;

    fn digest(encode: impl FnOnce(&mut DigestEncoder) -> Result<(), ManifestError>) -> [u8; 32] {
        section("test", encode).unwrap().digest
    }

    #[test]
    fn validation_manifest_host_matrix_is_column_major_and_includes_padding() {
        let matrix = RowMajorMatrix::<F>::new_by_values(
            vec![
                F::from_u64(1),
                F::from_u64(2),
                F::from_u64(3),
                F::from_u64(4),
            ],
            2,
            InstancePaddingStrategy::Default,
        );
        let actual = digest(|out| encode_matrix(out, 0, &matrix));
        let expected = digest(|out| {
            out.u32(0usize)?;
            out.u64(2usize)?;
            out.u64(2usize)?;
            out.u64(2usize)?;
            out.u64(2usize)?;
            for value in [1u64, 3, 2, 4] {
                out.u64(value)?;
            }
            Ok(())
        });
        assert_eq!(actual, expected);
    }

    #[test]
    fn validation_manifest_compact_prefix_matches_non_power_of_two_host_matrix() {
        let host = RowMajorMatrix::<F>::new_by_values(
            (1..=6).map(|value| F::from_u64(value)).collect(),
            2,
            InstancePaddingStrategy::Default,
        );
        assert_eq!(host.num_instances(), 3);
        assert_eq!(host.occupied_physical_rows(), 3);
        assert_eq!(host.height(), 4);

        let host_digest = digest(|out| encode_matrix(out, 0, &host));
        let compact_digest = digest(|out| {
            out.u32(0usize)?;
            out.u64(host.num_instances())?;
            out.u64(host.occupied_physical_rows())?;
            out.u64(host.height())?;
            out.u64(host.width())?;
            let compact_col_major: Vec<F> = [1, 3, 5, 2, 4, 6]
                .into_iter()
                .map(|value| F::from_u64(value))
                .collect();
            encode_col_major_values(
                out,
                &compact_col_major,
                host.occupied_physical_rows(),
                host.height(),
                host.width(),
            )
        });
        assert_eq!(host_digest, compact_digest);
    }

    #[test]
    fn validation_manifest_disabled_gate_runs_no_validation_work() {
        let config: Option<&ValidationManifestConfig> = None;
        let root = tempfile::tempdir().unwrap();
        let output_dir = root.path().join("not-created");
        let mut calls = 0;
        let result = ValidationManifestConfig::with_enabled(config, |_config| {
            calls += 1;
            fs::create_dir_all(&output_dir).unwrap();
            7
        });
        assert_eq!(result, None);
        assert_eq!(calls, 0);
        assert!(!output_dir.exists());
    }

    #[test]
    fn validation_manifest_lookup_order_is_canonical() {
        let encode = |tables: &[FxHashMap<u64, usize>]| {
            digest(|out| {
                out.u32(tables.len())?;
                for table in tables {
                    let mut entries: Vec<_> = table.iter().map(|(&k, &v)| (k, v)).collect();
                    entries.sort_unstable_by_key(|&(k, _)| k);
                    out.u64(entries.len())?;
                    out.u64(entries.iter().map(|(_, v)| *v as u64).sum::<u64>())?;
                    for (key, value) in entries {
                        out.u64(key)?;
                        out.u64(value)?;
                    }
                }
                Ok(())
            })
        };
        let mut left = FxHashMap::default();
        left.insert(9, 3);
        left.insert(2, 7);
        let mut right = FxHashMap::default();
        right.insert(2, 7);
        right.insert(9, 3);
        assert_eq!(encode(&[left]), encode(&[right]));
    }

    #[test]
    fn validation_manifest_addresses_are_a_sorted_set() {
        assert_eq!(
            digest(|out| encode_addresses(out, &[8, 2, 8, 5])),
            digest(|out| encode_addresses(out, &[5, 8, 2]))
        );
    }

    #[test]
    fn validation_manifest_public_and_continuation_cover_final_state() {
        let mut pi = PublicValues {
            heap_start_addr: 100,
            heap_shard_len: 3,
            hint_start_addr: 200,
            hint_shard_len: 2,
            ..Default::default()
        };
        let baseline = digest(|out| encode_public_values(out, &pi));
        pi.shard_rw_sum[13] = 1;
        assert_ne!(baseline, digest(|out| encode_public_values(out, &pi)));

        let actual = digest(|out| encode_final_continuation(out, &pi));
        let expected = digest(|out| {
            out.u32(pi.end_pc)?;
            out.u64(pi.end_cycle)?;
            out.u32(112u32)?;
            out.u32(208u32)?;
            for word in pi.shard_rw_sum {
                out.u32(word)?;
            }
            Ok(())
        });
        assert_eq!(actual, expected);
    }

    #[test]
    fn validation_manifest_continuation_names_match_runtime_names() {
        assert_eq!(
            <LocalFinalCircuit<E> as TableCircuit<E>>::name(),
            CONTINUATION_NAMES[0]
        );
        assert_eq!(
            <ShardRamCircuit<E> as TableCircuit<E>>::name(),
            CONTINUATION_NAMES[1]
        );
        assert_eq!(
            <ShardRamEcTreeCircuit<E> as TableCircuit<E>>::name(),
            CONTINUATION_NAMES[2]
        );
        assert_eq!(
            <GlobalState<E> as crate::instructions::Instruction<E>>::name(),
            CONTINUATION_NAMES[3]
        );
    }

    #[test]
    fn validation_manifest_publication_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shard-000000.manifest");
        publish_atomic_no_replace(&path, b"first").unwrap();
        assert!(publish_atomic_no_replace(&path, b"second").is_err());
        assert_eq!(fs::read(path).unwrap(), b"first");
    }
}
