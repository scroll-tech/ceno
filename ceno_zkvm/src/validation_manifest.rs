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
const DETAIL_DIGESTS_ENV: &str = "CENO_VALIDATION_DETAIL_DIGESTS";
const DETAIL_CHUNK_ROWS: usize = 4096;
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
    detail_digests: bool,
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
        let detail_digests =
            env::var_os(DETAIL_DIGESTS_ENV).is_some_and(|value| !value.is_empty() && value != "0");
        Ok(Some(Self {
            output_dir,
            detail_digests,
        }))
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
    let mut matrix_details = Vec::new();
    let mut lookup_details = Vec::new();

    sections.push(section("public_values", |out| {
        encode_public_values(out, public_values)
    })?);

    let lookup_tables = witnesses.combined_lk_mlt().ok_or_else(|| {
        ManifestError("validation manifest requested before lookup finalization".into())
    })?;
    let lookup_entry_count = lookup_tables.iter().map(|table| table.len() as u64).sum();
    sections.push(section("lookup_multiplicities", |out| {
        out.u32(lookup_tables.len())?;
        for (index, table) in lookup_tables.iter().enumerate() {
            let mut entries: Vec<_> = table.iter().map(|(&key, &value)| (key, value)).collect();
            entries.sort_unstable_by_key(|&(key, _)| key);
            out.u64(entries.len())?;
            let total = entries.iter().try_fold(0u64, |total, &(_, value)| {
                total
                    .checked_add(value as u64)
                    .ok_or_else(|| ManifestError("lookup multiplicity total overflow".into()))
            })?;
            out.u64(total)?;
            let mut detail = config.detail_digests.then(DigestEncoder::new);
            if let Some(detail) = detail.as_mut() {
                detail.u32(index)?;
                detail.u64(entries.len())?;
                detail.u64(total)?;
            }
            for &(key, value) in &entries {
                out.u64(key)?;
                out.u64(value)?;
                if let Some(detail) = detail.as_mut() {
                    detail.u64(key)?;
                    detail.u64(value)?;
                }
            }
            if let Some(detail) = detail {
                let (payload_len, digest) = detail.finish();
                let diagnostic_entries = if matches!(index, 0 | 5) {
                    entries
                        .iter()
                        .map(|&(key, value)| {
                            u64::try_from(value).map(|value| (key, value)).map_err(|_| {
                                ManifestError(
                                    "lookup multiplicity does not fit diagnostic u64".into(),
                                )
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?
                } else {
                    Vec::new()
                };
                lookup_details.push(LookupDetail {
                    index,
                    entry_count: table.len(),
                    total,
                    payload_len,
                    digest,
                    entries: diagnostic_entries,
                });
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
        encode_matrices(
            out,
            witnesses,
            |_| true,
            config.detail_digests.then_some(&mut matrix_details),
        )
    })?);
    sections.push(section("ordered_shard_ram", |out| {
        encode_matrices(out, witnesses, |name| name == SHARD_RAM_NAME, None)
    })?);
    sections.push(section("continuation_matrices", |out| {
        encode_matrices(
            out,
            witnesses,
            |name| CONTINUATION_NAMES.contains(&name),
            None,
        )
    })?);
    sections.push(section("final_continuation_state", |out| {
        encode_final_continuation(out, public_values)
    })?);

    let (canonical, root_digest) = encode_manifest_summary(&sections)?;
    let final_path = config
        .output_dir
        .join(format!("shard-{shard_id:06}.manifest"));
    publish_atomic_no_replace(&final_path, &canonical)?;
    if config.detail_digests {
        let detail_path = config
            .output_dir
            .join(format!("shard-{shard_id:06}.details"));
        let detail_bytes = encode_detail_records(&matrix_details, &lookup_details);
        publish_atomic_no_replace(&detail_path, &detail_bytes)?;
    }

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

trait DigestWrite {
    fn u32(&mut self, value: impl TryInto<u32>) -> Result<(), ManifestError>;
    fn u64(&mut self, value: impl TryInto<u64>) -> Result<(), ManifestError>;
}

struct TeeDigestEncoder<'a> {
    primary: &'a mut DigestEncoder,
    detail: &'a mut DigestEncoder,
}

struct MatrixDetail {
    chip_name: String,
    input_name: String,
    role: usize,
    actual_rows: usize,
    num_instances: usize,
    occupied_rows: usize,
    height: usize,
    width: usize,
    payload_len: u64,
    digest: [u8; 32],
    columns: Vec<MatrixColumnDetail>,
}

struct MatrixColumnDetail {
    column: usize,
    actual_rows: usize,
    padding_rows: usize,
    actual_digest: [u8; 32],
    padding_digest: [u8; 32],
    chunks: Vec<MatrixChunkDetail>,
}

struct MatrixChunkDetail {
    chunk: usize,
    row_start: usize,
    row_count: usize,
    digest: [u8; 32],
}

struct LookupDetail {
    index: usize,
    entry_count: usize,
    total: u64,
    payload_len: u64,
    digest: [u8; 32],
    entries: Vec<(u64, u64)>,
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

impl DigestWrite for DigestEncoder {
    fn u32(&mut self, value: impl TryInto<u32>) -> Result<(), ManifestError> {
        DigestEncoder::u32(self, value)
    }

    fn u64(&mut self, value: impl TryInto<u64>) -> Result<(), ManifestError> {
        DigestEncoder::u64(self, value)
    }
}

impl DigestWrite for TeeDigestEncoder<'_> {
    fn u32(&mut self, value: impl TryInto<u32>) -> Result<(), ManifestError> {
        let value = value
            .try_into()
            .map_err(|_| ManifestError("validation value does not fit u32".into()))?;
        self.primary.u32(value)?;
        self.detail.u32(value)
    }

    fn u64(&mut self, value: impl TryInto<u64>) -> Result<(), ManifestError> {
        let value = value
            .try_into()
            .map_err(|_| ManifestError("validation value does not fit u64".into()))?;
        self.primary.u64(value)?;
        self.detail.u64(value)
    }
}

fn encode_detail_records(matrices: &[MatrixDetail], lookups: &[LookupDetail]) -> Vec<u8> {
    let mut text = String::from("CENO_VALIDATION_DETAIL_DIGESTS\t2\n");
    for matrix in matrices {
        use fmt::Write as _;
        writeln!(
            text,
            "matrix\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            matrix.chip_name,
            matrix.input_name,
            matrix.role,
            matrix.actual_rows,
            matrix.num_instances,
            matrix.occupied_rows,
            matrix.height,
            matrix.width,
            matrix.payload_len,
            hex_digest(&matrix.digest),
        )
        .expect("writing validation detail to String cannot fail");
        for column in &matrix.columns {
            writeln!(
                text,
                "matrix_column\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                matrix.chip_name,
                matrix.input_name,
                matrix.role,
                column.column,
                column.actual_rows,
                column.padding_rows,
                hex_digest(&column.actual_digest),
                hex_digest(&column.padding_digest),
            )
            .expect("writing validation detail to String cannot fail");
            for chunk in &column.chunks {
                writeln!(
                    text,
                    "matrix_chunk\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    matrix.chip_name,
                    matrix.input_name,
                    matrix.role,
                    column.column,
                    chunk.chunk,
                    chunk.row_start,
                    chunk.row_count,
                    hex_digest(&chunk.digest),
                )
                .expect("writing validation detail to String cannot fail");
            }
        }
    }
    for lookup in lookups {
        use fmt::Write as _;
        writeln!(
            text,
            "lookup\t{}\t{}\t{}\t{}\t{}",
            lookup.index,
            lookup.entry_count,
            lookup.total,
            lookup.payload_len,
            hex_digest(&lookup.digest),
        )
        .expect("writing validation detail to String cannot fail");
        for &(key, multiplicity) in &lookup.entries {
            writeln!(
                text,
                "lookup_entry\t{}\t{}\t{}",
                lookup.index, key, multiplicity,
            )
            .expect("writing validation detail to String cannot fail");
        }
    }
    text.into_bytes()
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
    mut details: Option<&mut Vec<MatrixDetail>>,
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
            let actual_rows = input.num_instances[0]
                .checked_add(input.num_instances[1])
                .ok_or_else(|| {
                    ManifestError(format!(
                        "validation matrix actual-row count overflow for chip {chip_name:?}, input {:?}",
                        input.name
                    ))
            })?;
            for (role, rmm) in input.witness_rmms.iter().enumerate() {
                if let Some(details) = details.as_deref_mut() {
                    let mut detail = DigestEncoder::new();
                    let mut columns = Vec::with_capacity(rmm.width());
                    detail.string(chip_name)?;
                    detail.string(&input.name)?;
                    detail.u32(role)?;
                    detail.u64(actual_rows)?;
                    {
                        let mut tee = TeeDigestEncoder {
                            primary: out,
                            detail: &mut detail,
                        };
                        encode_matrix(
                            &mut tee,
                            chip_name,
                            &input.name,
                            role,
                            actual_rows,
                            rmm,
                            Some(&mut columns),
                        )?;
                    }
                    let (payload_len, digest) = detail.finish();
                    details.push(MatrixDetail {
                        chip_name: chip_name.to_string(),
                        input_name: input.name.clone(),
                        role,
                        actual_rows,
                        num_instances: rmm.num_instances(),
                        occupied_rows: rmm.occupied_physical_rows(),
                        height: rmm.height(),
                        width: rmm.width(),
                        payload_len,
                        digest,
                        columns,
                    });
                } else {
                    encode_matrix(out, chip_name, &input.name, role, actual_rows, rmm, None)?;
                }
            }
        }
    }
    Ok(())
}

fn encode_matrix<F: SmallField + 'static, W: DigestWrite>(
    out: &mut W,
    chip_name: &str,
    input_name: &str,
    role: usize,
    actual_rows: usize,
    matrix: &RowMajorMatrix<F>,
    mut columns: Option<&mut Vec<MatrixColumnDetail>>,
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
                if let Some(columns) = columns.as_deref_mut() {
                    columns.push(build_matrix_column_detail(
                        col,
                        actual_rows,
                        matrix.height(),
                        |row| values[row * matrix.width() + col].to_canonical_u64(),
                    )?);
                }
                for row in 0..matrix.height() {
                    out.u64(values[row * matrix.width() + col].to_canonical_u64())?;
                }
            }
            Ok(())
        }
        Some(DeviceMatrixLayout::RowMajor) => encode_row_major_device_matrix(
            out,
            chip_name,
            input_name,
            role,
            actual_rows,
            matrix,
            columns,
        ),
        Some(DeviceMatrixLayout::ColMajor) => encode_col_major_device_matrix(
            out,
            chip_name,
            input_name,
            role,
            actual_rows,
            matrix,
            columns,
        ),
    }
}

#[cfg(feature = "gpu")]
fn encode_row_major_device_matrix<F: SmallField + 'static, W: DigestWrite>(
    out: &mut W,
    chip_name: &str,
    input_name: &str,
    role: usize,
    actual_rows: usize,
    matrix: &RowMajorMatrix<F>,
    mut columns: Option<&mut Vec<MatrixColumnDetail>>,
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
        .ok_or_else(|| ManifestError("row-major device backing type mismatch".into()))?;
    let present_rows = resolve_col_major_present_rows(
        device.len(),
        actual_rows,
        matrix.occupied_physical_rows(),
        matrix.height(),
        matrix.width(),
    )
    .map_err(|reason| {
        ManifestError(format!(
            "invalid row-major validation matrix for chip {chip_name:?}, input {input_name:?}, role {role}: {reason}; device_len={}, actual_rows={actual_rows}, occupied_rows={}, height={}, width={}, layout=RowMajor",
            device.len(),
            matrix.occupied_physical_rows(),
            matrix.height(),
            matrix.width(),
        ))
    })?;
    let values = device
        .to_vec()
        .map_err(|err| ManifestError(format!("validation matrix D2H failed: {err}")))?;
    for col in 0..matrix.width() {
        if let Some(columns) = columns.as_deref_mut() {
            columns.push(build_matrix_column_detail(
                col,
                actual_rows,
                matrix.height(),
                |row| {
                    (row < present_rows)
                        .then(|| values[row * matrix.width() + col].to_canonical_u64())
                        .unwrap_or(0)
                },
            )?);
        }
        for row in 0..matrix.height() {
            out.u64(
                (row < present_rows)
                    .then(|| values[row * matrix.width() + col].to_canonical_u64())
                    .unwrap_or(0),
            )?;
        }
    }
    Ok(())
}

#[cfg(not(feature = "gpu"))]
fn encode_row_major_device_matrix<F: SmallField + 'static, W: DigestWrite>(
    _out: &mut W,
    _chip_name: &str,
    _input_name: &str,
    _role: usize,
    _actual_rows: usize,
    _matrix: &RowMajorMatrix<F>,
    _columns: Option<&mut Vec<MatrixColumnDetail>>,
) -> Result<(), ManifestError> {
    Err(ManifestError(
        "row-major device validation requires the gpu feature".into(),
    ))
}

fn build_matrix_column_detail(
    column: usize,
    actual_rows: usize,
    padded_height: usize,
    mut value_at: impl FnMut(usize) -> u64,
) -> Result<MatrixColumnDetail, ManifestError> {
    if actual_rows > padded_height {
        return Err(ManifestError(format!(
            "validation matrix has {actual_rows} actual rows but padded height is {padded_height}"
        )));
    }
    let mut actual = DigestEncoder::new();
    let mut padding = DigestEncoder::new();
    let chunk_count = padded_height.div_ceil(DETAIL_CHUNK_ROWS);
    let mut chunk_encoders: Vec<_> = (0..chunk_count).map(|_| DigestEncoder::new()).collect();
    for row in 0..padded_height {
        let value = value_at(row);
        if row < actual_rows {
            actual.u64(value)?;
        } else {
            padding.u64(value)?;
        }
        chunk_encoders[row / DETAIL_CHUNK_ROWS].u64(value)?;
    }
    let (_, actual_digest) = actual.finish();
    let (_, padding_digest) = padding.finish();
    let chunks = chunk_encoders
        .into_iter()
        .enumerate()
        .map(|(chunk, encoder)| {
            let row_start = chunk * DETAIL_CHUNK_ROWS;
            MatrixChunkDetail {
                chunk,
                row_start,
                row_count: (padded_height - row_start).min(DETAIL_CHUNK_ROWS),
                digest: encoder.finish().1,
            }
        })
        .collect();
    Ok(MatrixColumnDetail {
        column,
        actual_rows,
        padding_rows: padded_height - actual_rows,
        actual_digest,
        padding_digest,
        chunks,
    })
}

#[cfg(any(feature = "gpu", test))]
fn resolve_col_major_present_rows(
    device_len: usize,
    actual_rows: usize,
    occupied_rows: usize,
    padded_height: usize,
    width: usize,
) -> Result<usize, String> {
    let full_len = padded_height
        .checked_mul(width)
        .ok_or_else(|| "full matrix length overflow".to_string())?;
    let compact_len = occupied_rows
        .checked_mul(width)
        .ok_or_else(|| "occupied matrix length overflow".to_string())?;

    // Preserve the existing full and occupied-prefix representations.
    if device_len == full_len {
        return Ok(padded_height);
    }
    if device_len == compact_len {
        return Ok(occupied_rows);
    }

    let actual_len = actual_rows
        .checked_mul(width)
        .ok_or_else(|| "actual-row matrix length overflow".to_string())?;
    if device_len == actual_len {
        if actual_rows > occupied_rows {
            return Err(format!(
                "actual rows {actual_rows} exceed occupied rows {occupied_rows}"
            ));
        }
        if occupied_rows > padded_height {
            return Err(format!(
                "occupied rows {occupied_rows} exceed padded height {padded_height}"
            ));
        }
        return Ok(actual_rows);
    }

    if width != 0 && !device_len.is_multiple_of(width) {
        return Err(format!(
            "device length {device_len} is not divisible by width {width}"
        ));
    }
    Err(format!(
        "device length {device_len} matches neither full {full_len}, occupied {compact_len}, nor checked actual-row {actual_len} length"
    ))
}

#[cfg(any(feature = "gpu", test))]
fn encode_col_major_values<F: SmallField, W: DigestWrite>(
    out: &mut W,
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
fn encode_col_major_device_matrix<F: SmallField + 'static, W: DigestWrite>(
    out: &mut W,
    chip_name: &str,
    input_name: &str,
    role: usize,
    actual_rows: usize,
    matrix: &RowMajorMatrix<F>,
    mut columns: Option<&mut Vec<MatrixColumnDetail>>,
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
    let present_rows = resolve_col_major_present_rows(
        device.len(),
        actual_rows,
        matrix.occupied_physical_rows(),
        matrix.height(),
        matrix.width(),
    )
    .map_err(|reason| {
        ManifestError(format!(
            "invalid col-major validation matrix for chip {chip_name:?}, input {input_name:?}, role {role}: {reason}; device_len={}, actual_rows={actual_rows}, occupied_rows={}, height={}, width={}, layout=ColMajor",
            device.len(),
            matrix.occupied_physical_rows(),
            matrix.height(),
            matrix.width(),
        ))
    })?;
    if present_rows > matrix.height() {
        return Err(ManifestError(format!(
            "invalid col-major validation matrix for chip {chip_name:?}, input {input_name:?}, role {role}: present rows {present_rows} exceed padded height {}; device_len={}, actual_rows={actual_rows}, occupied_rows={}, width={}, layout=ColMajor",
            matrix.height(),
            device.len(),
            matrix.occupied_physical_rows(),
            matrix.width(),
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
        if let Some(columns) = columns.as_deref_mut() {
            columns.push(build_matrix_column_detail(
                col,
                actual_rows,
                matrix.height(),
                |row| values.get(row).map_or(0, |value| value.to_canonical_u64()),
            )?);
        }
        encode_col_major_values(out, &values, present_rows, matrix.height(), 1)?;
    }
    Ok(())
}

#[cfg(not(feature = "gpu"))]
fn encode_col_major_device_matrix<F: SmallField + 'static, W: DigestWrite>(
    _out: &mut W,
    _chip_name: &str,
    _input_name: &str,
    _role: usize,
    _actual_rows: usize,
    _matrix: &RowMajorMatrix<F>,
    _columns: Option<&mut Vec<MatrixColumnDetail>>,
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
        let actual = digest(|out| encode_matrix(out, "test", "test", 0, 2, &matrix, None));
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

    #[cfg(feature = "gpu")]
    #[test]
    fn validation_manifest_row_major_device_matches_host_canonical_encoding() {
        use ceno_gpu::CudaHal;
        use gkr_iop::gpu::get_cuda_hal;
        use witness::DeviceMatrixLayout;

        let values = vec![
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(4),
        ];
        let host =
            RowMajorMatrix::<F>::new_by_values(values.clone(), 2, InstancePaddingStrategy::Default);
        let cuda_hal = get_cuda_hal().unwrap();
        let device = cuda_hal.alloc_elems_from_host(&values, None).unwrap();
        let device_row_major = RowMajorMatrix::<F>::new_by_device_backing(
            2,
            2,
            InstancePaddingStrategy::Default,
            device,
            DeviceMatrixLayout::RowMajor,
        );

        let host_digest = digest(|out| encode_matrix(out, "test", "test", 0, 2, &host, None));
        let device_digest =
            digest(|out| encode_matrix(out, "test", "test", 0, 2, &device_row_major, None));
        assert_eq!(device_digest, host_digest);
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

        let host_digest = digest(|out| encode_matrix(out, "test", "test", 0, 3, &host, None));
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
    fn validation_manifest_checked_actual_prefix_matches_zero_padded_matrix() {
        let actual_rows = 3;
        let occupied_rows = 4;
        let padded_height = 4;
        let width = 2;
        let compact_col_major: Vec<F> = [1, 3, 5, 2, 4, 6].into_iter().map(F::from_u64).collect();
        let present_rows = resolve_col_major_present_rows(
            compact_col_major.len(),
            actual_rows,
            occupied_rows,
            padded_height,
            width,
        )
        .unwrap();
        assert_eq!(present_rows, actual_rows);

        let compact_digest = digest(|out| {
            out.u32(1usize)?;
            out.u64(occupied_rows)?;
            out.u64(occupied_rows)?;
            out.u64(padded_height)?;
            out.u64(width)?;
            encode_col_major_values(out, &compact_col_major, present_rows, padded_height, width)
        });
        let padded_digest = digest(|out| {
            out.u32(1usize)?;
            out.u64(occupied_rows)?;
            out.u64(occupied_rows)?;
            out.u64(padded_height)?;
            out.u64(width)?;
            for value in [1u64, 3, 5, 0, 2, 4, 6, 0] {
                out.u64(value)?;
            }
            Ok(())
        });
        assert_eq!(compact_digest, padded_digest);
    }

    #[test]
    fn validation_manifest_checked_actual_prefix_rejects_invalid_shapes() {
        let non_divisible = resolve_col_major_present_rows(5, 3, 4, 4, 2).unwrap_err();
        assert!(non_divisible.contains("not divisible"));

        let oversized = resolve_col_major_present_rows(10, 3, 4, 4, 2).unwrap_err();
        assert!(oversized.contains("matches neither"));

        let actual_exceeds_occupied = resolve_col_major_present_rows(10, 5, 4, 8, 2).unwrap_err();
        assert!(actual_exceeds_occupied.contains("actual rows 5 exceed occupied rows 4"));

        let occupied_exceeds_height = resolve_col_major_present_rows(4, 2, 5, 4, 2).unwrap_err();
        assert!(occupied_exceeds_height.contains("occupied rows 5 exceed padded height 4"));

        let arbitrary_prefix = resolve_col_major_present_rows(4, 3, 4, 4, 2).unwrap_err();
        assert!(arbitrary_prefix.contains("checked actual-row 6"));
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
    fn validation_manifest_detail_records_name_matrix_roles_and_lookup_indices() {
        let matrices = [MatrixDetail {
            chip_name: "chip".into(),
            input_name: "input".into(),
            role: 1,
            actual_rows: 3,
            num_instances: 4,
            occupied_rows: 4,
            height: 8,
            width: 2,
            payload_len: 9,
            digest: [0x11; 32],
            columns: vec![MatrixColumnDetail {
                column: 0,
                actual_rows: 3,
                padding_rows: 5,
                actual_digest: [0x33; 32],
                padding_digest: [0x44; 32],
                chunks: vec![MatrixChunkDetail {
                    chunk: 0,
                    row_start: 0,
                    row_count: 8,
                    digest: [0x55; 32],
                }],
            }],
        }];
        let lookups = [LookupDetail {
            index: 7,
            entry_count: 5,
            total: 12,
            payload_len: 13,
            digest: [0x22; 32],
            entries: vec![(4, 9)],
        }];
        let text = String::from_utf8(encode_detail_records(&matrices, &lookups)).unwrap();
        assert!(text.starts_with("CENO_VALIDATION_DETAIL_DIGESTS\t2\n"));
        assert!(text.contains(
            "matrix\tchip\tinput\t1\t3\t4\t4\t8\t2\t9\t1111111111111111111111111111111111111111111111111111111111111111\n"
        ));
        assert!(text.contains(
            "lookup\t7\t5\t12\t13\t2222222222222222222222222222222222222222222222222222222222222222\n"
        ));
        assert!(text.contains(
            "matrix_column\tchip\tinput\t1\t0\t3\t5\t3333333333333333333333333333333333333333333333333333333333333333\t4444444444444444444444444444444444444444444444444444444444444444\n"
        ));
        assert!(text.contains(
            "matrix_chunk\tchip\tinput\t1\t0\t0\t0\t8\t5555555555555555555555555555555555555555555555555555555555555555\n"
        ));
        assert!(text.contains("lookup_entry\t7\t4\t9\n"));
    }

    #[test]
    fn validation_manifest_column_details_split_actual_padding_and_fixed_chunks() {
        let height = DETAIL_CHUNK_ROWS + 3;
        let actual_rows = DETAIL_CHUNK_ROWS - 1;
        let detail =
            build_matrix_column_detail(7, actual_rows, height, |row| row as u64 + 1).unwrap();
        assert_eq!(detail.column, 7);
        assert_eq!(detail.actual_rows, actual_rows);
        assert_eq!(detail.padding_rows, 4);
        assert_eq!(detail.chunks.len(), 2);
        assert_eq!(detail.chunks[0].row_count, DETAIL_CHUNK_ROWS);
        assert_eq!(detail.chunks[1].row_start, DETAIL_CHUNK_ROWS);
        assert_eq!(detail.chunks[1].row_count, 3);

        let digest_values = |range: std::ops::Range<usize>| {
            let mut encoder = DigestEncoder::new();
            for row in range {
                encoder.u64(row as u64 + 1).unwrap();
            }
            encoder.finish().1
        };
        assert_eq!(detail.actual_digest, digest_values(0..actual_rows));
        assert_eq!(detail.padding_digest, digest_values(actual_rows..height));
        assert_eq!(detail.chunks[0].digest, digest_values(0..DETAIL_CHUNK_ROWS));
        assert_eq!(
            detail.chunks[1].digest,
            digest_values(DETAIL_CHUNK_ROWS..height)
        );
    }

    #[test]
    fn validation_manifest_column_details_encode_implicit_padding_as_zero() {
        let compact = [9u64, 8, 7];
        let implicit =
            build_matrix_column_detail(0, 3, 8, |row| compact.get(row).copied().unwrap_or(0))
                .unwrap();
        let explicit =
            build_matrix_column_detail(0, 3, 8, |row| [9u64, 8, 7, 0, 0, 0, 0, 0][row]).unwrap();
        assert_eq!(implicit.actual_digest, explicit.actual_digest);
        assert_eq!(implicit.padding_digest, explicit.padding_digest);
        assert_eq!(implicit.chunks[0].digest, explicit.chunks[0].digest);
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
