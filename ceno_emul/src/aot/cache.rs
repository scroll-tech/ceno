//! AOT artifact identity, metadata validation, and atomic cache publication.

use super::*;

pub(super) fn default_aot_cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("CENO_AOT_CACHE_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(path).join("ceno/aot");
    }
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path).join(".cache/ceno/aot");
    }
    std::env::temp_dir().join("ceno-aot-cache")
}

pub(super) fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

pub(super) fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn program_digest(program: &Program) -> [u8; 32] {
    let mut bytes =
        Vec::with_capacity(16 + program.instructions.len() * 16 + program.image.len() * 8);
    bytes.extend_from_slice(&program.entry.to_le_bytes());
    bytes.extend_from_slice(&program.base_address.to_le_bytes());
    bytes.extend_from_slice(&program.sheap.to_le_bytes());
    bytes.extend_from_slice(&(program.instructions.len() as u64).to_le_bytes());
    for insn in &program.instructions {
        bytes.push(insn.kind as u8);
        bytes.push(insn.rs1);
        bytes.push(insn.rs2);
        bytes.push(insn.rd);
        bytes.extend_from_slice(&insn.imm.to_le_bytes());
        bytes.extend_from_slice(&insn.raw.to_le_bytes());
    }
    for (&addr, &value) in &program.image {
        bytes.extend_from_slice(&addr.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let static_roots = program.static_aot_roots.as_deref().unwrap_or_default();
    bytes.extend_from_slice(&(static_roots.len() as u64).to_le_bytes());
    for &pc in static_roots {
        bytes.extend_from_slice(&pc.to_le_bytes());
    }
    keccak256(&bytes)
}

pub(super) fn emitter_digest_for(variant: AotEmitterVariant, source: &[u8]) -> [u8; 32] {
    let mut bytes =
        Vec::with_capacity(AOT_EMITTER_SCHEMA.len() + variant.name().len() + source.len());
    bytes.extend_from_slice(AOT_EMITTER_SCHEMA.as_bytes());
    bytes.extend_from_slice(variant.name().as_bytes());
    bytes.extend_from_slice(source);
    keccak256(&bytes)
}

pub(super) fn emitter_digest(variant: AotEmitterVariant) -> [u8; 32] {
    // Bind every production source file that can change generated assembly or
    // its callbacks. Tests are intentionally excluded from cache identity.
    let sources: [&[u8]; 4] = [
        include_bytes!("../aot.rs"),
        include_bytes!("assembly.rs"),
        include_bytes!("runtime.rs"),
        include_bytes!("cache.rs"),
    ];
    let source_len = sources.iter().map(|source| source.len()).sum();
    let mut source = Vec::with_capacity(source_len);
    for part in sources {
        source.extend_from_slice(part);
    }
    emitter_digest_for(variant, &source)
}

pub(super) fn aot_cache_key(program: &Program, trace_style: AssemblyTraceStyle) -> String {
    if trace_style != AssemblyTraceStyle::GpuReplayDirect {
        return format!(
            "{}-abi{}-{}-{}-{}",
            hex_digest(&program_digest(program)),
            AOT_ABI_VERSION,
            trace_style.cache_name(),
            std::env::consts::ARCH,
            std::env::consts::OS,
        );
    }
    let emitter = emitter_digest(selected_emitter_variant(trace_style));
    format!(
        "{}-abi{}-{}-emit{}-{}-{}",
        hex_digest(&program_digest(program)),
        AOT_ABI_VERSION,
        trace_style.cache_name(),
        hex_digest(&emitter)[..32].to_owned(),
        std::env::consts::ARCH,
        std::env::consts::OS,
    )
}

pub(super) fn planner_cache_key(
    program: &Program,
    trace_style: AssemblyTraceStyle,
    model: &ShardCostModel,
) -> String {
    format!(
        "{}-cost{}",
        aot_cache_key(program, trace_style),
        hex_digest(&model.fingerprint())
    )
}

pub(super) fn artifact_digest(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("read AOT artifact {}", path.display()))?;
    Ok(keccak256(&bytes))
}

pub(super) fn cache_paths(cache_dir: &Path, key: &str) -> (PathBuf, PathBuf) {
    (
        cache_dir.join(format!("{key}.so")),
        cache_dir.join(format!("{key}.meta")),
    )
}

pub(super) fn cache_temporary_paths(
    cache_dir: &Path,
    process_id: u32,
    sequence: u64,
) -> [PathBuf; 3] {
    let basename = format!(".ceno-aot-{process_id:08x}-{sequence:016x}");
    [
        cache_dir.join(format!("{basename}.S")),
        cache_dir.join(format!("{basename}.so")),
        cache_dir.join(format!("{basename}.meta")),
    ]
}

pub(super) fn encode_cache_metadata(
    key: &str,
    emitter_variant: AotEmitterVariant,
    emitter_digest: &[u8; 32],
    so_digest: &[u8; 32],
    roots: &[u32],
    layout_profile: &AotLayoutProfile,
    event_count: usize,
    event_capacity: usize,
) -> String {
    let roots = roots
        .iter()
        .map(|pc| format!("{pc:08x}"))
        .collect::<Vec<_>>()
        .join(",");
    let emission_order = layout_profile
        .emission_order
        .iter()
        .map(|pc| format!("{pc:08x}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{AOT_CACHE_MAGIC}\n{key}\n{}\n{}\n{}\n{event_count}\n{event_capacity}\n{roots}\n{}\n{emission_order}\n",
        emitter_variant.name(),
        hex_digest(emitter_digest),
        hex_digest(so_digest),
        hex_digest(&layout_profile.digest),
    )
}

pub(super) type DecodedCacheMetadata = ([u8; 32], Vec<u32>, usize, [u8; 32], Vec<u32>);

pub(super) fn decode_cache_metadata(
    metadata: &str,
    expected_key: &str,
    expected_variant: AotEmitterVariant,
    expected_emitter_digest: &[u8; 32],
) -> Result<DecodedCacheMetadata> {
    let mut lines = metadata.lines();
    if lines.next() != Some(AOT_CACHE_MAGIC) || lines.next() != Some(expected_key) {
        bail!("AOT cache program/ABI identity mismatch");
    }
    if lines.next() != Some(expected_variant.name()) {
        bail!("AOT cache emitter variant mismatch");
    }
    let emitter_digest = decode_hex_digest(
        lines
            .next()
            .ok_or_else(|| anyhow!("AOT cache emitter digest missing"))?,
        "AOT cache emitter digest",
    )?;
    if &emitter_digest != expected_emitter_digest {
        bail!("AOT cache emitter digest mismatch");
    }
    let digest_hex = lines
        .next()
        .ok_or_else(|| anyhow!("AOT cache digest missing"))?;
    if digest_hex.len() != 64 {
        bail!("AOT cache digest has invalid length");
    }
    let digest = decode_hex_digest(digest_hex, "AOT cache digest")?;
    let event_count = lines
        .next()
        .ok_or_else(|| anyhow!("AOT cache event count missing"))?
        .parse::<usize>()
        .context("parse AOT cache event count")?;
    let event_capacity = lines
        .next()
        .ok_or_else(|| anyhow!("AOT cache event capacity missing"))?
        .parse::<usize>()
        .context("parse AOT cache event capacity")?;
    if event_capacity != next_access_capacity(event_count) {
        bail!("AOT cache next-access capacity does not match trained event count");
    }
    let roots = lines
        .next()
        .unwrap_or_default()
        .split(',')
        .filter(|root| !root.is_empty())
        .map(|root| u32::from_str_radix(root, 16).context("parse AOT cache root"))
        .collect::<Result<Vec<_>>>()?;
    let profile_digest = decode_hex_digest(
        lines
            .next()
            .ok_or_else(|| anyhow!("AOT cache profile digest missing"))?,
        "AOT cache profile digest",
    )?;
    let emission_order = lines
        .next()
        .unwrap_or_default()
        .split(',')
        .filter(|pc| !pc.is_empty())
        .map(|pc| u32::from_str_radix(pc, 16).context("parse AOT cache emission PC"))
        .collect::<Result<Vec<_>>>()?;
    Ok((
        digest,
        roots,
        event_capacity,
        profile_digest,
        emission_order,
    ))
}

pub(super) fn decode_hex_digest(hex: &str, description: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        bail!("{description} has invalid length");
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("parse {description}"))?;
    }
    Ok(digest)
}

pub(super) fn load_cached_aot(
    program: Arc<Program>,
    trace_style: AssemblyTraceStyle,
    cache_dir: &Path,
    key: &str,
    planner_fingerprint: Option<[u8; 32]>,
) -> Result<Option<AotProgram>> {
    let (so_path, metadata_path) = cache_paths(cache_dir, key);
    let role = trace_style.cache_name();
    aot_diagnostic_marker(
        "CACHE_PRESENCE",
        "BEGIN",
        role,
        key,
        &so_path,
        0,
        "artifacts=2",
    );
    let so_exists = so_path.exists();
    let metadata_exists = metadata_path.exists();
    aot_diagnostic_marker(
        "CACHE_PRESENCE",
        "END",
        role,
        key,
        &so_path,
        0,
        &format!("so_exists={so_exists},metadata_exists={metadata_exists}"),
    );
    if !so_exists || !metadata_exists {
        return Ok(None);
    }
    let metadata_bytes = fs::metadata(&metadata_path)?.len();
    aot_diagnostic_marker(
        "METADATA_READ",
        "BEGIN",
        role,
        key,
        &metadata_path,
        metadata_bytes,
        "files=1",
    );
    let metadata = fs::read_to_string(&metadata_path)
        .with_context(|| format!("read AOT metadata {}", metadata_path.display()))?;
    aot_diagnostic_marker(
        "METADATA_READ",
        "END",
        role,
        key,
        &metadata_path,
        metadata.len() as u64,
        "files=1",
    );
    aot_diagnostic_marker(
        "METADATA_DECODE",
        "BEGIN",
        role,
        key,
        &metadata_path,
        metadata.len() as u64,
        "records=1",
    );
    let emitter_variant = selected_emitter_variant(trace_style);
    let expected_emitter_digest = emitter_digest(emitter_variant);
    let (expected_digest, roots, event_capacity, profile_digest, emission_order) =
        decode_cache_metadata(&metadata, key, emitter_variant, &expected_emitter_digest)?;
    aot_diagnostic_marker(
        "METADATA_DECODE",
        "END",
        role,
        key,
        &metadata_path,
        metadata.len() as u64,
        &format!(
            "roots={},emissions={},event_capacity={},artifact_digest={},profile_digest={}",
            roots.len(),
            emission_order.len(),
            event_capacity,
            hex_digest(&expected_digest),
            hex_digest(&profile_digest)
        ),
    );
    let so_bytes = fs::metadata(&so_path)?.len();
    aot_diagnostic_marker(
        "ARTIFACT_READ",
        "BEGIN",
        role,
        key,
        &so_path,
        so_bytes,
        "files=1",
    );
    let artifact =
        fs::read(&so_path).with_context(|| format!("read AOT artifact {}", so_path.display()))?;
    aot_diagnostic_marker(
        "ARTIFACT_READ",
        "END",
        role,
        key,
        &so_path,
        artifact.len() as u64,
        "files=1",
    );
    aot_diagnostic_marker(
        "ARTIFACT_KECCAK",
        "BEGIN",
        role,
        key,
        &so_path,
        artifact.len() as u64,
        "digests=1",
    );
    let actual_digest = keccak256(&artifact);
    aot_diagnostic_marker(
        "ARTIFACT_KECCAK",
        "END",
        role,
        key,
        &so_path,
        artifact.len() as u64,
        &format!("digests=1,artifact_digest={}", hex_digest(&actual_digest)),
    );
    drop(artifact);
    if actual_digest != expected_digest {
        bail!("AOT artifact checksum mismatch");
    }
    tracing::info!(
        "AOT cached artifact size={} profile_digest={}",
        fs::metadata(&so_path)?.len(),
        hex_digest(&profile_digest),
    );
    let root_count = roots.len();
    aot_diagnostic_marker(
        "BLOCK_RECONSTRUCTION",
        "BEGIN",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("roots={root_count}"),
    );
    let blocks = partition_basic_blocks_with_roots(&program, roots)?;
    aot_diagnostic_marker(
        "BLOCK_RECONSTRUCTION",
        "END",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("roots={root_count},blocks={}", blocks.len()),
    );
    aot_diagnostic_marker(
        "EMISSION_VALIDATION",
        "BEGIN",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("blocks={},emissions={}", blocks.len(), emission_order.len()),
    );
    validate_emission_order(&blocks, &emission_order)?;
    aot_diagnostic_marker(
        "EMISSION_VALIDATION",
        "END",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("blocks={},emissions={}", blocks.len(), emission_order.len()),
    );
    let layout_profile = AotLayoutProfile {
        block_counts: Vec::new(),
        edge_counts: BTreeMap::new(),
        emission_order,
        digest: profile_digest,
    };
    let started = Instant::now();
    let (library, entry) = load_native(&so_path, trace_style.cache_name(), key)?;
    aot_diagnostic_marker(
        "AOT_PROGRAM_COMPLETION",
        "BEGIN",
        role,
        key,
        &so_path,
        so_bytes,
        &format!("blocks={},event_capacity={event_capacity}", blocks.len()),
    );
    let aot = AotProgram {
        cache_identity: key.to_owned(),
        artifact_path: Some(so_path.clone()),
        program,
        blocks,
        layout_profile,
        _library: library,
        entry,
        compile_load_time: started.elapsed(),
        trace_style,
        next_access_capacity: event_capacity,
        planner_fingerprint,
    };
    aot_diagnostic_marker(
        "AOT_PROGRAM_COMPLETION",
        "END",
        role,
        key,
        &so_path,
        so_bytes,
        &format!(
            "blocks={},event_capacity={event_capacity}",
            aot.blocks.len()
        ),
    );
    Ok(Some(aot))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compile_cached_aot(
    program: Arc<Program>,
    roots: Vec<u32>,
    layout_profile: Option<AotLayoutProfile>,
    trace_style: AssemblyTraceStyle,
    cache_dir: &Path,
    key: &str,
    event_count: usize,
    planner_model: Option<&ShardCostModel>,
) -> Result<AotProgram> {
    let started = Instant::now();
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("create AOT cache directory {}", cache_dir.display()))?;
    let blocks = partition_basic_blocks_with_roots(&program, roots.clone())?;
    let planner_metadata = planner_model
        .map(|model| build_aot_block_cost_descriptors(&program, &blocks, model))
        .transpose()?;
    let layout_profile = layout_profile.unwrap_or_else(|| pc_order_layout(&blocks));
    validate_emission_order(&blocks, &layout_profile.emission_order)?;
    let sequence = AOT_CACHE_TEMP_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| anyhow!("AOT cache temporary sequence exhausted"))?;
    let [asm_tmp, so_tmp, meta_tmp] =
        cache_temporary_paths(cache_dir, std::process::id(), sequence);
    let (so_path, metadata_path) = cache_paths(cache_dir, key);
    let result = (|| -> Result<()> {
        compile_native_to(
            &program,
            &blocks,
            &layout_profile.emission_order,
            trace_style,
            planner_metadata.as_ref(),
            &asm_tmp,
            &so_tmp,
        )?;
        tracing::info!(
            "AOT generated artifact size={} profile_digest={}",
            fs::metadata(&so_tmp)?.len(),
            hex_digest(&layout_profile.digest),
        );
        let digest = artifact_digest(&so_tmp)?;
        let event_capacity = next_access_capacity(event_count);
        let emitter_variant = selected_emitter_variant(trace_style);
        let emitter_digest = emitter_digest(emitter_variant);
        fs::write(
            &meta_tmp,
            encode_cache_metadata(
                key,
                emitter_variant,
                &emitter_digest,
                &digest,
                &roots,
                &layout_profile,
                event_count,
                event_capacity,
            ),
        )?;
        fs::rename(&so_tmp, &so_path)?;
        fs::rename(&meta_tmp, &metadata_path)?;
        Ok(())
    })();
    let _ = fs::remove_file(&asm_tmp);
    if let Err(err) = result {
        let _ = fs::remove_file(&so_tmp);
        let _ = fs::remove_file(&meta_tmp);
        return Err(err.context("compile and atomically cache AOT artifact"));
    }
    let (library, entry) = load_native(&so_path, trace_style.cache_name(), key)?;
    Ok(AotProgram {
        cache_identity: key.to_owned(),
        artifact_path: Some(so_path),
        program,
        blocks,
        layout_profile,
        _library: library,
        entry,
        compile_load_time: started.elapsed(),
        trace_style,
        next_access_capacity: next_access_capacity(event_count),
        planner_fingerprint: planner_model.map(ShardCostModel::fingerprint),
    })
}
