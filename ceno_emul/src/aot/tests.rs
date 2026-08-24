//! AOT compiler, emitter, cache, and execution regression tests.

use super::*;
use crate::{CENO_PLATFORM, ChipCostSpec, EmuContext, ShardCostModel, encode_rv32};
use std::sync::Arc;
use strum::EnumCount;

fn program(instructions: Vec<Instruction>) -> Program {
    Program::new(
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.heap.start,
        instructions,
        Default::default(),
    )
}

#[test]
fn cache_temporary_names_fit_longest_active_key_component_limit() {
    let cache_dir = Path::new("cache");
    let longest_active_key = "k".repeat(234);
    let (so_path, metadata_path) = cache_paths(cache_dir, &longest_active_key);
    let first = cache_temporary_paths(cache_dir, u32::MAX, u64::MAX - 1);
    let second = cache_temporary_paths(cache_dir, u32::MAX, u64::MAX);

    assert_ne!(first, second);
    for path in [so_path, metadata_path]
        .into_iter()
        .chain(first)
        .chain(second)
    {
        assert!(
            path.file_name().unwrap().as_encoded_bytes().len() <= 255,
            "cache filename component exceeds NAME_MAX: {}",
            path.display()
        );
    }
}

#[test]
fn coverage_roots_include_entry_and_observed_jump_target() {
    let base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::JAL, 0, 0, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let roots = trace_preflight_roots(&CENO_PLATFORM, program, []).unwrap();

    assert_eq!(roots[0], base);
    assert!(roots.contains(&(base + 8)));
}

#[test]
fn coverage_training_counts_instructions_and_branch_directions() {
    let base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let training = trace_preflight_profile(&CENO_PLATFORM, program.clone(), []).unwrap();
    assert_eq!(training.instruction_counts, vec![1, 3, 3, 1]);
    assert_eq!(
        training.branch_counts[2],
        BranchCounts {
            taken: 2,
            not_taken: 1,
        }
    );

    let blocks = partition_basic_blocks_with_roots(&program, training.roots.clone()).unwrap();
    let layout = build_layout_profile(&program, &blocks, &training).unwrap();
    assert_eq!(layout.block_counts, vec![1, 3, 1]);
    assert_eq!(layout.edge_counts[&(base, base + 4)], 1);
    assert_eq!(layout.edge_counts[&(base + 4, base + 4)], 2);
    assert_eq!(layout.edge_counts[&(base + 4, base + 12)], 1);
}

#[test]
fn hot_chains_are_deterministic_and_do_not_form_cycles() {
    let blocks = (0..4)
        .map(|index| BasicBlock {
            start_pc: 0x1000 + index * 4,
            end_pc: 0x1004 + index * 4,
        })
        .collect::<Vec<_>>();
    let edges = BTreeMap::from([
        ((0x1000, 0x1004), 30),
        ((0x1004, 0x1008), 20),
        ((0x1008, 0x1000), 10),
    ]);

    let first = hot_chain_emission_order(&blocks, &[30, 20, 10, 0], &edges);
    let second = hot_chain_emission_order(&blocks, &[30, 20, 10, 0], &edges);
    assert_eq!(first, second);
    assert_eq!(first, vec![0x1000, 0x1004, 0x1008, 0x100c]);
    assert_eq!(first.iter().copied().collect::<BTreeSet<_>>().len(), 4);
}

#[test]
fn cache_metadata_round_trips_layout_digest_and_emission_order() {
    let profile = AotLayoutProfile {
        block_counts: vec![9, 4, 0],
        edge_counts: BTreeMap::from([((0x1000, 0x1008), 7)]),
        emission_order: vec![0x1000, 0x1008, 0x1004],
        digest: [0x5a; 32],
    };
    let artifact_digest = [0xa5; 32];
    let emitter_variant = AotEmitterVariant::SharedPacked;
    let emitter_digest = emitter_digest(emitter_variant);
    let event_count = 17;
    let event_capacity = next_access_capacity(event_count);
    let encoded = encode_cache_metadata(
        "test-key",
        emitter_variant,
        &emitter_digest,
        &artifact_digest,
        &[0x1000, 0x1008],
        &profile,
        event_count,
        event_capacity,
    );

    let (decoded_artifact, roots, capacity, profile_digest, emission_order) =
        decode_cache_metadata(&encoded, "test-key", emitter_variant, &emitter_digest).unwrap();
    assert_eq!(decoded_artifact, artifact_digest);
    assert_eq!(roots, vec![0x1000, 0x1008]);
    assert_eq!(capacity, event_capacity);
    assert_eq!(profile_digest, profile.digest);
    assert_eq!(emission_order, profile.emission_order);
}

#[test]
fn cache_metadata_rejects_missing_or_mismatched_emitter_provenance() {
    let profile = AotLayoutProfile {
        block_counts: Vec::new(),
        edge_counts: BTreeMap::new(),
        emission_order: vec![0x1000],
        digest: [0x5a; 32],
    };
    let variant = AotEmitterVariant::SharedPacked;
    let digest = emitter_digest(variant);
    let encoded = encode_cache_metadata(
        "test-key",
        variant,
        &digest,
        &[0xa5; 32],
        &[0x1000],
        &profile,
        17,
        next_access_capacity(17),
    );

    let missing = format!("{AOT_CACHE_MAGIC}\ntest-key\n{}\n", variant.name());
    assert!(
        decode_cache_metadata(&missing, "test-key", variant, &digest)
            .unwrap_err()
            .to_string()
            .contains("emitter digest")
    );
    assert!(
        decode_cache_metadata(
            &encoded,
            "test-key",
            AotEmitterVariant::FullyInlinedDiagnostic,
            &emitter_digest(AotEmitterVariant::FullyInlinedDiagnostic),
        )
        .unwrap_err()
        .to_string()
        .contains("emitter variant mismatch")
    );
    assert!(
        decode_cache_metadata(&encoded, "test-key", variant, &[0x3c; 32])
            .unwrap_err()
            .to_string()
            .contains("emitter digest mismatch")
    );
}

#[test]
fn emitter_revisions_and_variants_have_distinct_cache_identity() {
    let program = program(vec![encode_rv32(InsnKind::ADDI, 0, 0, 1, 1)]);
    let standard = emitter_digest(AotEmitterVariant::Standard);
    let shared = emitter_digest(AotEmitterVariant::SharedPacked);
    let inline = emitter_digest(AotEmitterVariant::FullyInlinedDiagnostic);

    assert_ne!(standard, shared);
    assert_ne!(shared, inline);
    assert_ne!(
        emitter_digest_for(AotEmitterVariant::SharedPacked, b"revision-a"),
        emitter_digest_for(AotEmitterVariant::SharedPacked, b"revision-b"),
    );
    assert!(
        aot_cache_key(&program, AssemblyTraceStyle::GpuReplayDirect)
            .contains(&format!("emit{}", &hex_digest(&shared)[..32]))
    );
}

#[test]
fn successor_emission_falls_through_to_adjacent_hot_edge() {
    let base = CENO_PLATFORM.pc_base();
    let program = program(vec![
        encode_rv32(InsnKind::BNE, 1, 0, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]);
    let labels = BTreeMap::from([
        (base + 4, "L_cold".to_owned()),
        (base + 8, "L_hot".to_owned()),
    ]);
    let mut conditional = Vec::new();
    emit_successor_jump(
        &mut conditional,
        &program,
        &labels,
        Some(base + 8),
        base,
        program.instructions[0],
    )
    .unwrap();
    let conditional = String::from_utf8(conditional).unwrap();
    assert!(conditional.contains("je L_cold"));
    assert!(!conditional.contains("je L_hot"));
    assert!(conditional.contains("jne ceno_aot_dispatch"));

    let jump = encode_rv32(InsnKind::JAL, 0, 0, 0, 8);
    let mut unconditional = Vec::new();
    emit_successor_jump(
        &mut unconditional,
        &program,
        &labels,
        Some(base + 8),
        base,
        jump,
    )
    .unwrap();
    assert!(unconditional.is_empty());
}

#[test]
fn coverage_roots_include_late_indirect_target_and_post_ecall_continuation() {
    let base = CENO_PLATFORM.pc_base();
    let indirect = Arc::new(program(vec![
        encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let mut vm = VMState::<CoverageTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        indirect.clone(),
        CoverageTracerConfig {
            entry: base,
            program_base: indirect.base_address,
            instruction_count: indirect.instructions.len(),
        },
    );
    vm.init_register_unsafe(1, base + 16);
    while vm.next_step_record().unwrap().is_some() {}
    let roots = &vm.tracer().roots;
    assert!(roots.contains(&(base + 16)), "roots={roots:#x?}");

    let mut platform = CENO_PLATFORM.clone();
    platform.unsafe_ecall_nop = true;
    let post_ecall = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_ecall().into(), 123),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_ecall().into(), 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let roots = trace_preflight_roots(&platform, post_ecall, []).unwrap();
    assert!(roots.contains(&(base + 8)));
}

#[test]
fn coverage_roots_preserve_canonical_whole_blocks() {
    let base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ADDI, 1, 0, 2, 2),
        encode_rv32(InsnKind::ADDI, 2, 0, 3, 3),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let roots = trace_preflight_roots(&CENO_PLATFORM, program.clone(), []).unwrap();
    let blocks = partition_basic_blocks_with_roots(&program, roots).unwrap();
    assert_eq!(
        blocks[0],
        BasicBlock {
            start_pc: base,
            end_pc: base + 12
        }
    );
    assert_eq!(blocks.len(), 2);
}

#[test]
fn partitions_direct_branch_and_fallthrough() {
    let base = CENO_PLATFORM.pc_base();
    let program = program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]);

    let blocks = partition_basic_blocks(&program).unwrap();
    assert_eq!(
        blocks,
        vec![
            BasicBlock {
                start_pc: base,
                end_pc: base + 8,
            },
            BasicBlock {
                start_pc: base + 8,
                end_pc: base + 12,
            },
            BasicBlock {
                start_pc: base + 12,
                end_pc: base + 16,
            },
        ]
    );
}

#[test]
fn partitions_only_static_reachable_blocks() {
    let base = CENO_PLATFORM.pc_base();
    let program = program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
        encode_rv32(InsnKind::JAL, 0, 0, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 3, 3),
    ]);

    let blocks = partition_basic_blocks(&program).unwrap();
    assert_eq!(
        blocks,
        vec![
            BasicBlock {
                start_pc: base,
                end_pc: base + 4,
            },
            BasicBlock {
                start_pc: base + 4,
                end_pc: base + 8,
            },
        ]
    );
}

#[test]
fn llvm_static_roots_admit_unobserved_blocks_and_change_cache_identity() {
    let base = CENO_PLATFORM.pc_base();
    let mut program = program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]);
    let training_only_key = aot_cache_key(&program, AssemblyTraceStyle::Pure);

    program.static_aot_roots = Some(vec![base, base + 8]);
    let blocks = partition_basic_blocks(&program).unwrap();

    assert_eq!(
        blocks
            .iter()
            .map(|block| block.start_pc)
            .collect::<Vec<_>>(),
        vec![base, base + 4, base + 8, base + 12]
    );
    assert_ne!(
        aot_cache_key(&program, AssemblyTraceStyle::Pure),
        training_only_key
    );
}

#[test]
fn static_preflight_roots_include_metadata_and_all_resume_pcs() {
    let base = CENO_PLATFORM.pc_base();
    let mut program = program(vec![
        encode_rv32(InsnKind::JALR, 1, 0, 1, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(InsnKind::INVALID, 0, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 0, 0),
    ]);
    program.static_aot_roots = Some(vec![base, base + 12]);

    assert_eq!(
        static_preflight_roots(&program).unwrap(),
        vec![base, base + 4, base + 8, base + 12]
    );
}

#[test]
fn aot_runtime_context_offsets_match_assembly_constants() {
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, trace_mode),
        AOT_CTX_TRACE_MODE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_latest_cells),
        AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_cycle),
        AOT_CTX_PREFLIGHT_CYCLE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pc_before),
        AOT_CTX_PREFLIGHT_PC_BEFORE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pc_after),
        AOT_CTX_PREFLIGHT_PC_AFTER_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_last_kind),
        AOT_CTX_PREFLIGHT_LAST_KIND_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_current_shard_start),
        AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, memory_prev_stamp),
        AOT_CTX_MEMORY_PREV_STAMP_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pending_steps),
        AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_step_cells_table),
        AOT_CTX_PREFLIGHT_STEP_CELLS_TABLE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_heap_start_word),
        AOT_CTX_PREFLIGHT_HEAP_START_WORD_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_hints_max),
        AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fallback_steps),
        AOT_CTX_FALLBACK_STEPS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_block_cells_table),
        AOT_CTX_PREFLIGHT_BLOCK_CELLS_TABLE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_block_cost_descriptors),
        AOT_CTX_PREFLIGHT_BLOCK_COST_DESCRIPTORS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_chip_contributions),
        AOT_CTX_PREFLIGHT_CHIP_CONTRIBUTIONS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_cost_table),
        AOT_CTX_PREFLIGHT_COST_TABLE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_num_instances),
        AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_num_chips),
        AOT_CTX_PREFLIGHT_NUM_CHIPS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pending_block),
        AOT_CTX_PREFLIGHT_PENDING_BLOCK_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_planner_cur_trace_cells),
        AOT_CTX_PREFLIGHT_PLANNER_CUR_TRACE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_planner_cur_main_peak),
        AOT_CTX_PREFLIGHT_PLANNER_CUR_MAIN_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_planner_cur_tower_peak),
        AOT_CTX_PREFLIGHT_PLANNER_CUR_TOWER_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_tower_cost_table),
        AOT_CTX_PREFLIGHT_TOWER_COST_TABLE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fallback_dynamic_pc),
        AOT_CTX_FALLBACK_DYNAMIC_PC_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fallback_memory_guard),
        AOT_CTX_FALLBACK_MEMORY_GUARD_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fallback_ecall),
        AOT_CTX_FALLBACK_ECALL_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fallback_exceptional),
        AOT_CTX_FALLBACK_EXCEPTIONAL_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fallback_reason),
        AOT_CTX_FALLBACK_REASON_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fallback_ecall_codes),
        AOT_CTX_FALLBACK_ECALL_CODES_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fallback_recovery_reason),
        AOT_CTX_FALLBACK_RECOVERY_REASON_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_event_cursor),
        AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_event_end),
        AOT_CTX_PREFLIGHT_EVENT_END_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_latest_len),
        AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, memory_end_word),
        AOT_CTX_MEMORY_END_WORD_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fulltracer_records),
        AOT_CTX_FULLTRACER_RECORDS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fulltracer_len),
        AOT_CTX_FULLTRACER_LEN_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fulltracer_pending_index),
        AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fulltracer_pending_cycle),
        AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fulltracer_latest_cells),
        AOT_CTX_FULLTRACER_LATEST_CELLS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fulltracer_latest_base),
        AOT_CTX_FULLTRACER_LATEST_BASE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fulltracer_latest_len),
        AOT_CTX_FULLTRACER_LATEST_LEN_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fulltracer_max_heap),
        AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, fulltracer_max_hint),
        AOT_CTX_FULLTRACER_MAX_HINT_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_register_touched_mask),
        AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_register_shard_start),
        AOT_CTX_PREFLIGHT_REGISTER_SHARD_START_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, memory_start_ordinal),
        AOT_CTX_MEMORY_START_ORDINAL_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_bucket_ceilings),
        AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_bucket_generations),
        AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_bucket_generation),
        AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pending_specialized),
        AOT_CTX_PREFLIGHT_PENDING_SPECIALIZED_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pending_chips),
        AOT_CTX_PREFLIGHT_PENDING_CHIPS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pending_deltas),
        AOT_CTX_PREFLIGHT_PENDING_DELTAS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pending_trace),
        AOT_CTX_PREFLIGHT_PENDING_TRACE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pending_main),
        AOT_CTX_PREFLIGHT_PENDING_MAIN_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_pending_tower),
        AOT_CTX_PREFLIGHT_PENDING_TOWER_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_memory_shard_start_ordinal),
        AOT_CTX_PREFLIGHT_MEMORY_SHARD_START_ORDINAL_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_block_kind_histograms),
        AOT_CTX_PREFLIGHT_BLOCK_KIND_HISTOGRAMS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_block_kind_histogram_count),
        AOT_CTX_PREFLIGHT_BLOCK_KIND_HISTOGRAM_COUNT_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_replay_range_len),
        AOT_CTX_PREFLIGHT_REPLAY_RANGE_LEN_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_replay_family_counts),
        AOT_CTX_PREFLIGHT_REPLAY_FAMILY_COUNTS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_replay_fallback_count),
        AOT_CTX_PREFLIGHT_REPLAY_FALLBACK_COUNT_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_replay_unsupported_count),
        AOT_CTX_PREFLIGHT_REPLAY_UNSUPPORTED_COUNT_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, preflight_replay_range_capacity),
        AOT_CTX_PREFLIGHT_REPLAY_RANGE_CAPACITY_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_kinds),
        AOT_CTX_GPU_REPLAY_KINDS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_kind_count),
        AOT_CTX_GPU_REPLAY_KIND_COUNT_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_ordinal),
        AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_pending_cycle),
        AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_latest_cells),
        AOT_CTX_GPU_REPLAY_LATEST_CELLS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_latest_base),
        AOT_CTX_GPU_REPLAY_LATEST_BASE_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_latest_len),
        AOT_CTX_GPU_REPLAY_LATEST_LEN_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_max_heap),
        AOT_CTX_GPU_REPLAY_MAX_HEAP_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_max_hint),
        AOT_CTX_GPU_REPLAY_MAX_HINT_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_events),
        AOT_CTX_GPU_REPLAY_EVENTS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_events_len),
        AOT_CTX_GPU_REPLAY_EVENTS_LEN_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_event_cursor),
        AOT_CTX_GPU_REPLAY_EVENT_CURSOR_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_error),
        AOT_CTX_GPU_REPLAY_ERROR_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_ordinary_callbacks),
        AOT_CTX_GPU_REPLAY_ORDINARY_CALLBACKS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, combined_saved),
        AOT_CTX_COMBINED_SAVED_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, layered_rs1_previous),
        AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, layered_rs2_previous),
        AOT_CTX_LAYERED_RS2_PREVIOUS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, layered_rd_previous),
        AOT_CTX_LAYERED_RD_PREVIOUS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, compact_bytes_cursor),
        AOT_CTX_COMPACT_BYTES_CURSOR_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, layered_next_access_events),
        AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, layered_next_access_events_len),
        AOT_CTX_LAYERED_NEXT_ACCESS_EVENTS_LEN_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, layered_next_access_cursor),
        AOT_CTX_LAYERED_NEXT_ACCESS_CURSOR_OFFSET
    );
    assert_eq!(
        std::mem::offset_of!(AotRuntimeContext, gpu_replay_packed_block),
        AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET
    );
}

#[test]
fn next_cost_bucket_ceiling_matches_ceil_log2_transitions() {
    assert_eq!(next_cost_bucket_ceiling(0), 1);
    assert_eq!(next_cost_bucket_ceiling(1), 2);
    assert_eq!(next_cost_bucket_ceiling(2), 3);
    assert_eq!(next_cost_bucket_ceiling(3), 5);
    assert_eq!(next_cost_bucket_ceiling(4), 5);
    assert_eq!(next_cost_bucket_ceiling(5), 9);
}

#[test]
fn invalid_instruction_errors_if_executed() {
    let program = Arc::new(program(vec![encode_rv32(InsnKind::INVALID, 0, 0, 0, 0)]));
    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut vm = VMState::new(CENO_PLATFORM.clone(), program);
    let err = aot.run_to_halt(&mut vm, 1).unwrap_err().to_string();
    assert!(err.contains("IllegalInstruction"));
}

#[test]
fn native_opcode_family_keeps_unsupported_ops_on_slow_path() {
    assert_eq!(
        native_opcode_family(InsnKind::ADD),
        Some(NativeOpcodeFamily::Compute)
    );
    assert_eq!(
        native_opcode_family(InsnKind::BEQ),
        Some(NativeOpcodeFamily::ControlFlow)
    );
    assert_eq!(
        native_opcode_family(InsnKind::LW),
        Some(NativeOpcodeFamily::Memory)
    );
    assert_eq!(
        native_opcode_family(InsnKind::DIV),
        Some(NativeOpcodeFamily::Compute)
    );
    assert_eq!(
        native_opcode_family(InsnKind::JALR),
        Some(NativeOpcodeFamily::ControlFlow)
    );
    assert_eq!(native_opcode_family(InsnKind::ECALL), None);
}

#[test]
fn aot_trace_matches_interpreter_for_supported_loop() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 5),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let tracer_config = crate::FullTracerConfig {
        max_step_shard: 100,
    };
    let mut interp = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        tracer_config,
    );
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        tracer_config,
    );
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
    assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
fn one_and_many_compile_workers_have_identical_semantics() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 4),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let blocks = partition_basic_blocks(&program).unwrap();
    let layout = pc_order_layout(&blocks);

    let compile = |jobs| {
        let dir = tempfile::tempdir().unwrap();
        let asm = dir.path().join("program.S");
        let so = dir.path().join("program.so");
        compile_native_to_with_jobs(
            &program,
            &blocks,
            &layout.emission_order,
            AssemblyTraceStyle::FullTracerDirect,
            None,
            &asm,
            &so,
            jobs,
        )
        .unwrap();
        let (library, entry) = load_native(&so, "fulltracer-direct", "test").unwrap();
        AotProgram {
            program: program.clone(),
            cache_identity: String::new(),
            artifact_path: None,
            blocks: blocks.clone(),
            layout_profile: layout.clone(),
            _library: library,
            entry,
            compile_load_time: Duration::ZERO,
            trace_style: AssemblyTraceStyle::FullTracerDirect,
            next_access_capacity: 0,
            planner_fingerprint: None,
        }
    };
    let one = compile(1);
    let many = compile(4);
    let config = crate::FullTracerConfig { max_step_shard: 16 };
    let mut one_vm = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config,
    );
    let mut many_vm = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    let one_report = one.run_to_halt(&mut one_vm, 32).unwrap();
    let many_report = many.run_to_halt(&mut many_vm, 32).unwrap();

    assert_eq!(one_report.executed_steps, many_report.executed_steps);
    assert_eq!(one_report.fallback, many_report.fallback);
    assert_eq!(one_vm.peek_register(1), many_vm.peek_register(1));
    assert_eq!(
        one_vm.tracer().recorded_steps(),
        many_vm.tracer().recorded_steps()
    );
}

#[test]
fn aot_preflight_direct_grows_tape_without_changing_accesses() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
    let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config.clone(),
    );
    while interp.next_step_record().unwrap().is_some() {}

    let mut aot =
        AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    aot.next_access_capacity = 1;
    let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    assert!(report.next_access_growths > 0);
    assert!(report.next_access_growth_bytes > 0);
    assert!(report.next_access_capacity > 1);
    let (interp_plan, interp_next, _) = interp.take_tracer().into_shard_plan();
    let (aot_plan, aot_next, _) = aot_vm.take_tracer().into_shard_plan();
    assert_eq!(aot_next, interp_next);
    assert_eq!(
        aot_plan.shard_cycle_boundaries(),
        interp_plan.shard_cycle_boundaries()
    );
}

#[test]
fn i049_preflight_capture_emits_exact_typed_ranges_and_sparse_halt() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
        encode_rv32(InsnKind::ADDI, 1, 0, 2, 5),
        encode_rv32(
            InsnKind::ADDI,
            0,
            0,
            Platform::reg_ecall().into(),
            Platform::ecall_halt() as i32,
        ),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 64 },
    );
    while reference.next_step_record().unwrap().is_some() {}

    let config = crate::PreflightTracerConfig::new(true, 2, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep))
        .with_replay_range_capacity(2)
        .with_combined_capture(true);
    let aot = AotProgram::compile_preflight_capture_with_extra_roots(program.clone(), Vec::new())
        .unwrap();
    let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    let report = aot.run_to_halt(&mut vm, 16).unwrap();
    assert_eq!(report.executed_steps, 4);
    let (ranges, syscalls, patches, initialization) =
        vm.tracer_mut().finish_combined_capture_for_test().unwrap();
    let patch_events = patches
        .iter()
        .map(|patch| {
            crate::NextAccessEvent::new(patch.source_cycle, patch.target_cycle, patch.address)
        })
        .chain(initialization.iter().copied())
        .collect::<Vec<_>>();
    reference
        .tracer_mut()
        .apply_next_access_events_for_test(&patch_events);
    assert_eq!(ranges.len(), 3);
    assert!(ranges.iter().all(|range| {
        range
            .typed
            .iter()
            .flatten()
            .map(crate::GpuTypedSoaArena::len)
            .sum::<usize>()
            + range.fallback.len()
            <= 2
    }));
    let ordinary = ranges
        .iter()
        .flat_map(|range| range.typed.iter().flatten())
        .map(crate::GpuTypedSoaArena::len)
        .sum::<usize>();
    let fallback = ranges
        .iter()
        .map(|range| range.fallback.len())
        .sum::<usize>();
    assert_eq!((ordinary, fallback, syscalls.len()), (3, 1, 0));
    let ordinals = ranges
        .iter()
        .filter_map(|range| range.typed[InsnKind::ADDI as usize].as_ref())
        .flat_map(|arena| arena.fields()[0][..arena.len()].iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(ordinals, [0, 1, 2]);
    assert_eq!(ranges.last().unwrap().fallback[0].ordinal, 3);
    let expected = reference.tracer().recorded_steps();
    for range in ranges {
        for arena in range.typed.iter().flatten() {
            for row in 0..arena.len() {
                let ordinal = arena.fields()[0][row] as usize;
                let mut oracle = crate::GpuTypedSoaArena::new(arena.kind(), 1).unwrap();
                oracle
                    .push_step(ordinal as u32, &expected[ordinal])
                    .unwrap();
                for (field_index, (actual, expected)) in
                    arena.fields().iter().zip(oracle.fields()).enumerate()
                {
                    assert_eq!(
                        actual[row],
                        expected[0],
                        "typed word mismatch kind={:?} ordinal={ordinal} field={field_index}",
                        arena.kind()
                    );
                }
            }
        }
        for fallback in &range.fallback {
            assert_eq!(
                fallback.record, expected[fallback.ordinal as usize],
                "sparse record mismatch ordinal={}",
                fallback.ordinal
            );
        }
    }
}

#[test]
fn i049_preflight_capture_matches_fulltracer_for_memory_and_multishard_reuse() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::SW, 20, 1, 0, 4),
        encode_rv32(InsnKind::LW, 20, 0, 2, 4),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(
            InsnKind::ADDI,
            0,
            0,
            Platform::reg_ecall().into(),
            Platform::ecall_halt() as i32,
        ),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 64 },
    );
    reference.init_register_unsafe(20, base);
    reference.init_memory(ByteAddr(base).waddr(), 37);
    reference.init_memory(ByteAddr(base + 4).waddr(), 0);
    while reference.next_step_record().unwrap().is_some() {}

    let config = crate::PreflightTracerConfig::new(true, 1, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep))
        .with_replay_range_capacity(2)
        .with_combined_capture(true);
    let roots = (1..6)
        .map(|index| CENO_PLATFORM.pc_base() + index * PC_STEP_SIZE as u32)
        .collect();
    let aot =
        AotProgram::compile_preflight_capture_with_extra_roots(program.clone(), roots).unwrap();
    let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    vm.init_register_unsafe(20, base);
    vm.init_memory(ByteAddr(base).waddr(), 37);
    vm.init_memory(ByteAddr(base + 4).waddr(), 0);
    assert_eq!(aot.run_to_halt(&mut vm, 16).unwrap().executed_steps, 6);
    let (ranges, syscalls, patches, initialization) =
        vm.tracer_mut().finish_combined_capture_for_test().unwrap();
    assert!(syscalls.is_empty());
    assert!(!initialization.is_empty());
    assert!(patches.iter().any(|patch| {
        patch.ram_class == crate::tracer::PatchRamClass::Memory
            && patch.target_shard > patch.source_shard + 1
    }));
    let events = patches
        .iter()
        .map(|patch| {
            crate::NextAccessEvent::new(patch.source_cycle, patch.target_cycle, patch.address)
        })
        .chain(initialization.iter().copied())
        .collect::<Vec<_>>();
    reference
        .tracer_mut()
        .apply_next_access_events_for_test(&events);
    let expected = reference.tracer().recorded_steps();
    for range in ranges {
        for arena in range.typed.iter().flatten() {
            for row in 0..arena.len() {
                let ordinal = arena.fields()[0][row] as usize;
                let mut oracle = crate::GpuTypedSoaArena::new(arena.kind(), 1).unwrap();
                oracle
                    .push_step(ordinal as u32, &expected[ordinal])
                    .unwrap();
                for (actual, expected) in arena.fields().iter().zip(oracle.fields()) {
                    assert_eq!(actual[row], expected[0]);
                }
            }
        }
        for fallback in &range.fallback {
            assert_eq!(fallback.record, expected[fallback.ordinal as usize]);
        }
    }
}

#[test]
fn i049_preflight_capture_matches_fulltracer_for_multiop_syscall() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(
            InsnKind::ADDI,
            0,
            0,
            Platform::reg_ecall().into(),
            Platform::ecall_halt() as i32,
        ),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let input: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
        crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 64 },
    );
    let config = crate::PreflightTracerConfig::new(true, 1, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep))
        .with_replay_range_capacity(2)
        .with_combined_capture(true);
    let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config,
    );
    for state in [
        &mut reference as &mut dyn SyscallTestVm,
        &mut vm as &mut dyn SyscallTestVm,
    ] {
        state.init_register(Platform::reg_ecall(), crate::SECP256K1_DOUBLE);
        state.init_register(Platform::reg_arg0(), base);
        state.init_register(20, base);
        for (offset, value) in input.into_iter().enumerate() {
            state.init_word(ByteAddr(base).waddr() + offset, value);
        }
    }
    while reference.next_step_record().unwrap().is_some() {}
    let roots = (1..4)
        .map(|index| CENO_PLATFORM.pc_base() + index * PC_STEP_SIZE as u32)
        .collect();
    let aot = AotProgram::compile_preflight_capture_with_extra_roots(program, roots).unwrap();
    assert_eq!(aot.run_to_halt(&mut vm, 16).unwrap().executed_steps, 4);
    let (ranges, syscalls, patches, initialization) =
        vm.tracer_mut().finish_combined_capture_for_test().unwrap();
    let events = patches
        .iter()
        .map(|patch| {
            crate::NextAccessEvent::new(patch.source_cycle, patch.target_cycle, patch.address)
        })
        .chain(initialization.iter().copied())
        .collect::<Vec<_>>();
    reference
        .tracer_mut()
        .apply_next_access_events_for_test(&events);
    assert_eq!(syscalls, reference.tracer().syscall_witnesses());
    let expected = reference.tracer().recorded_steps();
    for fallback in ranges.iter().flat_map(|range| &range.fallback) {
        assert_eq!(fallback.record, expected[fallback.ordinal as usize]);
    }
    assert!(patches.iter().any(|patch| matches!(
        patch.source_lane,
        crate::tracer::PatchSourceLane::SyscallMemory
            | crate::tracer::PatchSourceLane::SyscallRegister
    )));
}

trait SyscallTestVm {
    fn init_register(&mut self, index: RegIdx, value: Word);
    fn init_word(&mut self, address: WordAddr, value: Word);
}

impl<T: crate::Tracer> SyscallTestVm for VMState<T> {
    fn init_register(&mut self, index: RegIdx, value: Word) {
        self.init_register_unsafe(index, value);
    }

    fn init_word(&mut self, address: WordAddr, value: Word) {
        self.init_memory(address, value);
    }
}

#[test]
fn i049_production_capture_syscalls_match_canonical_raw_next_access_tape() {
    let codes = [267, 268, 270, 65801, 65802, 65840];
    assert_eq!(crate::SECP256K1_DOUBLE, codes[0]);
    assert_eq!(crate::SECP256K1_DECOMPRESS, codes[1]);
    assert_eq!(crate::SECP256K1_SCALAR_INVERT, codes[2]);
    assert_eq!(crate::KECCAK_PERMUTE, codes[3]);
    assert_eq!(crate::SECP256K1_ADD, codes[4]);
    assert_eq!(crate::KECCAK_XORIN, codes[5]);

    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(
            InsnKind::ADDI,
            0,
            0,
            Platform::reg_ecall().into(),
            Platform::ecall_halt() as i32,
        ),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let roots = (1..4)
        .map(|index| CENO_PLATFORM.pc_base() + index * PC_STEP_SIZE as u32)
        .collect::<Vec<_>>();
    let production =
        AotProgram::compile_preflight_with_extra_roots(program.clone(), roots.clone()).unwrap();
    let capture =
        AotProgram::compile_preflight_capture_with_extra_roots(program.clone(), roots).unwrap();
    let generator: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
        crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();
    let doubled = crate::syscalls::secp256k1::double_words(generator);

    for code in codes {
        let first = CENO_PLATFORM.heap.start;
        let second = first + 256;
        let arg1 = if code == crate::SECP256K1_DECOMPRESS {
            0
        } else {
            second
        };
        let config = crate::PreflightTracerConfig::new(true, 1, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
        let mut expected = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.clone(),
        );
        let mut actual = VMState::<crate::PreflightTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            config.with_combined_capture(true),
        );
        let mut first_words = [0; 64];
        let mut second_words = [0; 64];
        match code {
            crate::SECP256K1_DOUBLE | crate::SECP256K1_ADD => {
                first_words[..generator.len()].copy_from_slice(&generator);
                second_words[..doubled.len()].copy_from_slice(&doubled);
            }
            crate::SECP256K1_DECOMPRESS => {
                let encoded = secp::Point::generator().serialize_uncompressed();
                let x: [u8; 32] = encoded[1..33].try_into().unwrap();
                let x: [Word; crate::syscalls::secp256k1::COORDINATE_WORDS] =
                    unsafe { std::mem::transmute(x) };
                first_words[..x.len()].copy_from_slice(&x);
            }
            crate::SECP256K1_SCALAR_INVERT => {
                first_words[..crate::syscalls::secp256k1::COORDINATE_WORDS].fill(1);
            }
            _ => {
                for (offset, (first, second)) in
                    first_words.iter_mut().zip(&mut second_words).enumerate()
                {
                    *first = offset as Word;
                    *second = !*first;
                }
            }
        }
        for vm in [&mut expected, &mut actual] {
            vm.init_register_unsafe(Platform::reg_ecall(), code);
            vm.init_register_unsafe(Platform::reg_arg0(), first);
            vm.init_register_unsafe(Platform::reg_arg1(), arg1);
            for offset in 0usize..64 {
                vm.init_memory(ByteAddr(first).waddr() + offset, first_words[offset]);
                vm.init_memory(ByteAddr(second).waddr() + offset, second_words[offset]);
            }
        }

        let expected_report = production.run_to_halt(&mut expected, 16).unwrap();
        let actual_report = capture.run_to_halt(&mut actual, 16).unwrap();
        assert_eq!(expected_report.executed_steps, 4, "code={code}");
        assert_eq!(actual_report.executed_steps, 4, "code={code}");
        assert_eq!(
            expected_report.fallback.ecall_by_code[&code], 2,
            "code={code}"
        );
        assert_eq!(
            actual_report.fallback.ecall_by_code[&code], 2,
            "code={code}"
        );
        let expected_events = expected.tracer().raw_next_access_events_for_test().to_vec();
        let actual_events = actual.tracer().raw_next_access_events_for_test().to_vec();
        assert_eq!(
            actual_events, expected_events,
            "raw tape differs for code={code}"
        );
        let (expected_plan, _, _) = expected.take_tracer().into_shard_plan();
        let (actual_plan, _, _) = actual.take_tracer().into_shard_plan();
        assert_eq!(
            actual_plan.shard_cycle_boundaries(),
            expected_plan.shard_cycle_boundaries(),
            "shard boundaries differ for code={code}",
        );
    }
}

#[test]
fn aot_preflight_direct_syscall_matches_generic_tracking() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(
            InsnKind::ADDI,
            0,
            0,
            Platform::reg_ecall().into(),
            Platform::ecall_halt() as i32,
        ),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let config = crate::PreflightTracerConfig::new(true, 64, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
    let input: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
        crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();

    let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config.clone(),
    );
    let mut direct = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config,
    );
    for vm in [&mut interp, &mut direct] {
        vm.init_register_unsafe(Platform::reg_ecall(), crate::SECP256K1_DOUBLE);
        vm.init_register_unsafe(Platform::reg_arg0(), base);
        for (offset, value) in input.into_iter().enumerate() {
            vm.init_memory(ByteAddr(base).waddr() + offset, value);
        }
    }
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_preflight_with_extra_roots(program, Vec::new()).unwrap();
    let report = aot.run_to_halt(&mut direct, 64).unwrap();
    assert_eq!(report.executed_steps, 3);
    assert_eq!(report.fallback.ecall_by_code[&crate::SECP256K1_DOUBLE], 1);
    for offset in 0..crate::syscalls::secp256k1::SECP256K1_ARG_WORDS {
        let addr = ByteAddr(base).waddr() + offset;
        assert_eq!(direct.peek_memory(addr), interp.peek_memory(addr));
        assert_eq!(
            direct.final_access_cycle(addr),
            interp.final_access_cycle(addr)
        );
    }
    assert_eq!(direct.final_access_count(), interp.final_access_count());
    for addr in interp.final_access_addresses() {
        assert_eq!(
            direct.final_access_cycle(addr),
            interp.final_access_cycle(addr)
        );
    }
    let (interp_plan, interp_next, _) = interp.take_tracer().into_shard_plan();
    let (direct_plan, direct_next, _) = direct.take_tracer().into_shard_plan();
    assert_eq!(direct_next, interp_next);
    assert_eq!(
        direct_plan.shard_cycle_boundaries(),
        interp_plan.shard_cycle_boundaries()
    );
}

#[derive(Debug)]
struct OneCellPerNativeStep;

impl crate::StepCellExtractor for OneCellPerNativeStep {
    fn cells_for_kind(&self, kind: InsnKind, _rs1_value: Option<crate::addr::Word>) -> u64 {
        if native_opcode_family(kind).is_some() {
            1
        } else {
            0
        }
    }

    fn shard_cost_model(&self) -> Option<Arc<ShardCostModel>> {
        let mut opcodes = vec![vec![0]; InsnKind::COUNT];
        opcodes[InsnKind::ECALL as usize].clear();
        let mut ecalls = BTreeMap::new();
        ecalls.insert(Platform::ecall_halt(), vec![0]);
        ecalls.insert(crate::SECP256K1_DOUBLE, vec![0]);
        ecalls.insert(crate::SECP256K1_ADD, vec![0]);
        ecalls.insert(crate::SECP256K1_DECOMPRESS, vec![0]);
        ecalls.insert(crate::KECCAK_PERMUTE, vec![0]);
        ecalls.insert(crate::KECCAK_XORIN, vec![0]);
        ecalls.insert(crate::SECP256K1_SCALAR_INVERT, vec![0]);
        Some(Arc::new(ShardCostModel::new(
            opcodes,
            ecalls,
            vec![ChipCostSpec {
                rotation: 0,
                trace_cells_per_row: 1,
                tower_peak_cells_per_row: 0,
                tower_peak_cells_by_bucket: None,
            }],
            1,
        )))
    }
}

#[test]
fn pure_and_full_paths_match_guest_state() {
    let base = CENO_PLATFORM.stack.start + 64;
    let memory_addr = ByteAddr(base).waddr();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
        encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
        encode_rv32(InsnKind::SW, 20, 2, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let full_aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut full = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 5 },
    );
    full.init_register_unsafe(20, base);
    full.init_memory(memory_addr, 0);
    let full_report = full_aot.run_to_halt(&mut full, 16).unwrap();

    let pure_aot = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::Pure,
    )
    .unwrap();
    let mut pure = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
    pure.init_register_unsafe(20, base);
    pure.init_memory(memory_addr, 0);
    let pure_report = pure_aot.run_pure_to_halt(&mut pure, 16).unwrap();

    assert_eq!(full_report.executed_steps, 5);
    assert_eq!(pure_report.executed_steps, full_report.executed_steps);
    assert_eq!(
        pure.halted_state().map(|state| state.exit_code),
        full.halted_state().map(|state| state.exit_code)
    );
    assert_eq!(pure.get_pc(), full.get_pc());
    for register in [1, 2, 3, 20] {
        assert_eq!(pure.peek_register(register), full.peek_register(register));
    }
    assert_eq!(pure.peek_memory(memory_addr), 14);
    assert_eq!(pure.peek_memory(memory_addr), full.peek_memory(memory_addr));
}

#[test]
fn cached_aot_hit_and_corrupt_rebuild_match_preflight_state() {
    let cache = tempfile::tempdir().unwrap();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
        encode_rv32(InsnKind::ADDI, 1, 0, 2, 9),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));

    let cold = AotProgram::load_or_train_preflight_in(
        &CENO_PLATFORM,
        program.clone(),
        [],
        config.clone(),
        cache.path(),
    )
    .unwrap();
    let warm = AotProgram::load_or_train_preflight_in(
        &CENO_PLATFORM,
        program.clone(),
        [(ByteAddr(CENO_PLATFORM.heap.start).waddr(), 0x1234)],
        config.clone(),
        cache.path(),
    )
    .unwrap();
    let mut cold_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config.clone(),
    );
    let mut warm_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config.clone(),
    );
    let cold_report = cold.run_to_halt(&mut cold_vm, 10).unwrap();
    let warm_report = warm.run_to_halt(&mut warm_vm, 10).unwrap();
    assert_eq!(cold_report.executed_steps, warm_report.executed_steps);
    assert_eq!(cold_report.fallback, warm_report.fallback);
    assert_eq!(cold_report.fallback.dynamic_pc_miss, 0);
    assert_eq!(
        cold_report
            .fallback
            .ecall_by_code
            .get(&Platform::ecall_halt()),
        Some(&1)
    );
    for idx in 0..VMState::<crate::PreflightTracer>::REG_COUNT as u8 {
        assert_eq!(cold_vm.peek_register(idx), warm_vm.peek_register(idx));
    }
    for addr in cold_vm.final_access_addresses() {
        assert_eq!(
            cold_vm.final_access_cycle(addr),
            warm_vm.final_access_cycle(addr)
        );
    }
    let (cold_plan, cold_next, _) = cold_vm.take_tracer().into_shard_plan();
    let (warm_plan, warm_next, _) = warm_vm.take_tracer().into_shard_plan();
    assert_eq!(cold_next, warm_next);
    assert_eq!(
        cold_plan.shard_cycle_boundaries(),
        warm_plan.shard_cycle_boundaries()
    );
    let expected_steps = warm_report.executed_steps;
    let expected_fallback = warm_report.fallback.clone();
    drop(cold);
    drop(warm);

    let key = format!(
        "{}-cells{}-cycles{}",
        planner_cache_key(
            &program,
            production_preflight_trace_style(),
            &config
                .step_cell_extractor()
                .and_then(|extractor| extractor.shard_cost_model())
                .unwrap(),
        ),
        config.max_cell_per_shard(),
        config.max_cycle_per_shard()
    );
    let (so_path, _) = cache_paths(cache.path(), &key);
    fs::write(&so_path, b"corrupt").unwrap();
    let rebuilt = AotProgram::load_or_train_preflight_in(
        &CENO_PLATFORM,
        program.clone(),
        [],
        config.clone(),
        cache.path(),
    )
    .unwrap();
    let mut rebuilt_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config.clone(),
    );
    let rebuilt_report = rebuilt.run_to_halt(&mut rebuilt_vm, 10).unwrap();
    assert_eq!(rebuilt_report.executed_steps, expected_steps);
    assert_eq!(rebuilt_report.fallback, expected_fallback);
    drop(rebuilt);

    let (_, metadata_path) = cache_paths(cache.path(), &key);
    let metadata = fs::read_to_string(&metadata_path).unwrap();
    fs::write(
        &metadata_path,
        metadata.replacen(&key, "wrong-program-or-abi", 1),
    )
    .unwrap();
    let identity_rebuilt = AotProgram::load_or_train_preflight_in(
        &CENO_PLATFORM,
        program.clone(),
        [],
        config.clone(),
        cache.path(),
    )
    .unwrap();
    let mut identity_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    let identity_report = identity_rebuilt.run_to_halt(&mut identity_vm, 10).unwrap();
    assert_eq!(identity_report.executed_steps, expected_steps);
}

#[test]
fn specialized_planner_matches_generic_finite_cell_shards() {
    let cache = tempfile::tempdir().unwrap();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 8),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let config = crate::PreflightTracerConfig::new(true, 4, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
    let generic_aot =
        AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    let mut generic = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config.clone(),
    );
    let generic_report = generic_aot.run_to_halt(&mut generic, 64).unwrap();

    let aot = AotProgram::load_or_train_preflight_in(
        &CENO_PLATFORM,
        program.clone(),
        [],
        config.clone(),
        cache.path(),
    )
    .unwrap();
    let mut direct = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    let report = aot.run_to_halt(&mut direct, 64).unwrap();
    assert_eq!(report.fallback, generic_report.fallback);
    let (generic_plan, generic_next, _) = generic.take_tracer().into_shard_plan();
    let (direct_plan, direct_next, _) = direct.take_tracer().into_shard_plan();
    assert_eq!(
        direct_plan.shard_cycle_boundaries(),
        generic_plan.shard_cycle_boundaries()
    );
    assert_eq!(
        direct_plan.predicted_shard_costs(),
        generic_plan.predicted_shard_costs()
    );
    assert_eq!(direct_next, generic_next);
}

#[test]
fn unseen_later_indirect_target_uses_dynamic_pc_fallback() {
    let base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let aot =
        AotProgram::compile_preflight_with_extra_roots(program.clone(), vec![base + 4]).unwrap();
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
    let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    vm.init_register_unsafe(1, base + 8);
    let report = aot.run_to_halt(&mut vm, 10).unwrap();
    assert_eq!(report.fallback.dynamic_pc_miss, 1);
}

#[derive(Debug)]
struct AdaptiveTestCost(Arc<ShardCostModel>);

impl AdaptiveTestCost {
    fn new() -> Self {
        let mut opcodes = vec![Vec::new(); InsnKind::COUNT];
        opcodes[InsnKind::ADDI as usize] = vec![0];
        opcodes[InsnKind::ADD as usize] = vec![1];
        opcodes[InsnKind::JAL as usize] = vec![2];
        let mut ecalls = BTreeMap::new();
        ecalls.insert(Platform::ecall_halt(), vec![3]);
        Self(Arc::new(ShardCostModel::new(
            opcodes,
            ecalls,
            vec![
                ChipCostSpec {
                    rotation: 0,
                    trace_cells_per_row: 1,
                    tower_peak_cells_per_row: 0,
                    tower_peak_cells_by_bucket: None,
                },
                ChipCostSpec {
                    rotation: 0,
                    trace_cells_per_row: 1,
                    tower_peak_cells_per_row: 8,
                    tower_peak_cells_by_bucket: None,
                },
                ChipCostSpec {
                    rotation: 0,
                    trace_cells_per_row: 1,
                    tower_peak_cells_per_row: 0,
                    tower_peak_cells_by_bucket: None,
                },
                ChipCostSpec {
                    rotation: 0,
                    trace_cells_per_row: 1,
                    tower_peak_cells_per_row: 0,
                    tower_peak_cells_by_bucket: None,
                },
            ],
            4,
        )))
    }
}

impl crate::StepCellExtractor for AdaptiveTestCost {
    fn cells_for_kind(&self, _kind: InsnKind, _rs1_value: Option<Word>) -> u64 {
        0
    }

    fn shard_cost_model(&self) -> Option<Arc<ShardCostModel>> {
        Some(self.0.clone())
    }
}

fn adaptive_test_program() -> Arc<Program> {
    Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
        encode_rv32(InsnKind::JAL, 0, 0, 0, 4),
        encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
        encode_rv32(InsnKind::ADD, 2, 3, 4, 0),
        encode_rv32(InsnKind::JAL, 0, 0, 0, 4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]))
}

#[test]
fn aot_adaptive_cost_splits_before_blocks_and_reinitializes_rejected_block() {
    let program = adaptive_test_program();
    // The first block exactly fills the limit and must be accepted. The
    // second block is oversized on an empty shard and must also run once.
    let config = crate::PreflightTracerConfig::new(true, 7, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(AdaptiveTestCost::new()));
    let aot = AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    let report = aot.run_to_halt(&mut vm, 100).unwrap();
    let (plan, _, _) = vm.take_tracer().into_shard_plan();
    assert_eq!(plan.shard_cycle_boundaries(), &[4, 16, 28, 32]);
    assert_eq!(plan.predicted_shard_costs(), &[7, 19, 1]);
    assert_eq!(report.fallback.dynamic_pc_miss, 0);
}

#[test]
fn aot_adaptive_cost_honors_cycle_limit_at_block_boundaries() {
    let program = adaptive_test_program();
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, 16)
        .with_step_cell_extractor(Arc::new(AdaptiveTestCost::new()));
    let aot = AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    aot.run_to_halt(&mut vm, 100).unwrap();
    let (plan, _, _) = vm.take_tracer().into_shard_plan();
    assert_eq!(plan.shard_cycle_boundaries(), &[4, 16, 28, 32]);
    assert_eq!(plan.predicted_shard_costs(), &[7, 19, 1]);
}

#[test]
fn preflight_block_aot_requires_shard_cost_model() {
    let program = Arc::new(program(vec![encode_rv32(InsnKind::ADDI, 0, 0, 1, 1)]));
    let aot = AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    let mut vm = VMState::<crate::PreflightTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);

    let err = aot.run_to_halt(&mut vm, 10).unwrap_err().to_string();
    assert!(err.contains("preflight block AOT requires a shard cost model"));
}

#[test]
fn aot_preflight_block_plan_matches_without_shard_cuts() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
        encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));

    let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config.clone(),
    );
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    assert_eq!(aot.trace_style, production_preflight_trace_style());
    let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
    assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
    assert_eq!(aot_vm.final_access_count(), interp.final_access_count());
    for addr in interp.final_access_addresses() {
        assert_eq!(
            aot_vm.final_access_cycle(addr),
            interp.final_access_cycle(addr),
            "final access mismatch at {addr:?}"
        );
    }

    let (interp_plan, interp_next, _) = interp.take_tracer().into_shard_plan();
    let (aot_plan, aot_next, _) = aot_vm.take_tracer().into_shard_plan();
    assert_eq!(aot_next, interp_next);
    assert_eq!(
        aot_plan.shard_cycle_boundaries(),
        interp_plan.shard_cycle_boundaries()
    );
    assert_eq!(aot_plan.max_step_shard(), interp_plan.max_step_shard());
}

#[test]
fn preflight_block_plan_only_accepts_static_register_blocks() {
    let compute = program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
        encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
    ]);
    let block = BasicBlock {
        start_pc: compute.base_address,
        end_pc: compute.base_address + 8,
    };
    assert!(block_supports_preflight_block_plan(&compute, &block).unwrap());

    let memory = program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 0)]);
    let block = BasicBlock {
        start_pc: memory.base_address,
        end_pc: memory.base_address + 4,
    };
    assert_eq!(
        preflight_block_plan_kind(&memory, &block).unwrap(),
        Some(PreflightBlockPlanKind::MemoryExactAccess)
    );

    let dynamic_memory_base = program(vec![
        encode_rv32(InsnKind::ADDI, 20, 0, 20, 4),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
    ]);
    let block = BasicBlock {
        start_pc: dynamic_memory_base.base_address,
        end_pc: dynamic_memory_base.base_address + 8,
    };
    assert_eq!(
        preflight_block_plan_kind(&dynamic_memory_base, &block).unwrap(),
        None
    );

    let jalr = program(vec![encode_rv32(InsnKind::JALR, 1, 0, 0, 0)]);
    let block = BasicBlock {
        start_pc: jalr.base_address,
        end_pc: jalr.base_address + 4,
    };
    assert!(!block_supports_preflight_block_plan(&jalr, &block).unwrap());

    let ecall = program(vec![encode_rv32(InsnKind::ECALL, 0, 0, 0, 0)]);
    let block = BasicBlock {
        start_pc: ecall.base_address,
        end_pc: ecall.base_address + 4,
    };
    assert!(!block_supports_preflight_block_plan(&ecall, &block).unwrap());
}

#[test]
fn preflight_register_mask_covers_internal_x0_sink() {
    assert_eq!(preflight_register_bit(32), 1u64 << 32);
}

#[test]
fn initial_register_touched_mask_is_shard_local() {
    let mut latest = vec![0; (VMState::<PreflightTracer>::REG_COUNT - 1) * 64 + 1];
    latest[1 << 6] = 9;
    latest[2 << 6] = 10;
    latest[32 << 6] = 12;
    let shard_start = 10;

    let (mask, observed_start) =
        initial_preflight_register_touched_mask(latest.as_ptr(), &shard_start);

    assert_eq!(observed_start, shard_start);
    assert_eq!(mask, (1u64 << 2) | (1u64 << 32));
}

#[test]
fn aot_preflight_block_plan_simple_memory_keeps_exact_accesses() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 2, 1),
        encode_rv32(InsnKind::SW, 20, 2, 0, 4),
        encode_rv32(InsnKind::ADDI, 2, 0, 3, 1),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));

    let mut interp = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config.clone(),
    );
    interp.init_register_unsafe(20, base);
    interp.init_memory(ByteAddr(base).waddr(), 41);
    interp.init_memory(ByteAddr(base + 4).waddr(), 0);
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    aot_vm.init_register_unsafe(20, base);
    aot_vm.init_memory(ByteAddr(base).waddr(), 41);
    aot_vm.init_memory(ByteAddr(base + 4).waddr(), 0);
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    for idx in 0..VMState::<crate::PreflightTracer>::REG_COUNT as u8 {
        assert_eq!(
            aot_vm.peek_register(idx),
            interp.peek_register(idx),
            "register x{idx} mismatch"
        );
    }
    assert_eq!(
        aot_vm.peek_memory(ByteAddr(base + 4).waddr()),
        interp.peek_memory(ByteAddr(base + 4).waddr())
    );

    let (interp_plan, interp_next, _) = interp.take_tracer().into_shard_plan();
    let (aot_plan, aot_next, _) = aot_vm.take_tracer().into_shard_plan();
    assert_eq!(aot_next, interp_next);
    assert_eq!(
        aot_plan.shard_cycle_boundaries(),
        interp_plan.shard_cycle_boundaries()
    );
    assert_eq!(aot_plan.max_step_shard(), interp_plan.max_step_shard());
}

#[test]
fn aot_preflight_block_plan_memory_guard_falls_back_to_exact_path() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::LW, 20, 0, 1, 1),
        encode_rv32(InsnKind::ADDI, 1, 0, 2, 1),
    ]));
    let aot = AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
    let mut aot_vm = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    aot_vm.init_register_unsafe(20, base);

    let err = aot.run_to_halt(&mut aot_vm, 10).unwrap_err().to_string();

    assert!(err.contains("LoadAddressMisaligned"));
}

#[test]
fn dense_non_mmio_memory_stays_native() {
    let data_addr = CENO_PLATFORM.heap.end;
    let mut platform = CENO_PLATFORM.clone();
    platform.prog_data = Arc::new(BTreeSet::from([data_addr]));
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 2, 1),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let aot = AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
    let mut vm =
        VMState::<crate::PreflightTracer>::new_with_tracer_config(platform, program, config);
    vm.init_register_unsafe(20, data_addr);
    vm.init_memory(ByteAddr(data_addr).waddr(), 41);

    let report = aot.run_to_halt(&mut vm, 10).unwrap();

    assert_eq!(vm.peek_register(2), 42);
    assert_eq!(report.fallback.dynamic_pc_miss, 0);
    assert_eq!(report.fallback.memory_guard, 0);
}

#[test]
fn aot_native_arithmetic_matches_interpreter() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, -1),
        encode_rv32(InsnKind::ADDI, 1, 0, 2, 2),
        encode_rv32(InsnKind::XORI, 2, 0, 3, -1),
        encode_rv32(InsnKind::ORI, 3, 0, 4, 0x55),
        encode_rv32(InsnKind::ANDI, 4, 0, 6, 0x0f),
        encode_rv32(InsnKind::ADD, 1, 6, 7, 0),
        encode_rv32(InsnKind::SUB, 7, 6, 8, 0),
        encode_rv32(InsnKind::XOR, 8, 7, 9, 0),
        encode_rv32(InsnKind::OR, 9, 6, 12, 0),
        encode_rv32(InsnKind::AND, 12, 7, 13, 0),
        encode_rv32(InsnKind::ADDI, 13, 0, 0, 123),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
        assert_eq!(
            aot_vm.peek_register(idx),
            interp.peek_register(idx),
            "register x{idx} mismatch"
        );
    }
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
fn aot_native_shifts_and_comparisons_match_interpreter() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 33),
        encode_rv32(InsnKind::SLL, 1, 2, 3, 0),
        encode_rv32(InsnKind::SRL, 3, 2, 4, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 6, -8),
        encode_rv32(InsnKind::SRAI, 6, 0, 7, 1),
        encode_rv32(InsnKind::SRA, 6, 2, 8, 0),
        encode_rv32(InsnKind::SLLI, 1, 0, 9, 31),
        encode_rv32(InsnKind::SRLI, 9, 0, 12, 31),
        encode_rv32(InsnKind::SLT, 6, 1, 13, 0),
        encode_rv32(InsnKind::SLTU, 6, 1, 14, 0),
        encode_rv32(InsnKind::SLTI, 6, 0, 15, -7),
        encode_rv32(InsnKind::SLTIU, 6, 0, 16, -7),
        encode_rv32(InsnKind::SLTIU, 1, 0, 17, -1),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
        assert_eq!(
            aot_vm.peek_register(idx),
            interp.peek_register(idx),
            "register x{idx} mismatch"
        );
    }
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
fn aot_native_branches_and_jal_match_interpreter() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, -1),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 1),
        encode_rv32(InsnKind::BEQ, 2, 2, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 3, 99),
        encode_rv32(InsnKind::BNE, 1, 2, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 4, 99),
        encode_rv32(InsnKind::BLT, 1, 2, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 6, 99),
        encode_rv32(InsnKind::BGE, 2, 1, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 7, 99),
        encode_rv32(InsnKind::BLTU, 1, 2, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 8, 8),
        encode_rv32(InsnKind::BGEU, 1, 2, 0, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 9, 99),
        encode_rv32(InsnKind::JAL, 0, 0, 12, 8),
        encode_rv32(InsnKind::ADDI, 0, 0, 13, 99),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
        assert_eq!(
            aot_vm.peek_register(idx),
            interp.peek_register(idx),
            "register x{idx} mismatch"
        );
    }
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
fn aot_native_multiply_matches_interpreter() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, -1),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
        encode_rv32(InsnKind::MUL, 1, 2, 3, 0),
        encode_rv32(InsnKind::MULH, 1, 2, 4, 0),
        encode_rv32(InsnKind::MULHU, 1, 2, 6, 0),
        encode_rv32(InsnKind::MULHSU, 1, 2, 7, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 8, 1),
        encode_rv32(InsnKind::SLLI, 8, 0, 8, 31),
        encode_rv32(InsnKind::MUL, 8, 1, 9, 0),
        encode_rv32(InsnKind::MULH, 8, 1, 11, 0),
        encode_rv32(InsnKind::MULHU, 8, 1, 12, 0),
        encode_rv32(InsnKind::MULHSU, 8, 1, 13, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
        assert_eq!(
            aot_vm.peek_register(idx),
            interp.peek_register(idx),
            "register x{idx} mismatch"
        );
    }
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
fn aot_native_div_rem_matches_interpreter() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, -7),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 3),
        encode_rv32(InsnKind::DIV, 1, 2, 3, 0),
        encode_rv32(InsnKind::REM, 1, 2, 4, 0),
        encode_rv32(InsnKind::DIVU, 1, 2, 6, 0),
        encode_rv32(InsnKind::REMU, 1, 2, 7, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 8, 1),
        encode_rv32(InsnKind::SLLI, 8, 0, 8, 31),
        encode_rv32(InsnKind::ADDI, 0, 0, 9, -1),
        encode_rv32(InsnKind::DIV, 8, 9, 11, 0),
        encode_rv32(InsnKind::REM, 8, 9, 12, 0),
        encode_rv32(InsnKind::DIV, 1, 0, 13, 0),
        encode_rv32(InsnKind::REM, 1, 0, 14, 0),
        encode_rv32(InsnKind::DIVU, 1, 0, 15, 0),
        encode_rv32(InsnKind::REMU, 1, 0, 16, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
        assert_eq!(
            aot_vm.peek_register(idx),
            interp.peek_register(idx),
            "register x{idx} mismatch"
        );
    }
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
#[cfg(feature = "u16limb_circuit")]
fn aot_native_lui_auipc_matches_interpreter() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::LUI, 0, 0, 1, 0x1234),
        encode_rv32(InsnKind::AUIPC, 0, 0, 2, 0x40),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
    assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
fn aot_native_lw_sw_match_interpreter() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, 5),
        encode_rv32(InsnKind::SW, 20, 1, 0, 4),
        encode_rv32(InsnKind::LW, 20, 0, 2, 4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let tracer_config = crate::FullTracerConfig {
        max_step_shard: 100,
    };
    let mut interp = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        tracer_config,
    );
    interp.init_register_unsafe(20, base);
    interp.init_memory(ByteAddr(base).waddr(), 37);
    interp.init_memory(ByteAddr(base + 4).waddr(), 0);
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        tracer_config,
    );
    aot_vm.init_register_unsafe(20, base);
    aot_vm.init_memory(ByteAddr(base).waddr(), 37);
    aot_vm.init_memory(ByteAddr(base + 4).waddr(), 0);
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
        assert_eq!(
            aot_vm.peek_register(idx),
            interp.peek_register(idx),
            "register x{idx} mismatch"
        );
    }
    assert_eq!(aot_vm.peek_memory(ByteAddr(base + 4).waddr()), 42);
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
fn aot_pure_execution_updates_state_without_native_trace_callbacks() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
        encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
        encode_rv32(InsnKind::SW, 20, 2, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
    interp.init_register_unsafe(20, base);
    interp.init_memory(ByteAddr(base).waddr(), 0);
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::Pure,
    )
    .unwrap();
    let mut aot_vm = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
    aot_vm.init_register_unsafe(20, base);
    aot_vm.init_memory(ByteAddr(base).waddr(), 0);
    let report = aot.run_pure_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    assert!(aot_vm.halted());
    assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
    assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
    assert_eq!(
        aot_vm.peek_memory(ByteAddr(base).waddr()),
        interp.peek_memory(ByteAddr(base).waddr())
    );
    assert_eq!(aot_vm.final_access_cycle(ByteAddr(base).waddr()), 0);
    assert_eq!(report.fallback_steps, 1);
    assert_eq!(
        report.execute_time,
        report.native_time() + report.fallback_time
    );
}

#[test]
fn aot_native_byte_halfword_memory_matches_interpreter() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::LB, 20, 0, 1, 2),
        encode_rv32(InsnKind::LBU, 20, 0, 2, 2),
        encode_rv32(InsnKind::LH, 20, 0, 3, 2),
        encode_rv32(InsnKind::LHU, 20, 0, 4, 2),
        encode_rv32(InsnKind::ADDI, 0, 0, 6, 0x55),
        encode_rv32(InsnKind::SB, 20, 6, 0, 1),
        encode_rv32(InsnKind::ADDI, 0, 0, 7, 0xabcd),
        encode_rv32(InsnKind::SH, 20, 7, 0, 4),
        encode_rv32(InsnKind::LW, 20, 0, 8, 0),
        encode_rv32(InsnKind::LW, 20, 0, 9, 4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
    interp.init_register_unsafe(20, base);
    interp.init_memory(ByteAddr(base).waddr(), 0x80ff_7f00);
    interp.init_memory(ByteAddr(base + 4).waddr(), 0);
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
    aot_vm.init_register_unsafe(20, base);
    aot_vm.init_memory(ByteAddr(base).waddr(), 0x80ff_7f00);
    aot_vm.init_memory(ByteAddr(base + 4).waddr(), 0);
    let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

    assert_eq!(report.executed_steps, interp.tracer().executed_insts());
    for idx in 0..VMState::<crate::FullTracer>::REG_COUNT as u8 {
        assert_eq!(
            aot_vm.peek_register(idx),
            interp.peek_register(idx),
            "register x{idx} mismatch"
        );
    }
    assert_eq!(aot_vm.peek_memory(ByteAddr(base).waddr()), 0x80ff_5500);
    assert_eq!(aot_vm.peek_memory(ByteAddr(base + 4).waddr()), 0xabcd);
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
fn aot_memory_misalignment_uses_exact_slow_path_traps() {
    let base = CENO_PLATFORM.heap.start;
    let lw_program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
    let lw_aot = AotProgram::compile_fulltracer(lw_program.clone()).unwrap();
    let mut lw_vm = VMState::new(CENO_PLATFORM.clone(), lw_program);
    lw_vm.init_register_unsafe(20, base);
    let err = lw_aot.run_to_halt(&mut lw_vm, 1).unwrap_err().to_string();
    assert!(err.contains("LoadAddressMisaligned"));

    let lh_program = Arc::new(program(vec![encode_rv32(InsnKind::LH, 20, 0, 1, 1)]));
    let lh_aot = AotProgram::compile_fulltracer(lh_program.clone()).unwrap();
    let mut lh_vm = VMState::new(CENO_PLATFORM.clone(), lh_program);
    lh_vm.init_register_unsafe(20, base);
    let err = lh_aot.run_to_halt(&mut lh_vm, 1).unwrap_err().to_string();
    assert!(err.contains("LoadAddressMisaligned"));

    let sw_program = Arc::new(program(vec![encode_rv32(InsnKind::SW, 20, 1, 0, 1)]));
    let sw_aot = AotProgram::compile_fulltracer(sw_program.clone()).unwrap();
    let mut sw_vm = VMState::new(CENO_PLATFORM.clone(), sw_program);
    sw_vm.init_register_unsafe(20, base);
    sw_vm.init_register_unsafe(1, 42);
    let err = sw_aot.run_to_halt(&mut sw_vm, 1).unwrap_err().to_string();
    assert!(err.contains("StoreAddressMisaligned"));

    let sh_program = Arc::new(program(vec![encode_rv32(InsnKind::SH, 20, 1, 0, 1)]));
    let sh_aot = AotProgram::compile_fulltracer(sh_program.clone()).unwrap();
    let mut sh_vm = VMState::new(CENO_PLATFORM.clone(), sh_program);
    sh_vm.init_register_unsafe(20, base);
    sh_vm.init_register_unsafe(1, 42);
    let err = sh_aot.run_to_halt(&mut sh_vm, 1).unwrap_err().to_string();
    assert!(err.contains("StoreAddressMisaligned"));
}

#[test]
fn aot_memory_access_faults_use_exact_slow_path_traps() {
    let lb_program = Arc::new(program(vec![encode_rv32(InsnKind::LB, 20, 0, 1, 0)]));
    let lb_aot = AotProgram::compile_fulltracer(lb_program.clone()).unwrap();
    let mut lb_vm = VMState::new(CENO_PLATFORM.clone(), lb_program);
    lb_vm.init_register_unsafe(20, 0);
    let err = lb_aot.run_to_halt(&mut lb_vm, 1).unwrap_err().to_string();
    assert!(err.contains("LoadAccessFault"));

    let sb_program = Arc::new(program(vec![encode_rv32(InsnKind::SB, 20, 1, 0, 0)]));
    let sb_aot = AotProgram::compile_fulltracer(sb_program.clone()).unwrap();
    let mut sb_vm = VMState::new(CENO_PLATFORM.clone(), sb_program);
    sb_vm.init_register_unsafe(20, 0);
    sb_vm.init_register_unsafe(1, 42);
    let err = sb_aot.run_to_halt(&mut sb_vm, 1).unwrap_err().to_string();
    assert!(err.contains("StoreAccessFault"));
}

#[test]
fn aot_respects_max_steps_without_halting() {
    let base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut vm = VMState::new(CENO_PLATFORM.clone(), program);

    let report = aot.run_to_halt(&mut vm, 2).unwrap();

    assert_eq!(report.executed_steps, 2);
    assert!(!vm.halted());
    assert_eq!(vm.get_pc().0, base + 8);

    let report = aot.run_to_halt(&mut vm, 10).unwrap();
    assert_eq!(report.executed_steps, 6);
    assert!(vm.halted());
}

#[test]
fn aot_pure_block_plan_respects_limit_inside_block() {
    let base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let aot = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::Pure,
    )
    .unwrap();
    let mut vm = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);

    let report = aot.run_pure_to_halt(&mut vm, 2).unwrap();

    assert_eq!(report.executed_steps, 2);
    assert!(!vm.halted());
    assert_eq!(vm.get_pc().0, base + 8);
    assert_eq!(vm.peek_register(1), 2);
}

#[test]
fn preflight_pure_l0_matches_production_state_counts_and_exit() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 2, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
        encode_rv32(
            InsnKind::ADDI,
            0,
            0,
            Platform::reg_ecall().into(),
            Platform::ecall_halt() as i32,
        ),
        encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_arg0().into(), 7),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
    let production =
        AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    let l0 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightPureL0,
    )
    .unwrap();
    let mut expected = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config,
    );
    let mut actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
    expected.init_register_unsafe(20, base);
    expected.init_memory(ByteAddr(base).waddr(), 0);
    actual.init_register_unsafe(20, base);
    actual.init_memory(ByteAddr(base).waddr(), 0);

    let expected_report = production.run_to_halt(&mut expected, 64).unwrap();
    let actual_report = l0.run_pure_to_halt(&mut actual, 64).unwrap();

    assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
    assert_eq!(
        (actual_report.executed_steps as Cycle + 1) * PureAotTracer::SUBCYCLES_PER_INSN,
        expected.tracer().cycle()
    );
    assert_eq!(actual.get_pc(), expected.get_pc());
    assert_eq!(
        actual.halted_state().map(|state| state.exit_code),
        expected.halted_state().map(|state| state.exit_code)
    );
    for idx in 0..VMState::<PureAotTracer>::REG_COUNT as RegIdx {
        assert_eq!(actual.peek_register(idx), expected.peek_register(idx));
    }
    assert_eq!(actual.peek_memory(ByteAddr(base).waddr()), 1);
    assert_eq!(
        actual.peek_memory(ByteAddr(base).waddr()),
        expected.peek_memory(ByteAddr(base).waddr())
    );
    assert_eq!(actual_report.next_access_events, 0);
    assert_eq!(actual_report.next_access_capacity, 0);
    assert_eq!(actual_report.next_access_growths, 0);
    assert_eq!(actual_report.next_access_growth_bytes, 0);
}

#[test]
fn preflight_pure_l0_matches_production_trap() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
    let config = crate::PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX)
        .with_step_cell_extractor(Arc::new(OneCellPerNativeStep));
    let production =
        AotProgram::compile_preflight_with_extra_roots(program.clone(), Vec::new()).unwrap();
    let l0 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightPureL0,
    )
    .unwrap();
    let mut expected = VMState::<crate::PreflightTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config,
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
    expected.init_register_unsafe(20, base);
    actual.init_register_unsafe(20, base);

    let expected_err = production
        .run_to_halt(&mut expected, 1)
        .unwrap_err()
        .to_string();
    let actual_err = l0.run_pure_to_halt(&mut actual, 1).unwrap_err().to_string();

    assert!(expected_err.contains("LoadAddressMisaligned"));
    assert!(actual_err.contains("LoadAddressMisaligned"));
    assert_eq!(actual.get_pc(), expected.get_pc());
    for idx in 0..VMState::<PureAotTracer>::REG_COUNT as RegIdx {
        assert_eq!(actual.peek_register(idx), expected.peek_register(idx));
    }
}

#[test]
fn preflight_pure_l0_stops_at_direct_successor_boundary() {
    let base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::JAL, 0, 0, 0, 4),
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 9),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let l0 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightPureL0,
    )
    .unwrap();
    let mut vm = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);

    let first = l0.run_pure_to_halt(&mut vm, 1).unwrap();
    assert_eq!(first.executed_steps, 1);
    assert_eq!(vm.get_pc().0, base + 4);
    assert_eq!(vm.peek_register(1), 0);

    let second = l0.run_pure_to_halt(&mut vm, 1).unwrap();
    assert_eq!(second.executed_steps, 1);
    assert_eq!(vm.peek_register(1), 9);
}

#[test]
fn preflight_pure_l0_assembly_has_no_record_or_planner_work() {
    assert_eq!(
        AssemblyTraceStyle::PreflightPureL0.cache_name(),
        "preflight-pure-l0-schema3"
    );
    let program = program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
    ]);
    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("l0.S");
    write_assembly_with_planner(
        &path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightPureL0,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(path).unwrap();

    assert!(assembly.contains("ceno_aot_bb_"));
    assert!(!assembly.contains("preflight_bucket"));
    assert!(!assembly.contains("preflight_plan"));
    assert!(!assembly.contains("ceno_aot_fulltracer_emit_step"));
    assert!(!assembly.contains("ceno_aot_gpu_replay_emit_step"));
    assert!(!assembly.contains("FULLTRACER_ACCESS"));
}

fn assert_layered_skeleton_matches(reference: &crate::StepRecord, actual: &crate::StepRecord) {
    assert_eq!(actual.cycle(), reference.cycle());
    assert_eq!(actual.pc(), reference.pc());
    assert_eq!(actual.insn(), reference.insn());
    assert_eq!(
        actual.rs1().map(|op| op.addr),
        reference.rs1().map(|op| op.addr)
    );
    assert_eq!(
        actual.rs2().map(|op| op.addr),
        reference.rs2().map(|op| op.addr)
    );
    assert_eq!(
        actual.rd().map(|op| op.addr),
        reference.rd().map(|op| op.addr)
    );
    assert_eq!(
        actual.memory_op().map(|op| op.addr),
        reference.memory_op().map(|op| op.addr)
    );
}

fn assert_l1_skeleton_matches(reference: &crate::StepRecord, actual: &crate::StepRecord) {
    assert_layered_skeleton_matches(reference, actual);
    assert!(actual.l1_disabled_fields_are_poisoned());
}

fn assert_l2_values_match(reference: &crate::StepRecord, actual: &crate::StepRecord) {
    assert_layered_skeleton_matches(reference, actual);
    assert_eq!(
        actual.rs1().map(|op| op.value),
        reference.rs1().map(|op| op.value)
    );
    assert_eq!(
        actual.rs2().map(|op| op.value),
        reference.rs2().map(|op| op.value)
    );
    assert_eq!(
        actual.rd().map(|op| op.value),
        reference.rd().map(|op| op.value)
    );
    assert_eq!(
        actual.memory_op().map(|op| op.value),
        reference.memory_op().map(|op| op.value)
    );
    assert!(actual.l2_later_fields_are_poisoned());
}

fn assert_l3_registers_match(reference: &crate::StepRecord, actual: &crate::StepRecord) {
    assert_layered_skeleton_matches(reference, actual);
    assert_eq!(
        actual.rs1().map(|op| op.value),
        reference.rs1().map(|op| op.value)
    );
    assert_eq!(
        actual.rs2().map(|op| op.value),
        reference.rs2().map(|op| op.value)
    );
    assert_eq!(
        actual.rd().map(|op| op.value),
        reference.rd().map(|op| op.value)
    );
    assert_eq!(
        actual.memory_op().map(|op| op.value),
        reference.memory_op().map(|op| op.value)
    );
    assert_eq!(
        actual.rs1().map(|op| op.previous_cycle),
        reference.rs1().map(|op| op.previous_cycle)
    );
    assert_eq!(
        actual.rs2().map(|op| op.previous_cycle),
        reference.rs2().map(|op| op.previous_cycle)
    );
    assert_eq!(
        actual.rd().map(|op| op.previous_cycle),
        reference.rd().map(|op| op.previous_cycle)
    );
    assert!(actual.l3_later_fields_are_poisoned());
}

fn assert_l4_memory_matches(reference: &crate::StepRecord, actual: &crate::StepRecord) {
    assert_layered_skeleton_matches(reference, actual);
    assert_eq!(actual.rs1(), reference.rs1());
    assert_eq!(actual.rs2(), reference.rs2());
    assert_eq!(actual.rd(), reference.rd());
    assert_eq!(actual.memory_op(), reference.memory_op());
    assert_eq!(actual.heap_maxtouch_addr, reference.heap_maxtouch_addr);
    assert_eq!(actual.hint_maxtouch_addr, reference.hint_maxtouch_addr);
    assert!(actual.l4_later_fields_are_poisoned());
}

fn assert_l5_future_access_matches(reference: &crate::StepRecord, actual: &crate::StepRecord) {
    assert_layered_skeleton_matches(reference, actual);
    assert_eq!(actual.rs1(), reference.rs1());
    assert_eq!(actual.rs2(), reference.rs2());
    assert_eq!(actual.rd(), reference.rd());
    assert_eq!(actual.memory_op(), reference.memory_op());
    assert_eq!(actual.heap_maxtouch_addr, reference.heap_maxtouch_addr);
    assert_eq!(actual.hint_maxtouch_addr, reference.hint_maxtouch_addr);
    assert_eq!(actual.future_access_mask(), reference.future_access_mask());
    assert!(actual.l5_later_fields_are_poisoned());
}

#[test]
fn preflight_skeleton_l1_matches_direct_fields_and_poison_across_boundaries() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -20),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l1 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightSkeletonL1,
    )
    .unwrap();

    for capacity in [1, 2, 4, 5, 6, 7, 17, 31] {
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig {
                max_step_shard: capacity,
            },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        reference.init_register_unsafe(20, base);
        reference.init_memory(ByteAddr(base).waddr(), 0);
        actual.init_register_unsafe(20, base);
        actual.init_memory(ByteAddr(base).waddr(), 0);

        let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
        let actual_report = l1.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert_eq!(actual_report.l1_skeleton_records.len(), capacity);
        for (expected, actual) in reference
            .tracer()
            .recorded_steps()
            .iter()
            .zip(&actual_report.l1_skeleton_records)
        {
            assert_l1_skeleton_matches(expected, actual);
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_register(1), reference.peek_register(1));
        assert_eq!(
            actual.peek_memory(ByteAddr(base).waddr()),
            reference.peek_memory(ByteAddr(base).waddr())
        );
    }
}

#[test]
fn preflight_skeleton_l1_assembly_reserves_blocks_and_has_no_tracking() {
    assert_eq!(
        AssemblyTraceStyle::PreflightSkeletonL1.cache_name(),
        "preflight-skeleton-l1-schema1"
    );
    let program = program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
    ]);
    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("l1.S");
    write_assembly_with_planner(
        &path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightSkeletonL1,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(path).unwrap();
    assert!(assembly.contains("ceno_aot_skeleton_l1_emit_step"));
    assert!(assembly.contains(&format!("movq {AOT_CTX_FULLTRACER_LEN_OFFSET}(%r12), %rcx")));
    assert!(!assembly.contains("preflight_bucket"));
    assert!(!assembly.contains("preflight_plan"));
    assert!(!assembly.contains("FULLTRACER_ACCESS"));
}

#[test]
fn preflight_compact_skeleton_l1c_matches_l1_and_uses_forward_stores() {
    assert_eq!(
        AssemblyTraceStyle::PreflightCompactSkeletonL1C.cache_name(),
        "preflight-compact-skeleton-l1c-schema1"
    );
    assert_eq!(std::mem::size_of::<CompactSkeletonRecord>(), 16);

    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -20),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactSkeletonL1C,
    )
    .unwrap();

    for capacity in [1, 2, 4, 5, 6, 7, 17, 31] {
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig {
                max_step_shard: capacity,
            },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        reference.init_register_unsafe(20, base);
        reference.init_memory(ByteAddr(base).waddr(), 0);
        actual.init_register_unsafe(20, base);
        actual.init_memory(ByteAddr(base).waddr(), 0);

        direct.run_to_halt(&mut reference, capacity).unwrap();
        let report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(report.l1_skeleton_records.len(), capacity);
        for (expected, decoded) in reference
            .tracer()
            .recorded_steps()
            .iter()
            .zip(&report.l1_skeleton_records)
        {
            assert_l1_skeleton_matches(expected, decoded);
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_register(1), reference.peek_register(1));
        assert_eq!(
            actual.peek_memory(ByteAddr(base).waddr()),
            reference.peek_memory(ByteAddr(base).waddr())
        );
    }

    let syscall_program = Arc::new(self::program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let syscall_l1 = AotProgram::compile_with_extra_roots_and_trace_style(
        syscall_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightSkeletonL1,
    )
    .unwrap();
    let syscall_compact = AotProgram::compile_with_extra_roots_and_trace_style(
        syscall_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactSkeletonL1C,
    )
    .unwrap();
    let mut syscall_reference =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program.clone());
    let mut syscall_actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program);
    let syscall_l1_report = syscall_l1
        .run_pure_to_halt(&mut syscall_reference, 2)
        .unwrap();
    let syscall_report = syscall_compact
        .run_pure_to_halt(&mut syscall_actual, 2)
        .unwrap();
    assert_eq!(syscall_report.fallback_steps, 1);
    for (expected, decoded) in syscall_l1_report
        .l1_skeleton_records
        .iter()
        .zip(&syscall_report.l1_skeleton_records)
    {
        assert_l1_skeleton_matches(expected, decoded);
    }

    let trap_program = Arc::new(self::program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
    let trap_compact = AotProgram::compile_with_extra_roots_and_trace_style(
        trap_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactSkeletonL1C,
    )
    .unwrap();
    let mut trap_vm =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), trap_program);
    trap_vm.init_register_unsafe(20, base);
    let trap = trap_compact
        .run_pure_to_halt(&mut trap_vm, 1)
        .unwrap_err()
        .to_string();
    assert!(trap.contains("LoadAddressMisaligned"));

    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("l1c.S");
    write_assembly_with_planner(
        &path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightCompactSkeletonL1C,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(path).unwrap();
    let recorder = assembly
        .split("ceno_aot_compact_skeleton_l1c_emit_step:\n")
        .nth(1)
        .unwrap()
        .split("    ret\n")
        .next()
        .unwrap();
    let stores = recorder
        .lines()
        .filter(|line| line.contains("(%r10)"))
        .collect::<Vec<_>>();
    assert_eq!(
        stores,
        [
            "    movl %ecx, 0(%r10)",
            "    movl %edx, 4(%r10)",
            "    movl %edx, 8(%r10)",
            "    movl %eax, 12(%r10)",
        ]
    );
    assert!(!recorder.contains("0xa5a5"));
    assert!(!recorder.contains("$136"));
    assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
}

#[test]
fn preflight_values_l2_matches_direct_values_and_poison_across_boundaries() {
    assert_eq!(
        AssemblyTraceStyle::PreflightValuesL2.cache_name(),
        "preflight-values-l2-schema1"
    );
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 0, 1),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l2 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightValuesL2,
    )
    .unwrap();

    for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig {
                max_step_shard: capacity,
            },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        reference.init_register_unsafe(20, base);
        reference.init_memory(ByteAddr(base).waddr(), 0);
        actual.init_register_unsafe(20, base);
        actual.init_memory(ByteAddr(base).waddr(), 0);

        let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
        let actual_report = l2.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert_eq!(actual_report.l1_skeleton_records.len(), capacity);
        for (expected, actual) in reference
            .tracer()
            .recorded_steps()
            .iter()
            .zip(&actual_report.l1_skeleton_records)
        {
            assert_l2_values_match(expected, actual);
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_register(0), 0);
        assert_eq!(actual.peek_register(1), reference.peek_register(1));
        assert_eq!(
            actual.peek_memory(ByteAddr(base).waddr()),
            reference.peek_memory(ByteAddr(base).waddr())
        );
    }
}

#[test]
fn preflight_compact_values_l2c_matches_l2_and_uses_forward_family_stores() {
    assert_eq!(
        AssemblyTraceStyle::PreflightCompactValuesL2C.cache_name(),
        "preflight-compact-values-l2c-schema1"
    );
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 0, 1),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactValuesL2C,
    )
    .unwrap();

    for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig {
                max_step_shard: capacity,
            },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        reference.init_register_unsafe(20, base);
        reference.init_memory(ByteAddr(base).waddr(), 0x8877_6655);
        actual.init_register_unsafe(20, base);
        actual.init_memory(ByteAddr(base).waddr(), 0x8877_6655);

        direct.run_to_halt(&mut reference, capacity).unwrap();
        let report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(report.l1_skeleton_records.len(), capacity);
        assert!(report.compact_bytes_written >= capacity * 16);
        assert!(report.compact_bytes_written <= capacity * COMPACT_VALUES_MAX_BYTES);
        for (expected, decoded) in reference
            .tracer()
            .recorded_steps()
            .iter()
            .zip(&report.l1_skeleton_records)
        {
            assert_l2_values_match(expected, decoded);
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_register(0), 0);
        assert_eq!(actual.peek_register(1), reference.peek_register(1));
        assert_eq!(
            actual.peek_memory(ByteAddr(base).waddr()),
            reference.peek_memory(ByteAddr(base).waddr())
        );
    }

    let syscall_program = Arc::new(self::program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 7),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let syscall_l2 = AotProgram::compile_with_extra_roots_and_trace_style(
        syscall_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightValuesL2,
    )
    .unwrap();
    let syscall_compact = AotProgram::compile_with_extra_roots_and_trace_style(
        syscall_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactValuesL2C,
    )
    .unwrap();
    let mut syscall_reference =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program.clone());
    let mut syscall_actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program);
    let expected = syscall_l2
        .run_pure_to_halt(&mut syscall_reference, 2)
        .unwrap();
    let actual = syscall_compact
        .run_pure_to_halt(&mut syscall_actual, 2)
        .unwrap();
    assert_eq!(actual.fallback_steps, 1);
    for (expected, decoded) in expected
        .l1_skeleton_records
        .iter()
        .zip(&actual.l1_skeleton_records)
    {
        assert_l2_values_match(expected, decoded);
    }

    let trap_program = Arc::new(self::program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
    let trap_compact = AotProgram::compile_with_extra_roots_and_trace_style(
        trap_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactValuesL2C,
    )
    .unwrap();
    let mut trap_vm =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), trap_program);
    trap_vm.init_register_unsafe(20, base);
    assert!(
        trap_compact
            .run_pure_to_halt(&mut trap_vm, 1)
            .unwrap_err()
            .to_string()
            .contains("LoadAddressMisaligned")
    );

    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("l2c.S");
    write_assembly_with_planner(
        &path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightCompactValuesL2C,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(path).unwrap();
    let recorder = assembly
        .split("ceno_aot_compact_values_l2c_emit_step:\n")
        .nth(1)
        .unwrap()
        .split("    ret\n")
        .next()
        .unwrap();
    for line in recorder.lines().filter(|line| line.contains("(%r10)")) {
        assert!(
            line.trim_start().starts_with("movl %"),
            "destination load/RMW: {line}"
        );
    }
    for family in ["r", "i", "branch", "j", "load", "store"] {
        let body = recorder
            .split(&format!(".L_compact_values_l2c_{family}:\n"))
            .nth(1)
            .unwrap()
            .split("    jmp .L_compact_values_l2c_commit")
            .next()
            .unwrap();
        let offsets = body
            .lines()
            .filter_map(|line| line.split_once("(%r10)").map(|(prefix, _)| prefix))
            .filter_map(|prefix| prefix.split_whitespace().last())
            .map(|offset| offset.trim_end_matches(',').parse::<usize>().unwrap())
            .collect::<Vec<_>>();
        assert!(offsets.windows(2).all(|pair| pair[0] < pair[1]));
    }
    assert!(!recorder.contains("0xa5a5"));
    assert!(!recorder.contains("$136"));
    assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
}

#[test]
fn preflight_compact_values_l2c_executes_derived_value_edge_cases_and_resume() {
    let m_program = Arc::new(program(vec![
        encode_rv32(InsnKind::MUL, 1, 2, 5, 0),
        encode_rv32(InsnKind::MULH, 1, 2, 6, 0),
        encode_rv32(InsnKind::MULHSU, 1, 2, 7, 0),
        encode_rv32(InsnKind::MULHU, 1, 2, 8, 0),
        encode_rv32(InsnKind::DIV, 1, 2, 9, 0),
        encode_rv32(InsnKind::DIVU, 1, 2, 10, 0),
        encode_rv32(InsnKind::REM, 1, 2, 11, 0),
        encode_rv32(InsnKind::REMU, 1, 2, 12, 0),
        encode_rv32(InsnKind::DIV, 1, 4, 13, 0),
        encode_rv32(InsnKind::DIVU, 1, 4, 14, 0),
        encode_rv32(InsnKind::REM, 1, 4, 15, 0),
        encode_rv32(InsnKind::REMU, 1, 4, 16, 0),
    ]));
    let m_direct = AotProgram::compile_with_extra_roots_and_trace_style(
        m_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let m_compact = AotProgram::compile_with_extra_roots_and_trace_style(
        m_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactValuesL2C,
    )
    .unwrap();
    let mut m_reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        m_program.clone(),
        crate::FullTracerConfig { max_step_shard: 32 },
    );
    let mut m_actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), m_program);
    m_reference.init_register_unsafe(1, i32::MIN as u32);
    m_reference.init_register_unsafe(2, u32::MAX);
    m_reference.init_register_unsafe(4, 0);
    m_actual.init_register_unsafe(1, i32::MIN as u32);
    m_actual.init_register_unsafe(2, u32::MAX);
    m_actual.init_register_unsafe(4, 0);
    m_direct.run_to_halt(&mut m_reference, 12).unwrap();
    let m_report = m_compact.run_pure_to_halt(&mut m_actual, 12).unwrap();
    for (expected, decoded) in m_reference
        .tracer()
        .recorded_steps()
        .iter()
        .zip(&m_report.l1_skeleton_records)
    {
        assert_l2_values_match(expected, decoded);
    }

    let pc_base = CENO_PLATFORM.pc_base();
    let jalr_program = Arc::new(program(vec![
        encode_rv32(InsnKind::JALR, 1, 0, 5, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 7, 99),
        encode_rv32(InsnKind::JALR, 2, 0, 6, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 8, 7),
    ]));
    let jalr_direct = AotProgram::compile_with_extra_roots_and_trace_style(
        jalr_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let jalr_compact = AotProgram::compile_with_extra_roots_and_trace_style(
        jalr_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactValuesL2C,
    )
    .unwrap();
    let mut jalr_reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        jalr_program.clone(),
        crate::FullTracerConfig { max_step_shard: 8 },
    );
    let mut jalr_actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), jalr_program);
    jalr_reference.init_register_unsafe(1, pc_base + 8);
    jalr_reference.init_register_unsafe(2, pc_base + 12);
    jalr_reference.init_register_unsafe(5, 0x1111_1111);
    jalr_reference.init_register_unsafe(6, 0x2222_2222);
    jalr_actual.init_register_unsafe(1, pc_base + 8);
    jalr_actual.init_register_unsafe(2, pc_base + 12);
    jalr_actual.init_register_unsafe(5, 0x1111_1111);
    jalr_actual.init_register_unsafe(6, 0x2222_2222);
    jalr_direct.run_to_halt(&mut jalr_reference, 3).unwrap();
    let jalr_report = jalr_compact.run_pure_to_halt(&mut jalr_actual, 3).unwrap();
    assert!(jalr_report.fallback.dynamic_pc_miss > 0);
    for (expected, decoded) in jalr_reference
        .tracer()
        .recorded_steps()
        .iter()
        .zip(&jalr_report.l1_skeleton_records)
    {
        assert_l2_values_match(expected, decoded);
    }

    let heap = CENO_PLATFORM.heap.start;
    let subword_program = Arc::new(program(vec![
        encode_rv32(InsnKind::LB, 20, 0, 1, 2),
        encode_rv32(InsnKind::LBU, 20, 0, 2, 3),
        encode_rv32(InsnKind::LH, 20, 0, 3, 2),
        encode_rv32(InsnKind::LHU, 20, 0, 4, 0),
        encode_rv32(InsnKind::SB, 20, 5, 0, 1),
        encode_rv32(InsnKind::SH, 20, 6, 0, 2),
        encode_rv32(InsnKind::LW, 20, 0, 7, 0),
    ]));
    let subword_direct = AotProgram::compile_with_extra_roots_and_trace_style(
        subword_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let subword_compact = AotProgram::compile_with_extra_roots_and_trace_style(
        subword_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactValuesL2C,
    )
    .unwrap();
    let mut subword_reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        subword_program.clone(),
        crate::FullTracerConfig { max_step_shard: 32 },
    );
    let mut subword_actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), subword_program);
    subword_reference.init_register_unsafe(20, heap);
    subword_reference.init_register_unsafe(5, 0xaa);
    subword_reference.init_register_unsafe(6, 0xbbcc);
    subword_reference.init_memory(ByteAddr(heap).waddr(), 0x80ff_7f01);
    subword_actual.init_register_unsafe(20, heap);
    subword_actual.init_register_unsafe(5, 0xaa);
    subword_actual.init_register_unsafe(6, 0xbbcc);
    subword_actual.init_memory(ByteAddr(heap).waddr(), 0x80ff_7f01);
    for capacity in [1, 2, 1, 3] {
        let expected_start = subword_reference.tracer().recorded_steps().len();
        let expected_report = subword_direct
            .run_to_halt(&mut subword_reference, capacity)
            .unwrap();
        let actual_report = subword_compact
            .run_pure_to_halt(&mut subword_actual, capacity)
            .unwrap();
        let expected = &subword_reference.tracer().recorded_steps()
            [expected_start..expected_start + expected_report.executed_steps];
        for (expected, decoded) in expected.iter().zip(&actual_report.l1_skeleton_records) {
            assert_l2_values_match(expected, decoded);
        }
        assert_eq!(subword_actual.get_pc(), subword_reference.get_pc());
        assert_eq!(
            subword_actual.peek_memory(ByteAddr(heap).waddr()),
            subword_reference.peek_memory(ByteAddr(heap).waddr())
        );
    }
}

#[test]
fn preflight_registers_l3_matches_direct_across_aliases_boundaries_and_resume() {
    assert_eq!(
        AssemblyTraceStyle::PreflightRegistersL3.cache_name(),
        "preflight-registers-l3-schema1"
    );
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 0, 1),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l3 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightRegistersL3,
    )
    .unwrap();

    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig {
            max_step_shard: 256,
        },
    );
    let mut actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
    reference.init_register_unsafe(20, base);
    reference.init_memory(ByteAddr(base).waddr(), 0);
    actual.init_register_unsafe(20, base);
    actual.init_memory(ByteAddr(base).waddr(), 0);

    for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
        let expected_start = reference.tracer().recorded_steps().len();
        let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
        let actual_report = l3.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert_eq!(actual_report.l1_skeleton_records.len(), capacity);
        let expected = &reference.tracer().recorded_steps()
            [expected_start..expected_start + expected_report.executed_steps];
        for (expected, actual) in expected.iter().zip(&actual_report.l1_skeleton_records) {
            assert_l3_registers_match(expected, actual);
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_register(0), 0);
        assert_eq!(actual.peek_register(1), reference.peek_register(1));
        assert_eq!(
            actual.peek_memory(ByteAddr(base).waddr()),
            reference.peek_memory(ByteAddr(base).waddr())
        );
    }
}

#[test]
fn preflight_compact_registers_l3c_matches_aliases_branches_and_repeated_bounds() {
    assert_eq!(
        AssemblyTraceStyle::PreflightCompactRegistersL3C.cache_name(),
        "preflight-compact-registers-l3c-schema1"
    );
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 0, 1),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -12),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactRegistersL3C,
    )
    .unwrap();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig {
            max_step_shard: 256,
        },
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
    let heap = CENO_PLATFORM.heap.start;
    reference.init_register_unsafe(20, heap);
    reference.init_memory(ByteAddr(heap).waddr(), 0x8877_6655);
    actual.init_register_unsafe(20, heap);
    actual.init_memory(ByteAddr(heap).waddr(), 0x8877_6655);

    for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
        let expected_start = reference.tracer().recorded_steps().len();
        let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
        let actual_report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert_eq!(actual_report.l1_skeleton_records.len(), capacity);
        let expected = &reference.tracer().recorded_steps()
            [expected_start..expected_start + expected_report.executed_steps];
        assert_eq!(
            actual_report.compact_bytes_written,
            expected
                .iter()
                .map(|record| compact_registers_row_size(record.insn()))
                .sum::<usize>()
        );
        for (expected, actual) in expected.iter().zip(&actual_report.l1_skeleton_records) {
            assert_l3_registers_match(expected, actual);
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_register(0), 0);
        assert_eq!(actual.peek_register(1), reference.peek_register(1));
        assert_eq!(
            actual.peek_memory(ByteAddr(heap).waddr()),
            reference.peek_memory(ByteAddr(heap).waddr())
        );
    }
}

#[test]
fn preflight_compact_registers_l3c_matches_dynamic_jalr_ecall_and_trap() {
    let pc_base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::JALR, 1, 0, 6, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 7, 99),
        encode_rv32(InsnKind::ADDI, 6, 0, 7, 1),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactRegistersL3C,
    )
    .unwrap();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 4 },
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
    reference.init_register_unsafe(1, pc_base + 8);
    reference.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
    actual.init_register_unsafe(1, pc_base + 8);
    actual.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
    let expected_report = direct.run_to_halt(&mut reference, 4).unwrap();
    let actual_report = compact.run_pure_to_halt(&mut actual, 4).unwrap();
    assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
    assert!(actual_report.fallback.dynamic_pc_miss > 0);
    assert!(actual_report.fallback_steps >= 2);
    for (expected, actual) in reference
        .tracer()
        .recorded_steps()
        .iter()
        .zip(&actual_report.l1_skeleton_records)
    {
        if expected.insn().kind == InsnKind::ECALL {
            // Dynamic syscall register payload/index semantics remain L6C.
            assert_eq!(actual.cycle(), expected.cycle());
            assert_eq!(actual.pc(), expected.pc());
            assert_eq!(actual.insn(), expected.insn());
            assert!(actual.l3_later_fields_are_poisoned());
        } else {
            assert_l3_registers_match(expected, actual);
        }
    }
    assert_eq!(actual.get_pc(), reference.get_pc());

    let heap = CENO_PLATFORM.heap.start;
    let trap_program = Arc::new(self::program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        trap_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        trap_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactRegistersL3C,
    )
    .unwrap();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        trap_program.clone(),
        crate::FullTracerConfig { max_step_shard: 1 },
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), trap_program);
    reference.init_register_unsafe(20, heap);
    actual.init_register_unsafe(20, heap);
    let expected = direct
        .run_to_halt(&mut reference, 1)
        .unwrap_err()
        .to_string();
    let actual_error = compact
        .run_pure_to_halt(&mut actual, 1)
        .unwrap_err()
        .to_string();
    assert!(expected.contains("LoadAddressMisaligned"));
    assert!(actual_error.contains("LoadAddressMisaligned"));
    assert_eq!(actual.get_pc(), reference.get_pc());
}

#[test]
fn preflight_compact_registers_l3c_has_no_262144_row_reset() {
    let capacity = 262_145;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 1, 0, 1, 1),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -4),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactRegistersL3C,
    )
    .unwrap();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig {
            max_step_shard: capacity,
        },
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
    direct.run_to_halt(&mut reference, capacity).unwrap();
    let report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
    assert_eq!(report.executed_steps, capacity);
    assert_eq!(report.l1_skeleton_records.len(), capacity);
    for &index in &[0, 1, 262_143, 262_144] {
        assert_l3_registers_match(
            &reference.tracer().recorded_steps()[index],
            &report.l1_skeleton_records[index],
        );
    }
    assert_eq!(actual.get_pc(), reference.get_pc());
    assert_eq!(actual.peek_register(1), reference.peek_register(1));
}

#[test]
fn preflight_compact_registers_l3c_rejects_overflow_before_forward_family_stores() {
    let program = program(vec![
        encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 3, 1),
        encode_rv32(InsnKind::BEQ, 1, 2, 0, 4),
        encode_rv32(InsnKind::JAL, 0, 0, 3, 4),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::SW, 20, 3, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]);
    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("l3c.S");
    write_assembly_with_planner(
        &path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightCompactRegistersL3C,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(path).unwrap();

    let exact_boundary = "    movq 0(%rsp), %rax\n    cmpq %rbp, %rax\n    jae ceno_aot_done";
    assert!(
        assembly.matches(exact_boundary).count() >= blocks.len() + 1,
        "every L3C block leader plus the dispatcher must close an exact bound"
    );
    let recorder = assembly
        .split("ceno_aot_compact_registers_l3c_emit_step:\n")
        .nth(1)
        .unwrap()
        .split(".L_compact_registers_l3c_overflow:\n")
        .next()
        .unwrap();
    let first_family = recorder.find(".L_compact_registers_l3c_r:\n").unwrap();
    let prefix = &recorder[..first_family];
    assert!(prefix.contains("testl $3, %eax\n    jne .L_compact_registers_l3c_overflow"));
    assert!(prefix.contains("cmpl $1048576, %eax\n    jae .L_compact_registers_l3c_overflow"));
    assert!(!prefix.contains("(%r10)"));

    let expected = [
        (
            "r",
            &[
                "    movq %rax, 0(%r10)",
                "    movq %rax, 8(%r10)",
                "    movq %rax, 16(%r10)",
                "    movl %eax, 24(%r10)",
            ][..],
        ),
        (
            "i",
            &[
                "    movq %rax, 0(%r10)",
                "    movq %rax, 8(%r10)",
                "    movl %eax, 16(%r10)",
                "    movb %al, 20(%r10)",
            ][..],
        ),
        (
            "branch",
            &[
                "    movq %rax, 0(%r10)",
                "    movq %rax, 8(%r10)",
                "    movl %eax, 16(%r10)",
                "    movb %al, 20(%r10)",
            ][..],
        ),
        (
            "j",
            &[
                "    movq %rax, 0(%r10)",
                "    movl %eax, 8(%r10)",
                "    movb %al, 12(%r10)",
            ][..],
        ),
        (
            "load",
            &[
                "    movq %rax, 0(%r10)",
                "    movq %rax, 8(%r10)",
                "    movq %rax, 16(%r10)",
                "    movb %al, 24(%r10)",
            ][..],
        ),
        (
            "store",
            &[
                "    movq %rax, 0(%r10)",
                "    movq %rax, 8(%r10)",
                "    movq %rax, 16(%r10)",
                "    movb %al, 24(%r10)",
            ][..],
        ),
        (
            "exceptional",
            &["    movq %rax, 0(%r10)", "    movw %ax, 8(%r10)"][..],
        ),
        (
            "header",
            &["    movl %eax, 0(%r10)", "    movw %ax, 4(%r10)"][..],
        ),
    ];
    for (index, (family, expected_stores)) in expected.iter().enumerate() {
        let label = format!(".L_compact_registers_l3c_{family}:\n");
        let body = recorder.split(&label).nth(1).unwrap();
        let body = if let Some((next_family, _)) = expected.get(index + 1) {
            body.split(&format!(".L_compact_registers_l3c_{next_family}:\n"))
                .next()
                .unwrap()
        } else {
            body
        };
        let stores = body
            .lines()
            .filter(|line| line.contains("(%r10)"))
            .collect::<Vec<_>>();
        assert_eq!(stores, *expected_stores, "L3C {family} store coverage");
        if !matches!(*family, "header" | "exceptional") {
            let last_cycle_check = body
                .rfind("jae .L_compact_registers_l3c_overflow")
                .expect("register family must validate predecessor widths");
            let first_store = body.find("(%r10)").unwrap();
            assert!(last_cycle_check < first_store);
        }
    }
    for line in recorder.lines().filter(|line| line.contains("(%r10)")) {
        assert!(
            line.trim_end().ends_with("(%r10)"),
            "destination load/RMW: {line}"
        );
    }
    assert!(!recorder.contains("0xa5a5"));
    assert!(!recorder.contains("memset"));
    assert!(!recorder.contains("StepRecord"));
    assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
    let overflow = assembly
        .split(".L_compact_registers_l3c_overflow:\n")
        .nth(1)
        .unwrap()
        .split("ceno_aot_error:\n")
        .next()
        .unwrap();
    assert!(
        overflow.contains(
            "    addq $32, %rsp\n    popq %r10\n    addq $8, %rsp\n    jmp ceno_aot_error"
        )
    );

    let overflow_program = Arc::new(self::program(vec![encode_rv32(InsnKind::ADDI, 1, 0, 2, 1)]));
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        overflow_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactRegistersL3C,
    )
    .unwrap();
    let mut vm = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), overflow_program);
    vm.tracer_mut().layered_register_latest[1] = 1 << COMPACT_REGISTERS_CYCLE_BITS;
    let error = compact
        .run_pure_to_halt(&mut vm, 1)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "AOT native step failed without error detail");
    assert_eq!(vm.tracer().layered_cycle, PureAotTracer::SUBCYCLES_PER_INSN);
}

#[test]
fn preflight_compact_memory_l4c_matches_memory_aliases_bounds_fallback_and_resume() {
    assert_eq!(
        AssemblyTraceStyle::PreflightCompactMemoryL4C.cache_name(),
        "preflight-compact-memory-l4c-schema1"
    );
    assert_eq!(std::mem::size_of::<CompactMemoryLoad>(), 28);
    assert_eq!(std::mem::size_of::<CompactMemoryStore>(), 28);
    assert_eq!(std::mem::size_of::<CompactMemoryExceptional>(), 18);

    let pc_base = CENO_PLATFORM.pc_base();
    let heap = CENO_PLATFORM.heap.start;
    let hint = CENO_PLATFORM.hints.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::JALR, 22, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 7, 99),
        encode_rv32(InsnKind::SB, 20, 1, 0, 1),
        encode_rv32(InsnKind::LBU, 20, 0, 2, 1),
        encode_rv32(InsnKind::SH, 20, 2, 0, 2),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::SW, 21, 3, 0, 8),
        encode_rv32(InsnKind::LW, 21, 0, 1, 8),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactMemoryL4C,
    )
    .unwrap();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 32 },
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
    reference.init_register_unsafe(1, 0x1122_3344);
    reference.init_register_unsafe(20, heap);
    reference.init_register_unsafe(21, hint);
    reference.init_register_unsafe(22, pc_base + 8);
    reference.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
    reference.init_memory(ByteAddr(heap).waddr(), 0x8877_6655);
    reference.init_memory(ByteAddr(hint + 8).waddr(), 0);
    actual.init_register_unsafe(1, 0x1122_3344);
    actual.init_register_unsafe(20, heap);
    actual.init_register_unsafe(21, hint);
    actual.init_register_unsafe(22, pc_base + 8);
    actual.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
    actual.init_memory(ByteAddr(heap).waddr(), 0x8877_6655);
    actual.init_memory(ByteAddr(hint + 8).waddr(), 0);

    for capacity in [1, 2, 1, 3, 1] {
        let expected_start = reference.tracer().recorded_steps().len();
        let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
        let actual_report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        let expected = &reference.tracer().recorded_steps()
            [expected_start..expected_start + expected_report.executed_steps];
        assert_eq!(
            actual_report.compact_bytes_written,
            expected
                .iter()
                .map(|record| compact_memory_row_size(record.insn()))
                .sum::<usize>()
        );
        for (expected, decoded) in expected.iter().zip(&actual_report.l1_skeleton_records) {
            if expected.insn().kind == InsnKind::ECALL {
                assert_eq!(decoded.cycle(), expected.cycle());
                assert_eq!(decoded.pc(), expected.pc());
                assert_eq!(decoded.heap_maxtouch_addr, expected.heap_maxtouch_addr);
                assert_eq!(decoded.hint_maxtouch_addr, expected.hint_maxtouch_addr);
                assert!(decoded.l4_later_fields_are_poisoned());
            } else {
                assert_l4_memory_matches(expected, decoded);
            }
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(
            actual.peek_memory(ByteAddr(heap).waddr()),
            reference.peek_memory(ByteAddr(heap).waddr())
        );
        assert_eq!(
            actual.peek_memory(ByteAddr(hint + 8).waddr()),
            reference.peek_memory(ByteAddr(hint + 8).waddr())
        );
    }
}

#[test]
fn preflight_compact_memory_l4c_uses_only_forward_nonoverlapping_family_stores() {
    let program = program(vec![
        encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::SW, 20, 3, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]);
    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("l4c.S");
    write_assembly_with_planner(
        &path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightCompactMemoryL4C,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(path).unwrap();
    let recorder = assembly
        .split("ceno_aot_compact_registers_l3c_emit_step:\n")
        .nth(1)
        .unwrap()
        .split(".L_compact_registers_l3c_overflow:\n")
        .next()
        .unwrap();
    for (family, next_family) in [("load", "store"), ("store", "exceptional")] {
        let body = recorder
            .split(&format!(".L_compact_registers_l3c_{family}:\n"))
            .nth(1)
            .unwrap()
            .split(&format!(".L_compact_registers_l3c_{next_family}:\n"))
            .next()
            .unwrap();
        let stores = body
            .lines()
            .filter(|line| line.contains("(%r10)"))
            .collect::<Vec<_>>();
        assert_eq!(
            stores,
            [
                "    movq %rax, 0(%r10)",
                "    movq %rax, 8(%r10)",
                "    movq %rax, 16(%r10)",
                "    movl %eax, 24(%r10)",
            ],
            "L4C {family} store coverage"
        );
        let last_width_check = body
            .rfind("jae .L_compact_registers_l3c_overflow")
            .expect("L4C memory family must validate predecessor width");
        assert!(last_width_check < body.find("(%r10)").unwrap());
    }
    let exceptional = recorder
        .split(".L_compact_registers_l3c_exceptional:\n")
        .nth(1)
        .unwrap()
        .split(".L_compact_registers_l3c_header:\n")
        .next()
        .unwrap();
    assert_eq!(
        exceptional
            .lines()
            .filter(|line| line.contains("(%r10)"))
            .collect::<Vec<_>>(),
        [
            "    movq %rax, 0(%r10)",
            "    movq %rax, 8(%r10)",
            "    movw %ax, 16(%r10)",
        ]
    );
    for line in recorder.lines().filter(|line| line.contains("(%r10)")) {
        assert!(
            line.trim_end().ends_with("(%r10)"),
            "destination load/RMW: {line}"
        );
    }
    assert!(!recorder.contains("0xa5a5"));
    assert!(!recorder.contains("memset"));
    assert!(!recorder.contains("StepRecord"));
    assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
}

#[test]
fn preflight_memory_l4_matches_direct_repeated_subword_bounds_and_resume() {
    assert_eq!(
        AssemblyTraceStyle::PreflightMemoryL4.cache_name(),
        "preflight-memory-l4-schema1"
    );
    let heap = CENO_PLATFORM.heap.start;
    let hint = CENO_PLATFORM.hints.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::SB, 20, 1, 0, 1),
        encode_rv32(InsnKind::LBU, 20, 0, 2, 1),
        encode_rv32(InsnKind::SH, 20, 2, 0, 2),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::SW, 20, 3, 0, 4),
        encode_rv32(InsnKind::LW, 20, 0, 1, 4),
        encode_rv32(InsnKind::SW, 21, 1, 0, 8),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -32),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -40),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l4 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightMemoryL4,
    )
    .unwrap();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig {
            max_step_shard: 256,
        },
    );
    let mut actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
    reference.init_register_unsafe(20, heap);
    reference.init_register_unsafe(21, hint);
    reference.init_memory(ByteAddr(heap).waddr(), 0);
    reference.init_memory(ByteAddr(heap + 4).waddr(), 0);
    reference.init_memory(ByteAddr(hint + 8).waddr(), 0);
    actual.init_register_unsafe(20, heap);
    actual.init_register_unsafe(21, hint);
    actual.init_memory(ByteAddr(heap).waddr(), 0);
    actual.init_memory(ByteAddr(heap + 4).waddr(), 0);
    actual.init_memory(ByteAddr(hint + 8).waddr(), 0);

    for capacity in [1, 2, 4, 5, 6, 7, 8, 17, 31] {
        let expected_start = reference.tracer().recorded_steps().len();
        let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
        let actual_report = l4.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        let expected = &reference.tracer().recorded_steps()
            [expected_start..expected_start + expected_report.executed_steps];
        for (expected, actual) in expected.iter().zip(&actual_report.l1_skeleton_records) {
            assert_l4_memory_matches(expected, actual);
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        for addr in [heap, heap + 4, hint + 8] {
            assert_eq!(
                actual.peek_memory(ByteAddr(addr).waddr()),
                reference.peek_memory(ByteAddr(addr).waddr())
            );
        }
    }
}

#[test]
fn preflight_memory_l4_matches_direct_scalar_resume_and_ecall() {
    let pc_base = CENO_PLATFORM.pc_base();
    let heap = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 99),
        encode_rv32(InsnKind::SW, 20, 2, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l4 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightMemoryL4,
    )
    .unwrap();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 8 },
    );
    let mut actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
    reference.init_register_unsafe(1, pc_base + 8);
    reference.init_register_unsafe(2, 7);
    reference.init_register_unsafe(20, heap);
    reference.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
    reference.init_memory(ByteAddr(heap).waddr(), 0);
    actual.init_register_unsafe(1, pc_base + 8);
    actual.init_register_unsafe(2, 7);
    actual.init_register_unsafe(20, heap);
    actual.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
    actual.init_memory(ByteAddr(heap).waddr(), 0);

    let expected_report = direct.run_to_halt(&mut reference, 8).unwrap();
    let actual_report = l4.run_pure_to_halt(&mut actual, 8).unwrap();
    assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
    assert!(actual_report.fallback.dynamic_pc_miss > 0);
    assert!(actual_report.fallback_steps >= 2);
    for (expected, actual) in reference
        .tracer()
        .recorded_steps()
        .iter()
        .zip(&actual_report.l1_skeleton_records)
    {
        if expected.insn().kind == InsnKind::ECALL {
            // Dynamic syscall operands/witnesses are intentionally L6.
            // L4 still owns the exact bounds surrounding the syscall and
            // must leave all later-layer fields poisoned.
            assert_eq!(actual.cycle(), expected.cycle());
            assert_eq!(actual.pc(), expected.pc());
            assert_eq!(actual.heap_maxtouch_addr, expected.heap_maxtouch_addr);
            assert_eq!(actual.hint_maxtouch_addr, expected.hint_maxtouch_addr);
            assert!(actual.l4_later_fields_are_poisoned());
        } else {
            assert_l4_memory_matches(expected, actual);
        }
    }
    assert_eq!(actual.get_pc(), reference.get_pc());
    assert_eq!(actual.peek_memory(ByteAddr(heap).waddr()), 7);
}

#[test]
fn preflight_future_access_l5_matches_direct_native_scalar_and_resume() {
    assert_eq!(
        AssemblyTraceStyle::PreflightFutureAccessL5.cache_name(),
        "preflight-future-access-l5-schema1"
    );
    let pc_base = CENO_PLATFORM.pc_base();
    let heap = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::JALR, 22, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -16),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l5 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightFutureAccessL5,
    )
    .unwrap();

    let initialize = |vm: &mut VMState<_>| {
        vm.init_register_unsafe(20, heap);
        vm.init_register_unsafe(22, pc_base + 20);
        vm.init_memory(ByteAddr(heap).waddr(), 0);
    };
    let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 64 },
    );
    initialize(&mut seed);
    direct.run_to_halt(&mut seed, 31).unwrap();
    let mut events = Vec::new();
    for record in seed.tracer().recorded_steps() {
        for (subcycle, op) in [
            (
                crate::FullTracer::SUBCYCLE_RS1,
                record.rs1().map(|op| op.addr),
            ),
            (
                crate::FullTracer::SUBCYCLE_RS2,
                record.rs2().map(|op| op.addr),
            ),
            (
                crate::FullTracer::SUBCYCLE_RD,
                record.rd().map(|op| op.addr),
            ),
            (
                crate::FullTracer::SUBCYCLE_MEM,
                record.memory_op().map(|op| op.addr),
            ),
        ] {
            if let Some(address) = op {
                let source = record.cycle() + subcycle;
                events.push(NextAccessEvent::new(source, source + 1_000_000, address));
            }
        }
    }
    let tape = Arc::new(NextCycleAccess::from_unsorted(events));
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 64 },
        Some(tape.clone()),
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program,
        (),
        Some(tape),
    );
    initialize(&mut reference);
    actual.init_register_unsafe(20, heap);
    actual.init_register_unsafe(22, pc_base + 20);
    actual.init_memory(ByteAddr(heap).waddr(), 0);

    for capacity in [1, 2, 4, 5, 6, 7, 6] {
        let start = reference.tracer().recorded_steps().len();
        direct.run_to_halt(&mut reference, capacity).unwrap();
        reference.tracer_mut().annotate_recorded_steps(start);
        let report = l5.run_pure_to_halt(&mut actual, capacity).unwrap();
        let expected = &reference.tracer().recorded_steps()[start..start + capacity];
        assert_eq!(report.l1_skeleton_records.len(), capacity);
        for (expected, actual) in expected.iter().zip(&report.l1_skeleton_records) {
            assert_l5_future_access_matches(expected, actual);
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_register(1), reference.peek_register(1));
        assert_eq!(
            actual.peek_memory(ByteAddr(heap).waddr()),
            reference.peek_memory(ByteAddr(heap).waddr())
        );
    }
    assert_eq!(
        actual.tracer().layered_next_access_cursor,
        actual.tracer().layered_next_accesses.events().len()
    );
}

#[test]
fn preflight_future_access_l5_matches_direct_syscall_masks() {
    let program = Arc::new(program(vec![encode_rv32(InsnKind::ECALL, 0, 0, 0, 0)]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l5 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightFutureAccessL5,
    )
    .unwrap();
    let initialize = |vm: &mut VMState<_>| {
        vm.init_register_unsafe(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
        vm.init_register_unsafe(Platform::reg_arg0(), CENO_PLATFORM.heap.start);
        vm.init_register_unsafe(Platform::reg_arg1(), 0);
    };
    let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 1 },
    );
    initialize(&mut seed);
    direct.run_to_halt(&mut seed, 1).unwrap();
    let witness = &seed.tracer().syscall_witnesses()[0];
    let source = seed.tracer().recorded_steps()[0].cycle() + crate::FullTracer::SUBCYCLE_RD;
    let tape = Arc::new(NextCycleAccess::from_unsorted(
        witness
            .reg_ops
            .iter()
            .map(|op| NextAccessEvent::new(source, source + 100, op.addr))
            .collect(),
    ));
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 1 },
        Some(tape.clone()),
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program,
        (),
        Some(tape),
    );
    initialize(&mut reference);
    actual.init_register_unsafe(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
    actual.init_register_unsafe(Platform::reg_arg0(), CENO_PLATFORM.heap.start);
    actual.init_register_unsafe(Platform::reg_arg1(), 0);
    direct.run_to_halt(&mut reference, 1).unwrap();
    reference.tracer_mut().annotate_recorded_steps(0);
    let report = l5.run_pure_to_halt(&mut actual, 1).unwrap();
    assert_eq!(report.l1_skeleton_records[0].future_access_mask(), 0);
    assert!(report.l1_skeleton_records[0].l5_later_fields_are_poisoned());
    let expected = &reference.tracer().syscall_witnesses()[0];
    let actual = &actual.tracer().layered_syscall_future_accesses[0];
    assert_eq!(actual.reg_masks, expected.reg_future_access);
    assert_eq!(actual.mem_masks, expected.mem_future_access);
    assert_eq!(actual.reg_masks, vec![1, 1]);
}

#[test]
fn preflight_compact_future_access_l5c_matches_native_scalar_resume_and_closure() {
    assert_eq!(
        AssemblyTraceStyle::PreflightCompactFutureAccessL5C.cache_name(),
        "preflight-compact-future-access-l5c-schema2"
    );
    assert_eq!(std::mem::size_of::<CompactFutureJ>(), 14);
    assert_eq!(std::mem::size_of::<CompactFutureR>(), 29);
    assert_eq!(std::mem::size_of::<CompactFutureLoad>(), 29);
    assert_eq!(std::mem::size_of::<CompactFutureStore>(), 29);
    assert_eq!(std::mem::size_of::<CompactFutureSyscallMask>(), 11);

    let pc_base = CENO_PLATFORM.pc_base();
    let heap = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::JALR, 22, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -16),
        encode_rv32(InsnKind::JAL, 0, 0, 0, -28),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactFutureAccessL5C,
    )
    .unwrap();
    let initialize = |vm: &mut VMState<_>| {
        vm.init_register_unsafe(20, heap);
        vm.init_register_unsafe(22, pc_base + 20);
        vm.init_memory(ByteAddr(heap).waddr(), 0);
    };
    let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 64 },
    );
    initialize(&mut seed);
    direct.run_to_halt(&mut seed, 31).unwrap();
    let events = seed
        .tracer()
        .recorded_steps()
        .iter()
        .flat_map(|record| {
            [
                (
                    crate::FullTracer::SUBCYCLE_RS1,
                    record.rs1().map(|op| op.addr),
                ),
                (
                    crate::FullTracer::SUBCYCLE_RS2,
                    record.rs2().map(|op| op.addr),
                ),
                (
                    crate::FullTracer::SUBCYCLE_RD,
                    record.rd().map(|op| op.addr),
                ),
                (
                    crate::FullTracer::SUBCYCLE_MEM,
                    record.memory_op().map(|op| op.addr),
                ),
            ]
            .into_iter()
            .filter_map(|(subcycle, address)| {
                address.map(|address| {
                    let source = record.cycle() + subcycle;
                    NextAccessEvent::new(source, source + 1_000_000, address)
                })
            })
        })
        .collect::<Vec<_>>();
    let tape = Arc::new(NextCycleAccess::from_unsorted(events));
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 64 },
        Some(tape.clone()),
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program,
        (),
        Some(tape),
    );
    initialize(&mut reference);
    actual.init_register_unsafe(20, heap);
    actual.init_register_unsafe(22, pc_base + 20);
    actual.init_memory(ByteAddr(heap).waddr(), 0);

    for capacity in [1, 2, 4, 5, 6, 7, 6] {
        let start = reference.tracer().recorded_steps().len();
        direct.run_to_halt(&mut reference, capacity).unwrap();
        reference.tracer_mut().annotate_recorded_steps(start);
        let report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
        let expected = &reference.tracer().recorded_steps()[start..start + capacity];
        assert_eq!(report.l1_skeleton_records.len(), capacity);
        assert_eq!(
            report.compact_bytes_written,
            expected
                .iter()
                .map(|record| compact_future_access_row_size(record.insn()))
                .sum::<usize>()
        );
        for (expected, decoded) in expected.iter().zip(&report.l1_skeleton_records) {
            assert_l5_future_access_matches(expected, decoded);
        }
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.peek_register(1), reference.peek_register(1));
        assert_eq!(
            actual.peek_memory(ByteAddr(heap).waddr()),
            reference.peek_memory(ByteAddr(heap).waddr())
        );
    }
    assert_eq!(
        actual.tracer().layered_next_access_cursor,
        actual.tracer().layered_next_accesses.events().len()
    );
}

#[test]
fn preflight_compact_future_access_l5c_matches_syscall_masks() {
    let program = Arc::new(program(vec![encode_rv32(InsnKind::ECALL, 0, 0, 0, 0)]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactFutureAccessL5C,
    )
    .unwrap();
    let initialize = |vm: &mut VMState<_>| {
        vm.init_register_unsafe(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
        vm.init_register_unsafe(Platform::reg_arg0(), CENO_PLATFORM.heap.start);
        vm.init_register_unsafe(Platform::reg_arg1(), 0);
    };
    let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 1 },
    );
    initialize(&mut seed);
    direct.run_to_halt(&mut seed, 1).unwrap();
    let witness = &seed.tracer().syscall_witnesses()[0];
    let source = seed.tracer().recorded_steps()[0].cycle() + crate::FullTracer::SUBCYCLE_RD;
    let tape = Arc::new(NextCycleAccess::from_unsorted(
        witness
            .reg_ops
            .iter()
            .map(|op| NextAccessEvent::new(source, source + 100, op.addr))
            .collect(),
    ));
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 1 },
        Some(tape.clone()),
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program,
        (),
        Some(tape),
    );
    initialize(&mut reference);
    actual.init_register_unsafe(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
    actual.init_register_unsafe(Platform::reg_arg0(), CENO_PLATFORM.heap.start);
    actual.init_register_unsafe(Platform::reg_arg1(), 0);
    direct.run_to_halt(&mut reference, 1).unwrap();
    reference.tracer_mut().annotate_recorded_steps(0);
    let report = compact.run_pure_to_halt(&mut actual, 1).unwrap();
    assert_eq!(report.l1_skeleton_records[0].future_access_mask(), 0);
    let expected = &reference.tracer().syscall_witnesses()[0];
    let mask = actual.tracer().layered_compact_syscall_masks[0];
    let decoded = |index: usize| u8::from(mask.bits[index / 8] & (1 << (index % 8)) != 0);
    assert_eq!(mask.reg_count as usize, expected.reg_future_access.len());
    assert_eq!(mask.mem_count as usize, expected.mem_future_access.len());
    assert_eq!(
        (0..mask.reg_count as usize)
            .map(decoded)
            .collect::<Vec<_>>(),
        expected.reg_future_access
    );
    assert_eq!(
        (0..mask.mem_count as usize)
            .map(|index| decoded(mask.reg_count as usize + index))
            .collect::<Vec<_>>(),
        expected.mem_future_access
    );
}

#[test]
fn preflight_compact_exceptional_l6c_matches_complete_steps_syscalls_and_resume() {
    assert_eq!(
        AssemblyTraceStyle::PreflightCompactExceptionalL6C.cache_name(),
        "preflight-compact-exceptional-l6c-schema2"
    );
    assert_eq!(std::mem::size_of::<CompactL6SyscallHeader>(), 30);
    assert_eq!(std::mem::size_of::<CompactL6WriteOp>(), 20);

    let base = CENO_PLATFORM.pc_base();
    let heap = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::JALR, 22, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 99),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 2, 0),
        encode_rv32(InsnKind::SW, 20, 2, 0, 4),
        encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_arg0().into(), 0),
        encode_rv32(InsnKind::ADDI, 0, 0, Platform::reg_ecall().into(), 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        vec![base + 8],
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        vec![base + 8],
        AssemblyTraceStyle::PreflightCompactExceptionalL6C,
    )
    .unwrap();
    let initialize = |vm: &mut dyn SyscallTestVm| {
        vm.init_register(22, base + 8);
        vm.init_register(20, heap);
        vm.init_register(Platform::reg_ecall(), crate::syscalls::PHANTOM_LOG_PC_CYCLE);
        vm.init_register(Platform::reg_arg0(), heap);
        vm.init_register(Platform::reg_arg1(), 0);
        vm.init_word(ByteAddr(heap).waddr(), 17);
        vm.init_word(ByteAddr(heap + 4).waddr(), 0);
    };
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 16 },
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program);
    initialize(&mut reference);
    initialize(&mut actual);

    for capacity in [1, 2, 1, 3] {
        let start = reference.tracer().recorded_steps().len();
        let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
        reference.tracer_mut().annotate_recorded_steps(start);
        let actual_report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert_eq!(
            actual_report.fallback.dynamic_pc_miss,
            expected_report.fallback.dynamic_pc_miss
        );
        assert_eq!(
            actual_report.fallback.memory_guard,
            expected_report.fallback.memory_guard
        );
        assert_eq!(
            actual_report.fallback.exceptional_jump_or_trap,
            expected_report.fallback.exceptional_jump_or_trap
        );
        assert_eq!(
            actual_report.fallback.ecall_by_code,
            expected_report.fallback.ecall_by_code
        );
        assert_eq!(
            actual_report.l1_skeleton_records,
            reference.tracer().recorded_steps()[start..start + actual_report.executed_steps]
        );
        assert_eq!(
            actual_report.l6_syscall_witnesses,
            reference.tracer().syscall_witnesses()
        );
        assert_eq!(actual.get_pc(), reference.get_pc());
    }
    assert_eq!(
        actual.peek_register(1),
        0,
        "mid-block dynamic target was exact"
    );
    assert_eq!(actual.peek_memory(ByteAddr(heap + 4).waddr()), 17);
    assert_eq!(actual.tracer().layered_compact_l6_syscalls.len(), 2);
    assert_eq!(
        actual.tracer().layered_compact_l6_syscalls[1].syscall_index(),
        crate::StepRecord::NO_SYSCALL
    );
    assert_eq!(actual.tracer().layered_compact_l6_ops.len(), 3);
}

#[test]
fn preflight_compact_exceptional_l6c_matches_multi_op_syscall_capacity_and_repeat() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(
            InsnKind::ADDI,
            0,
            0,
            Platform::reg_ecall().into(),
            Platform::ecall_halt() as i32,
        ),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactExceptionalL6C,
    )
    .unwrap();
    let input: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
        crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();

    for capacity in [3, 4] {
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 4 },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        for vm in [
            &mut reference as &mut dyn SyscallTestVm,
            &mut actual as &mut dyn SyscallTestVm,
        ] {
            vm.init_register(Platform::reg_ecall(), crate::SECP256K1_DOUBLE);
            vm.init_register(Platform::reg_arg0(), base);
            for (offset, value) in input.into_iter().enumerate() {
                vm.init_word(ByteAddr(base).waddr() + offset, value);
            }
        }

        let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
        reference.tracer_mut().annotate_recorded_steps(0);
        let actual_report = compact.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(actual_report.executed_steps, 3);
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert_eq!(
            actual_report.l1_skeleton_records,
            reference.tracer().recorded_steps()
        );
        assert_eq!(
            actual_report.l6_syscall_witnesses,
            reference.tracer().syscall_witnesses()
        );
        assert_eq!(actual_report.l6_syscall_witnesses.len(), 1);
        assert_eq!(
            actual_report.l6_syscall_witnesses[0].mem_ops.len(),
            crate::syscalls::secp256k1::SECP256K1_ARG_WORDS
        );
        assert_eq!(
            actual_report.fallback.ecall_by_code,
            expected_report.fallback.ecall_by_code
        );
        assert_eq!(
            actual_report.fallback.ecall_by_code[&crate::SECP256K1_DOUBLE],
            2
        );
        assert_eq!(actual.get_pc(), reference.get_pc());
    }
}

#[test]
fn preflight_compact_exceptional_l6c_matches_memory_guard_trap_and_repeat() {
    let base = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactExceptionalL6C,
    )
    .unwrap();

    for _ in 0..2 {
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 1 },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        reference.init_register_unsafe(20, base);
        actual.init_register_unsafe(20, base);
        let expected = direct
            .run_to_halt(&mut reference, 1)
            .unwrap_err()
            .to_string();
        let observed = compact
            .run_pure_to_halt(&mut actual, 1)
            .unwrap_err()
            .to_string();
        assert!(expected.contains("LoadAddressMisaligned"));
        assert_eq!(observed, expected);
        assert_eq!(actual.get_pc(), reference.get_pc());
        assert_eq!(actual.tracer().cycle(), reference.tracer().cycle());
    }
}

#[test]
fn preflight_compact_exceptional_l6c_preserves_hot_assembly_and_side_layouts() {
    assert_eq!(std::mem::size_of::<CompactL6SyscallHeader>(), 30);
    assert_eq!(std::mem::size_of::<CompactL6WriteOp>(), 20);
    assert_eq!(std::mem::size_of::<CompactFutureSyscallMask>(), 11);
    let program = program(vec![
        encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 3, 1),
        encode_rv32(InsnKind::BEQ, 1, 2, 0, 4),
        encode_rv32(InsnKind::JAL, 0, 0, 3, 4),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::SW, 20, 3, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]);
    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("l6c.S");
    write_assembly_with_planner(
        &path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightCompactExceptionalL6C,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(path).unwrap();
    let exact_boundary = "    movq 0(%rsp), %rax\n    cmpq %rbp, %rax\n    jae ceno_aot_done";
    assert!(assembly.matches(exact_boundary).count() >= blocks.len() + 1);
    let recorder = assembly
        .split("ceno_aot_compact_registers_l3c_emit_step:\n")
        .nth(1)
        .unwrap()
        .split(".L_compact_registers_l3c_overflow:\n")
        .next()
        .unwrap();
    for size in [6, 14, 18, 21, 29] {
        assert!(recorder.contains(&format!("    addq ${size}, %r9")));
    }
    assert!(!recorder.contains("0xa5a5"));
    assert!(!recorder.contains("memset"));
    assert!(!recorder.contains("StepRecord"));
    assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
    assert!(!assembly.contains("ceno_aot_fulltracer_emit_step:"));
}

#[test]
fn preflight_compact_future_access_l5c_matches_mixed_keccak_xorin_masks() {
    let program = Arc::new(program(vec![encode_rv32(InsnKind::ECALL, 0, 0, 0, 0)]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let compact = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactFutureAccessL5C,
    )
    .unwrap();
    let state = CENO_PLATFORM.heap.start;
    let block = state + 512;
    macro_rules! initialize {
        ($vm:expr) => {{
            $vm.init_register_unsafe(Platform::reg_ecall(), crate::KECCAK_XORIN);
            $vm.init_register_unsafe(Platform::reg_arg0(), state);
            $vm.init_register_unsafe(Platform::reg_arg1(), block);
            for index in 0..crate::syscalls::keccak_xorin::KECCAK_RATE_WORDS {
                $vm.init_memory(
                    ByteAddr(state + (index * WORD_SIZE) as u32).waddr(),
                    index as u32,
                );
                $vm.init_memory(
                    ByteAddr(block + (index * WORD_SIZE) as u32).waddr(),
                    !(index as u32),
                );
            }
        }};
    }
    let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 1 },
    );
    initialize!(seed);
    direct.run_to_halt(&mut seed, 1).unwrap();
    let witness = &seed.tracer().syscall_witnesses()[0];
    assert_eq!(witness.reg_ops.len(), 2);
    assert_eq!(witness.mem_ops.len(), 68);
    let cycle = seed.tracer().recorded_steps()[0].cycle();
    let mut events = vec![NextAccessEvent::new(
        cycle + crate::FullTracer::SUBCYCLE_RD,
        cycle + 100,
        witness.reg_ops[0].addr,
    )];
    events.extend([0, 2, 33, 34, 67].into_iter().map(|index| {
        NextAccessEvent::new(
            cycle + crate::FullTracer::SUBCYCLE_MEM,
            cycle + 100,
            witness.mem_ops[index].addr,
        )
    }));
    let tape = Arc::new(NextCycleAccess::from_unsorted(events));
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 1 },
        Some(tape.clone()),
    );
    let mut actual = VMState::<PureAotTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program,
        (),
        Some(tape),
    );
    initialize!(reference);
    initialize!(actual);
    direct.run_to_halt(&mut reference, 1).unwrap();
    reference.tracer_mut().annotate_recorded_steps(0);
    compact.run_pure_to_halt(&mut actual, 1).unwrap();

    let expected = &reference.tracer().syscall_witnesses()[0];
    let mask = actual.tracer().layered_compact_syscall_masks[0];
    let decoded = |index: usize| u8::from(mask.bits[index / 8] & (1 << (index % 8)) != 0);
    let actual_regs = (0..mask.reg_count as usize)
        .map(decoded)
        .collect::<Vec<_>>();
    let actual_mem = (0..mask.mem_count as usize)
        .map(|index| decoded(mask.reg_count as usize + index))
        .collect::<Vec<_>>();
    assert_eq!(actual_regs, expected.reg_future_access);
    assert_eq!(actual_mem, expected.mem_future_access);
    assert_eq!(actual_regs, vec![1, 0]);
    assert_eq!(actual_mem.iter().filter(|&&bit| bit != 0).count(), 5);
    assert!(actual_mem.iter().any(|&bit| bit == 0));
    assert_eq!(
        actual.tracer().layered_next_access_cursor,
        actual.tracer().layered_next_accesses.events().len()
    );
}

#[test]
fn preflight_compact_future_access_l5c_validates_before_exact_forward_stores() {
    let program = program(vec![
        encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 3, 1),
        encode_rv32(InsnKind::BEQ, 1, 2, 0, 4),
        encode_rv32(InsnKind::JAL, 0, 0, 3, 4),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::SW, 20, 3, 0, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]);
    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("l5c.S");
    write_assembly_with_planner(
        &path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightCompactFutureAccessL5C,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(path).unwrap();
    let exact_boundary = "    movq 0(%rsp), %rax\n    cmpq %rbp, %rax\n    jae ceno_aot_done";
    assert!(
        assembly.matches(exact_boundary).count() >= blocks.len() + 1,
        "every L5C block leader plus the dispatcher must close an exact bound"
    );
    for block in &blocks {
        let label = format!("ceno_aot_bb_{:08x}:\n", block.start_pc);
        let leader = assembly
            .split(&label)
            .nth(1)
            .unwrap()
            .lines()
            .take(8)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            leader.contains(exact_boundary),
            "L5C block leader {:#010x} must close an exact bound",
            block.start_pc
        );
    }
    let recorder = assembly
        .split("ceno_aot_compact_registers_l3c_emit_step:\n")
        .nth(1)
        .unwrap()
        .split(".L_compact_registers_l3c_overflow:\n")
        .next()
        .unwrap();
    let first_family = recorder.find(".L_compact_registers_l3c_r:\n").unwrap();
    let validation = &recorder[..first_family];
    assert!(validation.contains(".L_compact_future_l5c_event_loop:"));
    assert!(validation.contains("cmpq %rdx, %rax\n    jb .L_compact_registers_l3c_overflow"));
    assert!(validation.contains("jne .L_compact_registers_l3c_overflow"));
    assert!(validation.contains("incq %rcx\n    movq %rcx, (%r8)"));
    assert!(
        !validation
            .lines()
            .any(|line| line.trim_end().ends_with("(%r10)")),
        "event validation must precede every destination store"
    );

    let expected = [
        ("r", 29, &["movq", "movq", "movq", "movl", "movb"][..]),
        ("i", 21, &["movq", "movq", "movl", "movb"][..]),
        ("branch", 21, &["movq", "movq", "movl", "movb"][..]),
        ("j", 14, &["movq", "movl", "movw"][..]),
        ("load", 29, &["movq", "movq", "movq", "movl", "movb"][..]),
        ("store", 29, &["movq", "movq", "movq", "movl", "movb"][..]),
        ("exceptional", 18, &["movq", "movq", "movw"][..]),
        ("header", 6, &["movl", "movw"][..]),
    ];
    for (index, (family, size, mnemonics)) in expected.iter().enumerate() {
        let label = format!(".L_compact_registers_l3c_{family}:\n");
        let body = recorder.split(&label).nth(1).unwrap();
        let body = if let Some((next_family, _, _)) = expected.get(index + 1) {
            body.split(&format!(".L_compact_registers_l3c_{next_family}:\n"))
                .next()
                .unwrap()
        } else {
            body
        };
        let stores = body
            .lines()
            .filter(|line| line.contains("(%r10)"))
            .collect::<Vec<_>>();
        assert_eq!(stores.len(), mnemonics.len(), "L5C {family} store count");
        for (store, mnemonic) in stores.iter().zip(*mnemonics) {
            assert!(store.trim_start().starts_with(mnemonic));
            assert!(
                store.trim_end().ends_with("(%r10)"),
                "destination load/RMW: {store}"
            );
        }
        assert!(body.contains(&format!("    addq ${size}, %r9")));
    }
    assert!(!recorder.contains("0xa5a5"));
    assert!(!recorder.contains("memset"));
    assert!(!recorder.contains("StepRecord"));
    assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
    assert!(!assembly.contains("ceno_aot_fulltracer_emit_step:"));
}

#[test]
fn aot_dynamic_dispatch_handles_jalr_into_block_middle() {
    let base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 3, 1),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 7),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));

    let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
    interp.init_register_unsafe(1, base + 8);
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
    aot_vm.init_register_unsafe(1, base + 8);
    let report = aot.run_to_halt(&mut aot_vm, 10).unwrap();

    assert_eq!(report.executed_steps, 3);
    assert_eq!(aot_vm.peek_register(2), 7);
    assert_eq!(aot_vm.peek_register(3), 0);
    assert_eq!(
        aot_vm.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
}

#[test]
fn aot_jalr_misalignment_uses_exact_slow_path_trap() {
    let base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![encode_rv32(InsnKind::JALR, 1, 0, 0, 0)]));
    let aot = AotProgram::compile_fulltracer(program.clone()).unwrap();
    let mut vm = VMState::new(CENO_PLATFORM.clone(), program);
    vm.init_register_unsafe(1, base + 2);

    let err = aot.run_to_halt(&mut vm, 1).unwrap_err().to_string();

    assert!(err.contains("InstructionAddressMisaligned"));
}

#[test]
#[cfg(not(debug_assertions))]
fn fulltracer_direct_records_match_interpreter() {
    let base = CENO_PLATFORM.stack.start + 64;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 5),
        encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
        encode_rv32(InsnKind::SW, 20, 2, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::BEQ, 2, 3, 0, 4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let config = crate::FullTracerConfig { max_step_shard: 16 };

    let mut interp = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config,
    );
    interp.init_register_unsafe(20, base);
    interp.init_memory(ByteAddr(base).waddr(), 0);
    while interp.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let mut direct = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    direct.init_register_unsafe(20, base);
    direct.init_memory(ByteAddr(base).waddr(), 0);
    let report = aot.run_to_halt(&mut direct, 16).unwrap();

    assert_eq!(report.fallback_steps, 1, "only the halt ecall falls back");
    assert_eq!(direct.peek_register(3), interp.peek_register(3));
    assert_eq!(direct.peek_memory(ByteAddr(base).waddr()), 10);
    assert_eq!(
        direct.tracer().recorded_steps(),
        interp.tracer().recorded_steps()
    );
    assert_eq!(
        direct.tracer().syscall_witnesses(),
        interp.tracer().syscall_witnesses()
    );
}

#[test]
#[cfg(not(debug_assertions))]
fn gpu_replay_direct_typed_rows_match_interpreter_without_trace_callbacks() {
    let base = CENO_PLATFORM.heap.start;
    let pc_base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 5),
        encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
        encode_rv32(InsnKind::BEQ, 1, 0, 0, 8),
        encode_rv32(InsnKind::LUI, 0, 0, 4, 0x12000),
        encode_rv32(InsnKind::JAL, 0, 0, 12, 4),
        encode_rv32(InsnKind::JALR, 11, 0, 7, 0),
        encode_rv32(InsnKind::SW, 20, 2, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let mut family_counts = [0usize; InsnKind::COUNT];
    family_counts[InsnKind::ADDI as usize] = 1;
    family_counts[InsnKind::ADD as usize] = 1;
    family_counts[InsnKind::BEQ as usize] = 1;
    family_counts[InsnKind::LUI as usize] = 1;
    family_counts[InsnKind::JAL as usize] = 1;
    family_counts[InsnKind::JALR as usize] = 1;
    family_counts[InsnKind::SW as usize] = 1;
    family_counts[InsnKind::LW as usize] = 1;
    let descriptors = Arc::new(vec![crate::GpuReplayRangeDescriptor {
        shard_id: 0,
        sequence: 0,
        range_start: 0,
        range_len: 9,
        family_counts,
        fallback_count: 1,
        unsupported_count: 0,
    }]);
    let config = crate::GpuReplayTracerConfig { chunk_capacity: 9 };

    let mut interp = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        config,
    );
    interp
        .tracer_mut()
        .install_range_descriptors(descriptors.clone());
    interp.init_register_unsafe(20, base);
    interp.init_register_unsafe(11, pc_base + 24);
    interp.init_memory(ByteAddr(base).waddr(), 0);
    while interp.next_step_record().unwrap().is_some() {}
    interp.tracer_mut().finish_chunks();
    let expected = interp.tracer_mut().take_sealed_chunks().remove(0);

    let aot = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        vec![pc_base + 24],
        AssemblyTraceStyle::GpuReplayDirect,
    )
    .unwrap();
    let mut direct = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        config,
    );
    direct.tracer_mut().install_range_descriptors(descriptors);
    direct.init_register_unsafe(20, base);
    direct.init_register_unsafe(11, pc_base + 24);
    direct.init_memory(ByteAddr(base).waddr(), 0);
    // Force two returns in the middle of one compiled basic block. The
    // next entry must use the native resume table, never dynamic-PC Rust
    // fallback.
    let reports = (0..9)
        .map(|_| aot.run_to_halt(&mut direct, 1).unwrap())
        .collect::<Vec<_>>();
    direct.tracer_mut().finish_chunks();
    let actual = direct.tracer_mut().take_sealed_chunks().remove(0);

    assert_eq!(
        reports
            .iter()
            .map(|report| report.executed_steps)
            .sum::<usize>(),
        9
    );
    assert_eq!(
        reports
            .iter()
            .map(|report| report.fallback_steps)
            .sum::<usize>(),
        1
    );
    assert_eq!(
        reports
            .iter()
            .map(|report| report.fallback.dynamic_pc_miss)
            .sum::<usize>(),
        0
    );
    assert_eq!(actual.sequence, expected.sequence);
    for (kind_index, (actual, expected)) in actual.typed.iter().zip(&expected.typed).enumerate() {
        assert_eq!(
            actual.as_ref().map(crate::GpuTypedSoaArena::kind),
            expected.as_ref().map(crate::GpuTypedSoaArena::kind)
        );
        assert_eq!(
            actual.as_ref().map(crate::GpuTypedSoaArena::len),
            expected.as_ref().map(crate::GpuTypedSoaArena::len)
        );
        assert_eq!(
            actual.as_ref().map(crate::GpuTypedSoaArena::fields),
            expected.as_ref().map(crate::GpuTypedSoaArena::fields)
        );
        assert_eq!(
            actual.as_ref().map(crate::GpuTypedSoaArena::payload_bytes),
            expected
                .as_ref()
                .map(crate::GpuTypedSoaArena::payload_bytes),
            "kind={:?}",
            InsnKind::iter().nth(kind_index)
        );
        assert_eq!(
            actual.as_ref().map(crate::GpuTypedSoaArena::pc_base),
            expected.as_ref().map(crate::GpuTypedSoaArena::pc_base)
        );
    }
    assert_eq!(actual.fallback, expected.fallback);
    assert_eq!(AOT_NATIVE_CALLBACK_TRACE.load(Ordering::Relaxed), 0);
}

#[test]
#[cfg(not(debug_assertions))]
fn gpu_replay_direct_preserves_cycles_past_27_bits() {
    let program = Arc::new(program(vec![encode_rv32(InsnKind::OR, 1, 2, 3, 0)]));
    let mut family_counts = [0usize; InsnKind::COUNT];
    family_counts[InsnKind::OR as usize] = 1;
    let descriptors = Arc::new(vec![crate::GpuReplayRangeDescriptor {
        shard_id: 0,
        sequence: 0,
        range_start: 10,
        range_len: 1,
        family_counts,
        fallback_count: 0,
        unsupported_count: 0,
    }]);
    let aot = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::GpuReplayDirect,
    )
    .unwrap();
    let mut vm = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program,
        crate::GpuReplayTracerConfig { chunk_capacity: 1 },
    );
    vm.tracer_mut().install_range_descriptors(descriptors);
    let cycle_base = 1u64 << 27;
    let state = vm.tracer_mut().prepare_native_range();
    unsafe {
        *state.ordinal = 10;
        *state.pending_cycle = cycle_base + 40;
        for (reg, relative) in [(1u32, 7u64), (2, 8), (3, 9)] {
            let index = ((reg << 6) - state.latest_base.0) as usize;
            *state.latest_cells.add(index) = cycle_base + relative;
        }
    }
    assert_eq!(aot.run_to_halt(&mut vm, 1).unwrap().executed_steps, 1);
    vm.tracer_mut().finish_chunks();
    let chunk = vm.tracer_mut().take_sealed_chunks().remove(0);
    let payload = chunk.typed[InsnKind::OR as usize]
        .as_ref()
        .unwrap()
        .payload_bytes();
    let compact_bits = |bit: usize| {
        let mut window = 0u64;
        for index in 0..5 {
            window |= u64::from(payload[bit / 8 + index]) << (index * 8);
        }
        (window >> (bit % 8)) as u32
    };
    assert_eq!(compact_bits(63), (cycle_base + 7) as u32);
    assert_eq!(compact_bits(127), (cycle_base + 8) as u32);
    assert_eq!(compact_bits(191), (cycle_base + 9) as u32);
}

#[test]
#[cfg(not(debug_assertions))]
fn i061_l8_gpu_replay_packed_whole_blocks_match_interpreter_initialized_prefixes() {
    let heap = CENO_PLATFORM.heap.start;
    let pc_base = CENO_PLATFORM.pc_base();
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 5),
        // rs1/rs2/rd alias: predecessors must advance in subcycle order.
        encode_rv32(InsnKind::ADD, 1, 1, 1, 0),
        encode_rv32(InsnKind::BEQ, 1, 0, 0, 8),
        encode_rv32(InsnKind::LUI, 0, 0, 4, 0x12000),
        encode_rv32(InsnKind::JAL, 0, 0, 12, 4),
        // rs1/rd alias while the target still uses the before value.
        encode_rv32(InsnKind::JALR, 11, 0, 11, 0),
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    macro_rules! initialize {
        ($vm:expr) => {{
            $vm.init_register_unsafe(20, heap);
            $vm.init_register_unsafe(11, pc_base + 24);
            $vm.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
            $vm.init_memory(ByteAddr(heap).waddr(), 0);
        }};
    }

    // Build a nonempty tape covering every enabled ordinary access. Both
    // implementations must consume it in exact source-cycle/subcycle order.
    let mut seed = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 10 },
    );
    initialize!(seed);
    while seed.next_step_record().unwrap().is_some() {}
    let mut events = Vec::new();
    for record in seed.tracer().recorded_steps() {
        for (subcycle, address) in [
            (
                crate::FullTracer::SUBCYCLE_RS1,
                record.rs1().map(|op| op.addr),
            ),
            (
                crate::FullTracer::SUBCYCLE_RS2,
                record.rs2().map(|op| op.addr),
            ),
            (
                crate::FullTracer::SUBCYCLE_RD,
                record.rd().map(|op| op.addr),
            ),
            (
                crate::FullTracer::SUBCYCLE_MEM,
                record.memory_op().map(|op| op.addr),
            ),
        ] {
            if let Some(address) = address {
                let source = record.cycle() + subcycle;
                events.push(NextAccessEvent::new(source, source + 1_000_000, address));
            }
        }
    }
    assert!(!events.is_empty());
    let tape = Arc::new(NextCycleAccess::from_unsorted(events));

    let mut family_counts = [0usize; InsnKind::COUNT];
    for kind in [
        InsnKind::ADDI,
        InsnKind::ADD,
        InsnKind::BEQ,
        InsnKind::LUI,
        InsnKind::JAL,
        InsnKind::JALR,
        InsnKind::SW,
        InsnKind::LW,
    ] {
        family_counts[kind as usize] = 1;
    }
    let descriptors = Arc::new(vec![crate::GpuReplayRangeDescriptor {
        shard_id: 0,
        sequence: 0,
        range_start: 0,
        range_len: 9,
        family_counts,
        fallback_count: 1,
        unsupported_count: 0,
    }]);
    let config = crate::GpuReplayTracerConfig { chunk_capacity: 10 };

    let mut expected = VMState::<crate::GpuReplayTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program.clone(),
        config,
        Some(tape.clone()),
    );
    expected
        .tracer_mut()
        .install_range_descriptors(descriptors.clone());
    initialize!(expected);
    while expected.next_step_record().unwrap().is_some() {}

    let aot = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        vec![pc_base + 24],
        AssemblyTraceStyle::GpuReplayDirect,
    )
    .unwrap();
    let mut actual = VMState::<crate::GpuReplayTracer>::new_with_tracer_config_and_next_accesses(
        CENO_PLATFORM.clone(),
        program,
        config,
        Some(tape.clone()),
    );
    actual.tracer_mut().install_range_descriptors(descriptors);
    initialize!(actual);
    let report = aot.run_to_halt(&mut actual, 10).unwrap();
    assert_eq!(report.executed_steps, 9);
    assert_eq!(report.fallback_steps, 1);
    assert_eq!(actual.get_pc(), expected.get_pc());
    assert_eq!(actual.peek_register(1), expected.peek_register(1));
    assert_eq!(actual.peek_memory(ByteAddr(heap).waddr()), 10);

    let snapshot = |tracer: &mut crate::GpuReplayTracer| {
        let state = tracer.prepare_native_range();
        let kinds = unsafe { std::slice::from_raw_parts(state.kinds, state.kind_count) };
        let cursors = kinds
            .iter()
            .map(|kind| {
                (
                    kind.cursor,
                    kind.capacity,
                    kind.layout,
                    kind.sentinel,
                    kind.range_start,
                    kind.pc_base,
                )
            })
            .collect::<Vec<_>>();
        unsafe {
            (
                *state.ordinal,
                *state.next_access_cursor,
                *state.latest_len,
                cursors,
            )
        }
    };
    let expected_snapshot = snapshot(expected.tracer_mut());
    let actual_snapshot = snapshot(actual.tracer_mut());
    assert_eq!(actual_snapshot, expected_snapshot);
    assert_eq!(actual_snapshot.0, 9);
    assert_eq!(actual_snapshot.1, tape.events().len());
    assert_eq!(actual_snapshot.3[InsnKind::ADD as usize].0, 1);
    assert_eq!(actual_snapshot.3[InsnKind::ADD as usize].4, 0);

    let mut addresses = expected
        .tracer()
        .final_register_accesses()
        .addresses()
        .chain(actual.tracer().final_register_accesses().addresses())
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    assert!(!addresses.is_empty());
    for address in addresses {
        assert_eq!(
            actual.tracer().final_register_accesses().cycle(address),
            expected.tracer().final_register_accesses().cycle(address),
            "latest state at {address:?}"
        );
    }

    expected.tracer_mut().finish_chunks();
    actual.tracer_mut().finish_chunks();
    let expected = expected.tracer_mut().take_sealed_chunks().remove(0);
    let actual = actual.tracer_mut().take_sealed_chunks().remove(0);
    for (kind_index, (actual, expected)) in actual.typed.iter().zip(&expected.typed).enumerate() {
        assert_eq!(
            actual.as_ref().map(crate::GpuTypedSoaArena::len),
            expected.as_ref().map(crate::GpuTypedSoaArena::len)
        );
        assert_eq!(
            actual.as_ref().map(crate::GpuTypedSoaArena::range_start),
            expected.as_ref().map(crate::GpuTypedSoaArena::range_start)
        );
        assert_eq!(
            actual.as_ref().map(crate::GpuTypedSoaArena::pc_base),
            expected.as_ref().map(crate::GpuTypedSoaArena::pc_base)
        );
        assert_eq!(
            actual.as_ref().map(crate::GpuTypedSoaArena::payload_bytes),
            expected
                .as_ref()
                .map(crate::GpuTypedSoaArena::payload_bytes),
            "kind={:?}",
            InsnKind::iter().nth(kind_index)
        );
    }
    assert_eq!(actual.fallback, expected.fallback);
}

#[test]
#[cfg(not(debug_assertions))]
fn i061_l8_gpu_replay_packed_fallback_errors_leave_no_gap_or_duplicate_on_retry() {
    let heap = CENO_PLATFORM.heap.start;
    let pc_base = CENO_PLATFORM.pc_base();

    let memory_program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 0)]));
    let mut memory_counts = [0usize; InsnKind::COUNT];
    memory_counts[InsnKind::LW as usize] = 1;
    let memory_descriptors = Arc::new(vec![crate::GpuReplayRangeDescriptor {
        shard_id: 0,
        sequence: 0,
        range_start: 0,
        range_len: 1,
        family_counts: memory_counts,
        fallback_count: 0,
        unsupported_count: 0,
    }]);
    let config = crate::GpuReplayTracerConfig { chunk_capacity: 3 };
    let memory_aot = AotProgram::compile_with_extra_roots_and_trace_style(
        memory_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::GpuReplayDirect,
    )
    .unwrap();
    let mut memory = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        memory_program.clone(),
        config,
    );
    memory
        .tracer_mut()
        .install_range_descriptors(memory_descriptors.clone());
    memory.init_register_unsafe(20, heap + 1);
    let error = memory_aot
        .run_to_halt(&mut memory, 1)
        .unwrap_err()
        .to_string();
    assert!(error.contains("rejected fallback category 2"));
    let rolled = memory.tracer_mut().prepare_native_range();
    assert_eq!(unsafe { *rolled.ordinal }, 0);
    assert_eq!(
        unsafe { (*rolled.kinds.add(InsnKind::LW as usize)).cursor },
        0
    );

    memory.init_register_unsafe(20, heap);
    memory.init_memory(ByteAddr(heap).waddr(), 0x1122_3344);
    memory.set_pc(ByteAddr(pc_base));
    let retry = memory_aot.run_to_halt(&mut memory, 1).unwrap();
    assert_eq!(retry.executed_steps, 1);
    let retried = memory.tracer_mut().prepare_native_range();
    assert_eq!(unsafe { *retried.ordinal }, 1);
    assert_eq!(
        unsafe { (*retried.kinds.add(InsnKind::LW as usize)).cursor },
        1
    );

    let jalr_program = Arc::new(program(vec![
        encode_rv32(InsnKind::JALR, 11, 0, 11, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let mut jalr_counts = [0usize; InsnKind::COUNT];
    jalr_counts[InsnKind::JALR as usize] = 1;
    let jalr_descriptors = Arc::new(vec![crate::GpuReplayRangeDescriptor {
        shard_id: 0,
        sequence: 0,
        range_start: 0,
        range_len: 2,
        family_counts: jalr_counts,
        fallback_count: 1,
        unsupported_count: 0,
    }]);
    let jalr_aot = AotProgram::compile_with_extra_roots_and_trace_style(
        jalr_program.clone(),
        vec![pc_base + 4],
        AssemblyTraceStyle::GpuReplayDirect,
    )
    .unwrap();
    let mut jalr = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        jalr_program.clone(),
        config,
    );
    jalr.tracer_mut()
        .install_range_descriptors(jalr_descriptors.clone());
    jalr.init_register_unsafe(11, pc_base + 2);
    jalr.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
    let error = jalr_aot.run_to_halt(&mut jalr, 2).unwrap_err().to_string();
    assert!(error.contains("InstructionAddressMisaligned"));
    let rolled = jalr.tracer_mut().prepare_native_range();
    assert_eq!(unsafe { *rolled.ordinal }, 0);
    assert_eq!(
        unsafe { (*rolled.kinds.add(InsnKind::JALR as usize)).cursor },
        0
    );

    // A trapped interpreter step retains partial pending tracer state, so
    // resume semantics are validated from a fresh VM at the same PC. The
    // failed owner above must nevertheless remain completely unpublished.
    let mut jalr_retry = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        jalr_program.clone(),
        config,
    );
    jalr_retry
        .tracer_mut()
        .install_range_descriptors(jalr_descriptors.clone());
    jalr_retry.init_register_unsafe(11, pc_base + 4);
    jalr_retry.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
    let retry = jalr_aot.run_to_halt(&mut jalr_retry, 2).unwrap();
    assert_eq!(retry.executed_steps, 2);
    assert_eq!(retry.fallback_steps, 1);
    let retried = jalr_retry.tracer_mut().prepare_native_range();
    assert_eq!(unsafe { *retried.ordinal }, 2);
    assert_eq!(
        unsafe { (*retried.kinds.add(InsnKind::JALR as usize)).cursor },
        1
    );

    let mut expected = VMState::<crate::GpuReplayTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        jalr_program,
        config,
    );
    expected
        .tracer_mut()
        .install_range_descriptors(jalr_descriptors);
    expected.init_register_unsafe(11, pc_base + 4);
    expected.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
    while expected.next_step_record().unwrap().is_some() {}
    expected.tracer_mut().finish_chunks();
    jalr_retry.tracer_mut().finish_chunks();
    let expected = expected.tracer_mut().take_sealed_chunks().remove(0);
    let actual = jalr_retry.tracer_mut().take_sealed_chunks().remove(0);
    assert_eq!(
        actual.typed[InsnKind::JALR as usize]
            .as_ref()
            .unwrap()
            .payload_bytes(),
        expected.typed[InsnKind::JALR as usize]
            .as_ref()
            .unwrap()
            .payload_bytes()
    );
    assert_eq!(actual.fallback, expected.fallback);
}

#[test]
fn production_preflight_uses_admitted_block_emitter() {
    assert_eq!(
        production_preflight_trace_style(),
        AssemblyTraceStyle::PreflightProduction
    );
    let program = program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
    ]);
    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let model = crate::StepCellExtractor::shard_cost_model(&OneCellPerNativeStep).unwrap();
    let planner_metadata = build_aot_block_cost_descriptors(&program, &blocks, &model).unwrap();
    let cache = tempfile::tempdir().unwrap();
    let production = cache.path().join("production.S");
    write_assembly_with_planner(
        &production,
        &program,
        &blocks,
        &order,
        production_preflight_trace_style(),
        Some(&planner_metadata),
    )
    .unwrap();
    let production = fs::read(production).unwrap();
    let assembly = String::from_utf8(production).unwrap();
    assert!(assembly.contains("preflight_bucket_special_fail"));
    assert!(!assembly.contains(".L_preflight_cost_loop_0:"));
}

#[test]
fn i049_capture_requires_memory_address_when_release_events_emit_early() {
    let trace_style = AssemblyTraceStyle::PreflightProductionCapture;
    assert!(trace_style.needs_callback_values());
    assert!(!trace_style.preflight_feature_enabled(PreflightFeature::MmioBounds));
    assert!(trace_style.uses_preflight_block_plan());
    assert!(should_publish_trace_memory_address(
        trace_style,
        false,
        true
    ));
    assert!(!should_publish_trace_memory_address(
        AssemblyTraceStyle::PreflightProduction,
        false,
        true,
    ));
}

#[test]
fn preflight_compact_closure_l7_assembly_admits_transactionally_and_uses_static_ranks() {
    let program = program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
        encode_rv32(InsnKind::ADDI, 2, 0, 3, 1),
        encode_rv32(InsnKind::ADD, 2, 3, 4, 0),
    ]);
    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let dir = tempfile::tempdir().unwrap();
    let assembly_path = dir.path().join("l7.S");
    write_assembly_with_planner(
        &assembly_path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightCompactClosureL7,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(assembly_path).unwrap();
    let admission_end = assembly
        .find(&format!(
            ".L_l7_admission_done_{:08x}:\n",
            CENO_PLATFORM.pc_base()
        ))
        .unwrap();
    let admission = &assembly[..admission_end];
    let first_publication = admission.find("addl $2, 108(%r10)").unwrap();
    let last_capacity_check = admission.rfind("ja .L_l7_admission_error_").unwrap();
    assert!(last_capacity_check < first_publication);
    assert_eq!(admission.matches("addl $2, 108(%r10)").count(), 2);

    // Both interleaved families address final_cursor-2 then
    // final_cursor-1. The latter needs no restoration.
    assert_eq!(assembly.matches("subl $2, 108(%r10)").count(), 2);
    assert_eq!(assembly.matches("subl $1, 108(%r10)").count(), 2);
    assert_eq!(
        l7_block_family_rank(
            &program,
            CENO_PLATFORM.pc_base(),
            CENO_PLATFORM.pc_base() + 16,
            CENO_PLATFORM.pc_base() + 8,
            InsnKind::ADDI,
        )
        .unwrap(),
        (2, 1)
    );
    assert_eq!(
        l7_block_family_rank(
            &program,
            CENO_PLATFORM.pc_base(),
            CENO_PLATFORM.pc_base() + 16,
            CENO_PLATFORM.pc_base() + 12,
            InsnKind::ADD,
        )
        .unwrap(),
        (2, 1)
    );
    let u_packer = assembly
        .split(".L_gpu_compact_pack_u:\n")
        .nth(1)
        .unwrap()
        .split("// Assemble the common 63-bit prefix")
        .next()
        .unwrap();
    assert_eq!(
        u_packer
            .lines()
            .filter(|line| line.contains("(%r9)"))
            .collect::<Vec<_>>(),
        [
            "    movq %r8, 0(%r9)",
            "    movq %r8, 8(%r9)",
            "    movl %r8d, 16(%r9)",
        ]
    );
    assert!(!assembly.contains("ceno_aot_fulltracer_emit_step:"));
    assert!(!assembly.contains("ceno_aot_skeleton_l1_emit_step:"));
    assert!(!assembly.contains("memset"));
    assert!(!assembly.contains("StepRecord"));
}

#[test]
fn gpu_replay_shared_packed_emitter_is_default_and_has_forward_destination_stores() {
    let layout_program = program(vec![
        encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 3, 1),
        encode_rv32(InsnKind::BEQ, 1, 2, 0, 4),
        encode_rv32(InsnKind::JAL, 0, 0, 3, 4),
        encode_rv32(InsnKind::JALR, 1, 0, 3, 0),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::SW, 20, 2, 0, 0),
        encode_rv32(InsnKind::LUI, 0, 0, 3, 0x12000),
    ]);
    let blocks = partition_basic_blocks_with_roots(
        &layout_program,
        (0..layout_program.instructions.len())
            .map(|index| CENO_PLATFORM.pc_base() + (index * PC_STEP_SIZE) as u32)
            .collect(),
    )
    .unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let dir = tempfile::tempdir().unwrap();
    let assembly_path = dir.path().join("shared-packed.S");
    write_assembly_with_planner(
        &assembly_path,
        &layout_program,
        &blocks,
        &order,
        AssemblyTraceStyle::GpuReplayDirect,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(assembly_path).unwrap();

    assert_eq!(
        selected_emitter_variant(AssemblyTraceStyle::GpuReplayDirect),
        AotEmitterVariant::SharedPacked
    );
    assert!(assembly.contains("ceno_aot_gpu_replay_emit_step:"));
    assert!(assembly.contains("call ceno_aot_gpu_replay_emit_step"));
    assert!(!assembly.contains(".L_gpu_replay_packed_static_"));
    assert!(!assembly.contains(&format!(
        "movl $1, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
    )));

    let compact = assembly
        .split(".L_gpu_replay_compact:\n")
        .nth(1)
        .unwrap()
        .split(".L_gpu_replay_bad_kind:\n")
        .next()
        .unwrap();
    assert!(compact.contains(".L_gpu_compact_pack_1:"));
    assert!(compact.contains(".L_gpu_compact_pack_2:"));
    assert!(compact.contains(".L_gpu_compact_pack_3:"));
    assert!(compact.contains(".L_gpu_compact_pack_u:"));
    assert!(
        !compact.lines().any(|line| line.contains("(%r9),")),
        "shared compact packer must not load or RMW its destination"
    );
    for store in [
        "movq %r8, 0(%r9)",
        "movq %r8, 8(%r9)",
        "movq %r8, 16(%r9)",
        "movq %rdx, 24(%r9)",
    ] {
        assert!(compact.contains(store), "missing forward store {store}");
    }
    assert!(!assembly.contains("StepRecord"));
}

#[test]
#[ignore = "internal diagnostic emitter; run with CENO_AOT_GPU_REPLAY_EMITTER=fully-inlined-diagnostic"]
fn i061_l8_gpu_replay_packed_blocks_use_transactional_static_exact_stores() {
    let layout_program = program(vec![
        encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
        encode_rv32(InsnKind::ADDI, 1, 0, 3, 1),
        encode_rv32(InsnKind::BEQ, 1, 2, 0, 4),
        encode_rv32(InsnKind::JAL, 0, 0, 3, 4),
        encode_rv32(InsnKind::JALR, 1, 0, 3, 0),
        encode_rv32(InsnKind::LW, 20, 0, 3, 0),
        encode_rv32(InsnKind::SW, 20, 2, 0, 0),
        encode_rv32(InsnKind::LUI, 0, 0, 3, 0x12000),
    ]);
    let blocks = partition_basic_blocks_with_roots(
        &layout_program,
        (0..layout_program.instructions.len())
            .map(|index| CENO_PLATFORM.pc_base() + (index * PC_STEP_SIZE) as u32)
            .collect(),
    )
    .unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let dir = tempfile::tempdir().unwrap();
    let assembly_path = dir.path().join("l8-packed.S");
    write_assembly_with_planner(
        &assembly_path,
        &layout_program,
        &blocks,
        &order,
        AssemblyTraceStyle::GpuReplayDirect,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(assembly_path).unwrap();

    let admission_end = assembly
        .find(&format!(
            ".L_l7_admission_done_{:08x}:\n",
            CENO_PLATFORM.pc_base()
        ))
        .unwrap();
    let admission = &assembly[..admission_end];
    assert!(
        admission.rfind("ja .L_l7_admission_error_").unwrap()
            < admission.find("addl $1, 108(%r10)").unwrap()
    );
    assert!(assembly.contains(&format!(
        "movl $1, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
    )));

    let expected = [
        (0usize, 6usize),
        (1, 3),
        (2, 3),
        (3, 2),
        (4, 3),
        (5, 6),
        (6, 6),
        (7, 3),
    ];
    for (instruction_index, expected_stores) in expected {
        let pc = CENO_PLATFORM.pc_base() + (instruction_index * PC_STEP_SIZE) as u32;
        let body = assembly
            .split(&format!(".L_gpu_replay_packed_static_{pc:x}:\n"))
            .nth(1)
            .unwrap()
            .split(&format!(".L_gpu_replay_emit_done_{pc:x}:\n"))
            .next()
            .unwrap();
        assert!(!body.contains("call ceno_aot_gpu_replay_emit_step"));
        assert!(!body.contains("call .L_gpu_compact_pack_common"));
        assert!(!body.contains("movq 8(%r9)"));
        let stores = body
            .lines()
            .filter(|line| {
                line.contains("movq %r8, ")
                    || line.contains("movl %r8d, ")
                    || line.contains("movw %r8w, ")
                    || line.contains("movb %r8b, ")
            })
            .filter(|line| line.contains("(%r9)"))
            .count();
        assert_eq!(stores, expected_stores, "packed stores at {pc:#010x}");
        if expected_stores == 6 {
            assert!(body.contains("movl %r8d, 24(%r9)"));
            assert!(body.contains("movw %r8w, 28(%r9)"));
            assert!(body.contains("movb %r8b, 30(%r9)"));
            assert!(!body.contains("movq %r8, 24(%r9)"));
        }
        if instruction_index == 7 {
            assert!(body.contains(&format!(
                "movl {AOT_CTX_LAYERED_RS1_PREVIOUS_OFFSET}(%r12), %eax"
            )));
            assert!(!body.contains("xorl %eax, %eax"));
        }
    }

    let memory_slow = assembly
        .split(&format!(
            ".L_memory_slow_{:x}:\n",
            CENO_PLATFORM.pc_base() + 5 * PC_STEP_SIZE as u32
        ))
        .nth(1)
        .unwrap()
        .split(".popsection")
        .next()
        .unwrap();
    assert!(memory_slow.contains("subl $1, 108(%r10)"));
    assert!(
        memory_slow.find("subl $1, 108(%r10)").unwrap()
            < memory_slow.find("call *72(%rsp)").unwrap()
    );
    assert!(!memory_slow.contains("addl $1, 108(%r10)"));

    let jalr_slow = assembly
        .split(&format!(
            ".L_jalr_slow_{:x}:\n",
            CENO_PLATFORM.pc_base() + 4 * PC_STEP_SIZE as u32
        ))
        .nth(1)
        .unwrap()
        .split(&format!(
            ".L_jalr_done_{:x}:\n",
            CENO_PLATFORM.pc_base() + 4 * PC_STEP_SIZE as u32
        ))
        .next()
        .unwrap();
    assert!(jalr_slow.contains("subq $1, 0(%rsp)"));
    assert!(jalr_slow.contains("subl $1, 108(%r10)"));
    assert!(
        jalr_slow.find("subq $1, 0(%rsp)").unwrap() < jalr_slow.find("call *72(%rsp)").unwrap()
    );
    assert!(
        jalr_slow.find("subl $1, 108(%r10)").unwrap() < jalr_slow.find("call *72(%rsp)").unwrap()
    );
    assert!(!jalr_slow.contains("addl $1, 108(%r10)"));

    // A nonterminal memory row rolls back the current and all later
    // reservations before the callback, then republishes only the rows
    // that remain after the callback-owned current row.
    let memory_program = program(vec![
        encode_rv32(InsnKind::SW, 20, 1, 0, 0),
        encode_rv32(InsnKind::LW, 20, 0, 2, 4),
        encode_rv32(InsnKind::SW, 20, 2, 0, 8),
        encode_rv32(InsnKind::LW, 20, 0, 3, 12),
        encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
    ]);
    let memory_blocks = partition_basic_blocks(&memory_program).unwrap();
    let memory_order = memory_blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let memory_path = dir.path().join("l8-memory-remaining.S");
    write_assembly_with_planner(
        &memory_path,
        &memory_program,
        &memory_blocks,
        &memory_order,
        AssemblyTraceStyle::GpuReplayDirect,
        None,
    )
    .unwrap();
    let memory_assembly = fs::read_to_string(memory_path).unwrap();
    let memory_slow = memory_assembly
        .split(&format!(".L_memory_slow_{:x}:\n", CENO_PLATFORM.pc_base()))
        .nth(1)
        .unwrap()
        .split(".popsection")
        .next()
        .unwrap();
    for expected in ["subq $5, 0(%rsp)", "subl $2, 108(%r10)"] {
        assert!(memory_slow.contains(expected));
        assert!(memory_slow.find(expected).unwrap() < memory_slow.find("call *72(%rsp)").unwrap());
    }
    for expected in ["addl $1, 108(%r10)", "addq $4, 0(%rsp)"] {
        assert!(memory_slow.contains(expected));
        assert!(memory_slow.find("call *72(%rsp)").unwrap() < memory_slow.find(expected).unwrap());
    }
    for (index, expected_from_end) in [(0usize, 5u64), (1, 4), (2, 3), (3, 2)] {
        let pc = CENO_PLATFORM.pc_base() + (index * PC_STEP_SIZE) as u32;
        let body = memory_assembly
            .split(&format!(".L_memory_body_{pc:x}:\n"))
            .nth(1)
            .unwrap()
            .split(&format!(".L_fulltracer_direct_done_{pc:x}:\n"))
            .next()
            .unwrap();
        assert!(body.contains(&format!(
            "cmpl $0, {AOT_CTX_GPU_REPLAY_PACKED_BLOCK_OFFSET}(%r12)"
        )));
        assert!(body.contains(&format!("subq ${expected_from_end}, %rcx")));
    }

    let rank_program = program(vec![
        encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
        encode_rv32(InsnKind::ADDI, 3, 0, 3, 1),
        encode_rv32(InsnKind::ADD, 3, 2, 3, 0),
    ]);
    let rank_blocks = partition_basic_blocks(&rank_program).unwrap();
    let rank_order = rank_blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let rank_path = dir.path().join("l8-static-ranks.S");
    write_assembly_with_planner(
        &rank_path,
        &rank_program,
        &rank_blocks,
        &rank_order,
        AssemblyTraceStyle::GpuReplayDirect,
        None,
    )
    .unwrap();
    let rank_assembly = fs::read_to_string(rank_path).unwrap();
    for (index, expected_rank_from_end) in [(0usize, 2u32), (2, 1)] {
        let pc = CENO_PLATFORM.pc_base() + (index * PC_STEP_SIZE) as u32;
        let body = rank_assembly
            .split(&format!(".L_gpu_replay_packed_static_{pc:x}:\n"))
            .nth(1)
            .unwrap()
            .split(&format!(".L_gpu_replay_emit_done_{pc:x}:\n"))
            .next()
            .unwrap();
        assert!(body.contains(&format!("subl ${expected_rank_from_end}, %eax")));
    }
}

#[test]
#[cfg(not(debug_assertions))]
fn preflight_compact_closure_l7_matches_compact_oracle_across_capacity_boundaries() {
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
        encode_rv32(InsnKind::ADDI, 2, 0, 3, 1),
        encode_rv32(InsnKind::ADD, 2, 3, 4, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l7 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactClosureL7,
    )
    .unwrap();

    for capacity in [3, 4, 5] {
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig {
                max_step_shard: capacity,
            },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        reference.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        actual.init_register_unsafe(Platform::reg_ecall(), Platform::ecall_halt());
        let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
        let actual_report = l7.run_pure_to_halt(&mut actual, capacity).unwrap();
        assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
        assert_eq!(actual.get_pc(), reference.get_pc());

        for kind in [InsnKind::ADDI, InsnKind::ADD] {
            let expected = reference
                .tracer()
                .recorded_steps()
                .iter()
                .enumerate()
                .filter(|(_, record)| record.insn().kind == kind)
                .collect::<Vec<_>>();
            let mut oracle =
                crate::GpuTypedSoaArena::new_compact_with_range(kind, expected.len(), 0).unwrap();
            for (ordinal, record) in expected {
                oracle.push_step(ordinal as u32, record).unwrap();
            }
            let actual = actual_report
                .l7_family_payloads
                .iter()
                .find(|(actual_kind, _, _, _)| *actual_kind == kind)
                .unwrap();
            assert_eq!(actual.1, oracle.range_start());
            assert_eq!(actual.2, oracle.pc_base());
            assert_eq!(
                actual.3,
                oracle.payload_bytes(),
                "kind={kind:?}, capacity={capacity}"
            );
        }
    }
}

#[test]
#[cfg(not(debug_assertions))]
fn preflight_compact_closure_l7_matches_every_layout_scalar_native_and_repeat() {
    let base = CENO_PLATFORM.pc_base();
    let heap = CENO_PLATFORM.heap.start;
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
        encode_rv32(InsnKind::ADD, 1, 1, 2, 0),
        encode_rv32(InsnKind::LUI, 0, 0, 3, 0x1000),
        encode_rv32(InsnKind::LW, 20, 0, 4, 0),
        encode_rv32(InsnKind::SW, 20, 4, 0, 4),
        encode_rv32(InsnKind::BNE, 1, 0, 0, 4),
        encode_rv32(InsnKind::JAL, 0, 0, 7, 4),
        encode_rv32(InsnKind::JALR, 22, 0, 8, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        vec![base + 32],
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l7 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        vec![base + 32],
        AssemblyTraceStyle::PreflightCompactClosureL7,
    )
    .unwrap();

    for capacities in [&[1usize; 9][..], &[16usize][..]] {
        let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
            CENO_PLATFORM.clone(),
            program.clone(),
            crate::FullTracerConfig { max_step_shard: 16 },
        );
        let mut actual =
            VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
        for vm in [
            &mut reference as &mut dyn SyscallTestVm,
            &mut actual as &mut dyn SyscallTestVm,
        ] {
            vm.init_register(20, heap);
            vm.init_register(22, base + 32);
            vm.init_register(Platform::reg_ecall(), Platform::ecall_halt());
            vm.init_word(ByteAddr(heap).waddr(), 0x1122_3344);
            vm.init_word(ByteAddr(heap + 4).waddr(), 0);
        }

        for &capacity in capacities {
            let start = reference.tracer().recorded_steps().len();
            let expected_report = direct.run_to_halt(&mut reference, capacity).unwrap();
            reference.tracer_mut().annotate_recorded_steps(start);
            let actual_report = l7.run_pure_to_halt(&mut actual, capacity).unwrap();
            let expected =
                &reference.tracer().recorded_steps()[start..start + expected_report.executed_steps];
            assert_eq!(actual_report.executed_steps, expected_report.executed_steps);
            assert_eq!(actual.get_pc(), reference.get_pc());

            let mut expected_family_bytes = 0;
            for kind in [
                InsnKind::ADD,
                InsnKind::ADDI,
                InsnKind::BNE,
                InsnKind::JAL,
                InsnKind::JALR,
                InsnKind::LW,
                InsnKind::SW,
                InsnKind::LUI,
            ] {
                let records = expected
                    .iter()
                    .enumerate()
                    .filter(|(_, record)| record.insn().kind == kind)
                    .collect::<Vec<_>>();
                if records.is_empty() {
                    continue;
                }
                let mut oracle =
                    crate::GpuTypedSoaArena::new_compact_with_range(kind, records.len(), 0)
                        .unwrap();
                for (ordinal, record) in records {
                    oracle.push_step(ordinal as u32, record).unwrap();
                }
                expected_family_bytes += oracle.payload_bytes().len();
                let routed = actual_report
                    .l7_family_payloads
                    .iter()
                    .find(|(actual_kind, _, _, _)| *actual_kind == kind)
                    .unwrap();
                assert_eq!(routed.1, oracle.range_start(), "kind={kind:?}");
                assert_eq!(routed.2, oracle.pc_base(), "kind={kind:?}");
                assert_eq!(routed.3, oracle.payload_bytes(), "kind={kind:?}");
            }
            assert_eq!(
                actual_report
                    .l7_family_payloads
                    .iter()
                    .map(|(_, _, _, payload)| payload.len())
                    .sum::<usize>(),
                expected_family_bytes
            );
            assert_eq!(
                actual_report.l6_syscall_witnesses,
                reference.tracer().syscall_witnesses()
            );
            if actual.halted() {
                break;
            }
        }
        assert!(actual.halted());
        assert_eq!(actual.peek_register(2), 2);
        assert_eq!(actual.peek_memory(ByteAddr(heap + 4).waddr()), 0x1122_3344);
        assert_eq!(actual.tracer().layered_compact_l6_syscalls.len(), 1);
        assert_eq!(
            actual.tracer().layered_compact_l6_syscalls[0].syscall_index(),
            crate::StepRecord::NO_SYSCALL
        );
        assert_eq!(actual.tracer().layered_compact_l6_ops.len(), 1);
    }
}

#[test]
#[cfg(not(debug_assertions))]
fn preflight_compact_closure_l7_reuses_reserved_row_after_memory_guard() {
    let heap = CENO_PLATFORM.heap.start;
    // The second load makes the block-wide guard reject, while the first
    // load remains a successful scalar memory-guard fallback. The later
    // trap keeps this fixture bounded; the assembly assertions prove that
    // the successful fallback targets and restores its reserved L7 row.
    let program = Arc::new(program(vec![
        encode_rv32(InsnKind::LW, 20, 0, 1, 0),
        encode_rv32(InsnKind::LW, 21, 0, 2, 0),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l7 = AotProgram::compile_with_extra_roots_and_trace_style(
        program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactClosureL7,
    )
    .unwrap();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        program.clone(),
        crate::FullTracerConfig { max_step_shard: 2 },
    );
    let mut actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), program.clone());
    for vm in [
        &mut reference as &mut dyn SyscallTestVm,
        &mut actual as &mut dyn SyscallTestVm,
    ] {
        vm.init_register(20, heap);
        vm.init_register(21, heap + 1);
        vm.init_word(ByteAddr(heap).waddr(), 0x1122_3344);
    }

    let expected = direct
        .run_to_halt(&mut reference, 2)
        .unwrap_err()
        .to_string();
    let observed = l7.run_pure_to_halt(&mut actual, 2).unwrap_err().to_string();
    assert!(expected.contains("LoadAddressMisaligned"));
    assert_eq!(observed, expected);
    assert_eq!(actual.peek_register(1), 0x1122_3344);
    assert_eq!(actual.get_pc(), reference.get_pc());
    assert_eq!(actual.tracer().cycle(), reference.tracer().cycle());

    let blocks = partition_basic_blocks(&program).unwrap();
    let order = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<Vec<_>>();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l7-memory-guard.S");
    write_assembly_with_planner(
        &path,
        &program,
        &blocks,
        &order,
        AssemblyTraceStyle::PreflightCompactClosureL7,
        None,
    )
    .unwrap();
    let assembly = fs::read_to_string(path).unwrap();
    let slow = assembly
        .split(&format!(".L_memory_slow_{:x}:\n", CENO_PLATFORM.pc_base()))
        .nth(1)
        .unwrap()
        .split(".popsection")
        .next()
        .unwrap();
    assert!(slow.contains("subl $2, 108(%r10)"));
    assert!(slow.contains("call *72(%rsp)"));
    assert!(slow.contains("addl $1, 108(%r10)"));
}

#[test]
#[cfg(not(debug_assertions))]
fn preflight_compact_closure_l7_preserves_multi_op_and_trap_side_totals() {
    let heap = CENO_PLATFORM.heap.start;
    let syscall_program = Arc::new(program(vec![
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32(
            InsnKind::ADDI,
            0,
            0,
            Platform::reg_ecall().into(),
            Platform::ecall_halt() as i32,
        ),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]));
    let direct = AotProgram::compile_with_extra_roots_and_trace_style(
        syscall_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::FullTracerDirect,
    )
    .unwrap();
    let l7 = AotProgram::compile_with_extra_roots_and_trace_style(
        syscall_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactClosureL7,
    )
    .unwrap();
    let input: [Word; crate::syscalls::secp256k1::SECP256K1_ARG_WORDS] =
        crate::syscalls::secp256k1::SecpMaybePoint(secp::Point::generator().into()).into();
    let mut reference = VMState::<crate::FullTracer>::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        syscall_program.clone(),
        crate::FullTracerConfig { max_step_shard: 3 },
    );
    let mut actual =
        VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), syscall_program);
    for vm in [
        &mut reference as &mut dyn SyscallTestVm,
        &mut actual as &mut dyn SyscallTestVm,
    ] {
        vm.init_register(Platform::reg_ecall(), crate::SECP256K1_DOUBLE);
        vm.init_register(Platform::reg_arg0(), heap);
        for (offset, value) in input.into_iter().enumerate() {
            vm.init_word(ByteAddr(heap).waddr() + offset, value);
        }
    }
    direct.run_to_halt(&mut reference, 3).unwrap();
    reference.tracer_mut().annotate_recorded_steps(0);
    let report = l7.run_pure_to_halt(&mut actual, 3).unwrap();
    assert_eq!(
        report.l6_syscall_witnesses,
        reference.tracer().syscall_witnesses()
    );
    assert_eq!(actual.tracer().layered_compact_l6_syscalls.len(), 2);
    assert_eq!(
        actual.tracer().layered_compact_l6_syscalls.len()
            * std::mem::size_of::<CompactL6SyscallHeader>(),
        60
    );
    let expected_ops = report
        .l6_syscall_witnesses
        .iter()
        .map(|witness| witness.reg_ops.len() + witness.mem_ops.len())
        .sum::<usize>()
        + 1;
    assert_eq!(actual.tracer().layered_compact_l6_ops.len(), expected_ops);
    assert_eq!(
        actual.tracer().layered_compact_l6_ops.len() * std::mem::size_of::<CompactL6WriteOp>(),
        expected_ops * 20
    );

    let trap_program = Arc::new(program(vec![encode_rv32(InsnKind::LW, 20, 0, 1, 1)]));
    let trap_l7 = AotProgram::compile_with_extra_roots_and_trace_style(
        trap_program.clone(),
        Vec::new(),
        AssemblyTraceStyle::PreflightCompactClosureL7,
    )
    .unwrap();
    let mut trap = VMState::<PureAotTracer>::new_with_tracer(CENO_PLATFORM.clone(), trap_program);
    trap.init_register_unsafe(20, heap);
    let err = trap_l7
        .run_pure_to_halt(&mut trap, 1)
        .unwrap_err()
        .to_string();
    assert!(err.contains("LoadAddressMisaligned"));
    assert_eq!(trap.tracer().layered_compact_l6_syscalls.len(), 0);
    assert_eq!(trap.tracer().layered_compact_l6_ops.len(), 0);
    assert_eq!(trap.tracer().layered_compact_syscall_masks.len(), 0);
}

#[test]
fn planner_aware_parallel_compile_links() {
    let program = program(vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
        encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
        encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]);
    let blocks = partition_basic_blocks(&program).unwrap();
    let layout = pc_order_layout(&blocks);
    let model = crate::StepCellExtractor::shard_cost_model(&OneCellPerNativeStep).unwrap();
    let planner_metadata = build_aot_block_cost_descriptors(&program, &blocks, &model).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let asm = dir.path().join("program.S");
    let so = dir.path().join("program.so");

    compile_native_to_with_jobs(
        &program,
        &blocks,
        &layout.emission_order,
        production_preflight_trace_style(),
        Some(&planner_metadata),
        &asm,
        &so,
        4,
    )
    .unwrap();

    load_native(&so, "preflight-production", "test").unwrap();
}
