use crate::{
    error::ZKVMError,
    instructions::riscv::{DummyExtraConfig, MemPadder, MmuConfig, Rv32imConfig},
    scheme::{
        PublicValues, ZKVMProof,
        mock_prover::{LkMultiplicityKey, MockProver},
        prover::ZKVMProver,
        verifier::ZKVMVerifier,
    },
    state::GlobalState,
    structs::{
        ProgramParams, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMProvingKey, ZKVMVerifyingKey,
        ZKVMWitnesses,
    },
    tables::{MemFinalRecord, MemInitRecord, ProgramTableCircuit, ProgramTableConfig},
};
use ceno_emul::{
    Addr, ByteAddr, CENO_PLATFORM, EmuContext, InsnKind, IterAddresses, Platform, Program,
    StepRecord, Tracer, VMState, WORD_SIZE, WordAddr, host_utils::read_all_messages,
};
use clap::ValueEnum;
use ff_ext::{BabyBearExt4, ExtensionField};
#[cfg(debug_assertions)]
use ff_ext::{Instrumented, PoseidonField};
use gkr_iop::cpu::{CpuBackend, CpuProver};
use itertools::{Itertools, MinMaxResult, chain};
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme, SecurityLevel};
use p3::{babybear::BabyBear, goldilocks::Goldilocks};
use serde::Serialize;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};
use tracing::info;
use transcript::BasicTranscript as Transcript;

/// The polynomial commitment scheme kind
#[derive(
    Default,
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    ValueEnum,
    strum_macros::AsRefStr,
    strum_macros::Display,
    strum_macros::IntoStaticStr,
)]
pub enum PcsKind {
    #[default]
    Basefold,
    Whir,
}

/// The field type
#[derive(
    Default,
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    ValueEnum,
    strum_macros::AsRefStr,
    strum_macros::Display,
    strum_macros::IntoStaticStr,
)]
pub enum FieldType {
    #[default]
    Goldilocks,
    BabyBear,
}

// pub type E = GoldilocksExt2;
// pub type B = Goldilocks;
// pub type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;

pub type E = BabyBearExt4;
pub type B = BabyBear;
pub type Pcs = Basefold<E, BasefoldRSParams>;

pub struct FullMemState<Record> {
    pub mem: Vec<Record>,
    pub io: Vec<Record>,
    pub reg: Vec<Record>,
    pub hints: Vec<Record>,
    pub stack: Vec<Record>,
    pub heap: Vec<Record>,
}

type InitMemState = FullMemState<MemInitRecord>;
type FinalMemState = FullMemState<MemFinalRecord>;

pub struct EmulationResult {
    pub exit_code: Option<u32>,
    pub all_records: Vec<StepRecord>,
    pub final_mem_state: FinalMemState,
    pub pi: PublicValues,
}

pub fn emulate_program(
    program: Arc<Program>,
    max_steps: usize,
    init_mem_state: &InitMemState,
    platform: &Platform,
) -> EmulationResult {
    let InitMemState {
        mem: mem_init,
        io: io_init,
        reg: reg_init,
        hints: hints_init,
        stack: _,
        heap: _,
    } = init_mem_state;

    let mut vm: VMState = VMState::new(platform.clone(), program);

    for record in chain!(hints_init, io_init) {
        vm.init_memory(record.addr.into(), record.value);
    }

    let all_records_result: Result<Vec<StepRecord>, _> =
        vm.iter_until_halt().take(max_steps).collect();

    if platform.is_debug {
        let all_messages = read_all_messages(&vm)
            .iter()
            .map(|msg| String::from_utf8_lossy(msg).to_string())
            .collect::<Vec<_>>();

        if !all_messages.is_empty() {
            tracing::info!("========= BEGIN: I/O from guest =========");
            for msg in &all_messages {
                tracing::info!("│ {}", msg);
            }
            tracing::info!("========= END: I/O from guest =========");
        }
    }
    let all_records = all_records_result.expect("vm exec failed");

    // Find the exit code from the HALT step, if halting at all.
    let exit_code = all_records
        .iter()
        .rev()
        .find(|record| {
            record.insn().kind == InsnKind::ECALL
                && record.rs1().unwrap().value == Platform::ecall_halt()
        })
        .and_then(|halt_record| halt_record.rs2())
        .map(|rs2| rs2.value);

    let final_access = vm.tracer().final_accesses();
    let end_cycle = vm.tracer().cycle();
    let insts = vm.tracer().executed_insts();
    tracing::info!("program executed {insts} instructions in {end_cycle} cycles");

    let pi = PublicValues::new(
        exit_code.unwrap_or(0),
        vm.program().entry,
        Tracer::SUBCYCLES_PER_INSN,
        vm.get_pc().into(),
        end_cycle,
        io_init.iter().map(|rec| rec.value).collect_vec(),
    );

    // Find the final register values and cycles.
    let reg_final = reg_init
        .iter()
        .map(|rec| {
            let index = rec.addr as usize;
            if index < VMState::REG_COUNT {
                let vma: WordAddr = Platform::register_vma(index).into();
                MemFinalRecord {
                    addr: rec.addr,
                    value: vm.peek_register(index),
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            } else {
                // The table is padded beyond the number of registers.
                MemFinalRecord {
                    addr: rec.addr,
                    value: 0,
                    cycle: 0,
                }
            }
        })
        .collect_vec();

    // Find the final memory values and cycles.
    let mem_final = mem_init
        .iter()
        .map(|rec| {
            let vma: WordAddr = rec.addr.into();
            MemFinalRecord {
                addr: rec.addr,
                value: vm.peek_memory(vma),
                cycle: *final_access.get(&vma).unwrap_or(&0),
            }
        })
        .collect_vec();

    // Find the final public IO cycles.
    let io_final = io_init
        .iter()
        .map(|rec| MemFinalRecord {
            addr: rec.addr,
            value: rec.value,
            cycle: *final_access.get(&rec.addr.into()).unwrap_or(&0),
        })
        .collect_vec();

    // Find the final hints IO cycles.
    let hints_final = hints_init
        .iter()
        .map(|rec| MemFinalRecord {
            addr: rec.addr,
            value: rec.value,
            cycle: *final_access.get(&rec.addr.into()).unwrap_or(&0),
        })
        .collect_vec();

    // get stack access by min/max range
    let stack_final = if let Some((min_waddr, _)) = vm
        .tracer()
        .probe_min_max_address_by_start_addr(ByteAddr::from(platform.stack.start).waddr())
    {
        (min_waddr..ByteAddr::from(platform.stack.end).waddr())
            // stack record collect in reverse order
            .rev()
            .map(|vma| {
                let byte_addr = vma.baddr();
                MemFinalRecord {
                    addr: byte_addr.0,
                    value: vm.peek_memory(vma),
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            })
            .collect_vec()
    } else {
        vec![]
    };

    // get heap access by min/max range
    let heap_start_waddr = ByteAddr::from(platform.heap.start).waddr();
    // note: min_waddr for the heap is intentionally ignored
    // as the actual starting address may be shifted due to alignment requirements
    // e.g. heap start addr 0x90000000 + 32 bytes alignment => 0x90000000 % 32 = 16 → offset = 16 bytes → moves to 0x90000010.
    let heap_final = if let Some((_, max_waddr)) = vm
        .tracer()
        .probe_min_max_address_by_start_addr(heap_start_waddr)
    {
        (heap_start_waddr..max_waddr)
            .map(|vma| {
                let byte_addr = vma.baddr();
                MemFinalRecord {
                    addr: byte_addr.0,
                    value: vm.peek_memory(vma),
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            })
            .collect_vec()
    } else {
        vec![]
    };

    debug_memory_ranges(
        &vm,
        chain!(
            &mem_final,
            &io_final,
            &hints_final,
            &stack_final,
            &heap_final
        ),
    );

    EmulationResult {
        pi,
        exit_code,
        all_records,
        final_mem_state: FinalMemState {
            reg: reg_final,
            io: io_final,
            mem: mem_final,
            hints: hints_final,
            stack: stack_final,
            heap: heap_final,
        },
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Preset {
    Ceno,
}

pub fn setup_platform(
    preset: Preset,
    program: &Program,
    stack_size: u32,
    heap_size: u32,
    pub_io_size: u32,
) -> Platform {
    setup_platform_inner(preset, program, stack_size, heap_size, pub_io_size, false)
}

pub fn setup_platform_debug(
    preset: Preset,
    program: &Program,
    stack_size: u32,
    heap_size: u32,
    pub_io_size: u32,
) -> Platform {
    setup_platform_inner(preset, program, stack_size, heap_size, pub_io_size, true)
}

fn setup_platform_inner(
    preset: Preset,
    program: &Program,
    stack_size: u32,
    heap_size: u32,
    pub_io_size: u32,
    is_debug: bool,
) -> Platform {
    let preset = match preset {
        Preset::Ceno => Platform {
            is_debug,
            ..CENO_PLATFORM
        },
    };

    let prog_data = program.image.keys().copied().collect::<BTreeSet<_>>();

    let stack = if preset.is_debug {
        // reserve some extra space for io
        // thus memory consistent check could be satisfied
        preset.stack.end - stack_size..(preset.stack.end + 0x4000)
    } else {
        preset.stack.end - stack_size..preset.stack.end
    };

    let heap = {
        // Detect heap as starting after program data.
        let heap_start = program.sheap;
        let heap = heap_start..heap_start + heap_size;
        // pad the total size to the next power of two.
        let mem_size = heap.iter_addresses().len();
        let pad_size = mem_size.next_power_of_two() - mem_size;
        let heap_end = heap.end as usize + pad_size * WORD_SIZE;
        assert!(
            heap_end <= u32::MAX as usize,
            "not enough space for padding; reduce heap size"
        );
        heap.start..heap_end as u32
    };

    let platform = Platform {
        rom: program.base_address
            ..program.base_address + (program.instructions.len() * WORD_SIZE) as u32,
        prog_data,
        stack,
        heap,
        public_io: preset.public_io.start..preset.public_io.start + pub_io_size.next_power_of_two(),
        ..preset
    };
    assert!(
        platform.validate(),
        "invalid platform configuration: {platform}"
    );

    platform
}

pub fn init_static_addrs(program: &Program) -> Vec<MemInitRecord> {
    let program_addrs = program
        .image
        .iter()
        .map(|(addr, value)| MemInitRecord {
            addr: *addr,
            value: *value,
        })
        .sorted_by_key(|record| record.addr)
        .collect_vec();

    assert!(
        program_addrs.len().is_power_of_two(),
        "program_addrs.len {} is not pow2",
        program_addrs.len(),
    );
    program_addrs
}

pub struct ConstraintSystemConfig<E: ExtensionField> {
    pub zkvm_cs: ZKVMConstraintSystem<E>,
    pub config: Rv32imConfig<E>,
    pub mmu_config: MmuConfig<E>,
    pub dummy_config: DummyExtraConfig<E>,
    pub prog_config: ProgramTableConfig,
}

pub fn construct_configs<E: ExtensionField>(
    program_params: ProgramParams,
) -> ConstraintSystemConfig<E> {
    let mut zkvm_cs = ZKVMConstraintSystem::new_with_platform(program_params);

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let mmu_config = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    let dummy_config = DummyExtraConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();
    ConstraintSystemConfig {
        zkvm_cs,
        config,
        mmu_config,
        dummy_config,
        prog_config,
    }
}

pub fn generate_fixed_traces<E: ExtensionField>(
    system_config: &ConstraintSystemConfig<E>,
    reg_init: &[MemInitRecord],
    static_mem_init: &[MemInitRecord],
    io_addrs: &[Addr],
    program: &Program,
) -> ZKVMFixedTraces<E> {
    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();

    zkvm_fixed_traces.register_table_circuit::<ProgramTableCircuit<E>>(
        &system_config.zkvm_cs,
        &system_config.prog_config,
        program,
    );

    system_config
        .config
        .generate_fixed_traces(&system_config.zkvm_cs, &mut zkvm_fixed_traces);
    system_config.mmu_config.generate_fixed_traces(
        &system_config.zkvm_cs,
        &mut zkvm_fixed_traces,
        reg_init,
        static_mem_init,
        io_addrs,
    );
    system_config
        .dummy_config
        .generate_fixed_traces(&system_config.zkvm_cs, &mut zkvm_fixed_traces);

    zkvm_fixed_traces
}

pub fn generate_witness<E: ExtensionField>(
    system_config: &ConstraintSystemConfig<E>,
    emul_result: EmulationResult,
    program: &Program,
    is_mock_proving: bool,
) -> ZKVMWitnesses<E> {
    let mut zkvm_witness = ZKVMWitnesses::default();
    // assign opcode circuits
    let dummy_records = system_config
        .config
        .assign_opcode_circuit(
            &system_config.zkvm_cs,
            &mut zkvm_witness,
            emul_result.all_records,
        )
        .unwrap();
    system_config
        .dummy_config
        .assign_opcode_circuit(&system_config.zkvm_cs, &mut zkvm_witness, dummy_records)
        .unwrap();
    zkvm_witness.finalize_lk_multiplicities(is_mock_proving);

    // assign table circuits
    system_config
        .config
        .assign_table_circuit(&system_config.zkvm_cs, &mut zkvm_witness)
        .unwrap();
    system_config
        .mmu_config
        .assign_table_circuit(
            &system_config.zkvm_cs,
            &mut zkvm_witness,
            &emul_result.final_mem_state.reg,
            &emul_result.final_mem_state.mem,
            &emul_result
                .final_mem_state
                .io
                .iter()
                .map(|rec| rec.cycle)
                .collect_vec(),
            &emul_result.final_mem_state.hints,
            &emul_result.final_mem_state.stack,
            &emul_result.final_mem_state.heap,
        )
        .unwrap();
    // assign program circuit
    zkvm_witness
        .assign_table_circuit::<ProgramTableCircuit<E>>(
            &system_config.zkvm_cs,
            &system_config.prog_config,
            program,
        )
        .unwrap();

    zkvm_witness
}

// Encodes useful early return points of the e2e pipeline
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Checkpoint {
    PrepE2EProving,
    PrepWitnessGen,
    PrepProof,
    PrepVerify,
    #[default]
    Complete,
}

// Currently handles state required by the sanity check in `bin/e2e.rs`
// Future cases would require this to be an enum
pub type IntermediateState<E, PCS> = (Option<ZKVMProof<E, PCS>>, Option<ZKVMVerifyingKey<E, PCS>>);

/// Context construct from a program and given platform
pub struct E2EProgramCtx<E: ExtensionField> {
    pub program: Arc<Program>,
    pub platform: Platform,
    pub static_addrs: Vec<MemInitRecord>,
    pub pubio_len: usize,
    pub system_config: ConstraintSystemConfig<E>,
    pub reg_init: Vec<MemInitRecord>,
    pub io_init: Vec<MemInitRecord>,
    pub zkvm_fixed_traces: ZKVMFixedTraces<E>,
}

/// end-to-end pipeline result, stopping at a certain checkpoint
pub struct E2ECheckpointResult<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    /// The proof generated by the pipeline, if any
    pub proof: Option<ZKVMProof<E, PCS>>,
    /// The verifying key generated by the pipeline, if any
    pub vk: Option<ZKVMVerifyingKey<E, PCS>>,
    /// The next step to run after the checkpoint
    next_step: Option<Box<dyn FnOnce()>>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> E2ECheckpointResult<E, PCS> {
    pub fn next_step(self) {
        if let Some(next_step) = self.next_step {
            next_step();
        }
    }
}

/// Set up a program with the given platform
pub fn setup_program<E: ExtensionField>(program: Program, platform: Platform) -> E2EProgramCtx<E> {
    let static_addrs = init_static_addrs(&program);
    let pubio_len = platform.public_io.iter_addresses().len();
    let program_params = ProgramParams {
        platform: platform.clone(),
        program_size: program.instructions.len(),
        static_memory_len: static_addrs.len(),
        pubio_len,
    };
    let system_config = construct_configs::<E>(program_params);
    let reg_init = system_config.mmu_config.initial_registers();
    let io_init = MemPadder::new_mem_records_uninit(platform.public_io.clone(), pubio_len);

    // Generate fixed traces
    let zkvm_fixed_traces = generate_fixed_traces(
        &system_config,
        &reg_init,
        &static_addrs,
        &io_init.iter().map(|rec| rec.addr).collect_vec(),
        &program,
    );

    E2EProgramCtx {
        program: Arc::new(program),
        platform,
        static_addrs,
        pubio_len,
        system_config,
        reg_init,
        io_init,
        zkvm_fixed_traces,
    }
}

impl<E: ExtensionField> E2EProgramCtx<E> {
    pub fn keygen<PCS: PolynomialCommitmentScheme<E> + 'static>(
        &self,
        max_num_variables: usize,
        security_level: SecurityLevel,
    ) -> (ZKVMProvingKey<E, PCS>, ZKVMVerifyingKey<E, PCS>) {
        let pcs_param =
            PCS::setup(1 << max_num_variables, security_level).expect("Basefold PCS setup");
        let (pp, vp) = PCS::trim(pcs_param, 1 << max_num_variables).expect("Basefold trim");
        let pk = self
            .system_config
            .zkvm_cs
            .clone()
            .key_gen::<PCS>(pp.clone(), vp.clone(), self.zkvm_fixed_traces.clone())
            .expect("keygen failed");
        let vk = pk.get_vk_slow();
        (pk, vk)
    }

    /// Setup init mem state
    pub fn setup_init_mem(&self, hints: &[u32], public_io: &[u32]) -> InitMemState {
        let mut io_init = self.io_init.clone();
        MemPadder::init_mem_records(&mut io_init, public_io);
        let hint_init = MemPadder::new_mem_records(
            self.platform.hints.clone(),
            hints.len().next_power_of_two(),
            hints,
        );

        InitMemState {
            mem: self.static_addrs.clone(),
            reg: self.reg_init.clone(),
            io: io_init,
            hints: hint_init,
            // stack/heap both init value 0 and range is dynamic
            stack: vec![],
            heap: vec![],
        }
    }
}

// Runs end-to-end pipeline, stopping at a certain checkpoint and yielding useful state.
//
// The return type is a pair of:
// 1. Explicit state
// 2. A no-input-no-ouptut closure
//
// (2.) is useful when you want to setup a certain action and run it
// elsewhere (i.e, in a benchmark)
// (1.) is useful for exposing state which must be further combined with
// state external to this pipeline (e.g, sanity check in bin/e2e.rs)

#[allow(clippy::too_many_arguments)]
pub fn run_e2e_with_checkpoint<
    E: ExtensionField + LkMultiplicityKey + serde::de::DeserializeOwned,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
>(
    program: Program,
    platform: Platform,
    hints: &[u32],
    public_io: &[u32],
    max_steps: usize,
    max_num_variables: usize,
    security_level: SecurityLevel,
    checkpoint: Checkpoint,
) -> E2ECheckpointResult<E, PCS> {
    let start = std::time::Instant::now();
    let ctx = setup_program::<E>(program, platform);
    tracing::debug!("setup_program done in {:?}", start.elapsed());

    // Keygen
    let start = std::time::Instant::now();
    let (pk, vk) = ctx.keygen(max_num_variables, security_level);
    tracing::debug!("keygen done in {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let init_full_mem = ctx.setup_init_mem(hints, public_io);
    tracing::debug!("setup_init_mem done in {:?}", start.elapsed());

    // Generate witness
    let is_mock_proving = std::env::var("MOCK_PROVING").is_ok();
    if let Checkpoint::PrepE2EProving = checkpoint {
        return E2ECheckpointResult {
            proof: None,
            vk: Some(vk),
            next_step: Some(Box::new(move || {
                _ = run_e2e_proof::<E, _>(&ctx, &init_full_mem, pk, max_steps, is_mock_proving)
            })),
        };
    }

    // Emulate program
    let start = std::time::Instant::now();
    let emul_result = emulate_program(
        ctx.program.clone(),
        max_steps,
        &init_full_mem,
        &ctx.platform,
    );
    tracing::debug!("emulate done in {:?}", start.elapsed());

    // Clone some emul_result fields before consuming
    let pi = emul_result.pi.clone();
    let exit_code = emul_result.exit_code;

    if let Checkpoint::PrepWitnessGen = checkpoint {
        return E2ECheckpointResult {
            proof: None,
            vk: Some(vk),
            next_step: Some(Box::new(move || {
                // When we run e2e and halt before generate_witness, this implies we are going to
                // benchmark generate_witness performance. So we skip mock proving check on
                // `generate_witness` to avoid it affecting the benchmark result.
                _ = generate_witness(&ctx.system_config, emul_result, &ctx.program, false)
            })),
        };
    }

    let zkvm_witness = generate_witness(
        &ctx.system_config,
        emul_result,
        &ctx.program,
        is_mock_proving,
    );

    // proving
    let backend: CpuBackend<E, PCS> = CpuBackend::new();
    let device = CpuProver::new(backend);
    let mut prover = ZKVMProver::new(pk, device);

    if is_mock_proving {
        MockProver::assert_satisfied_full(
            &ctx.system_config.zkvm_cs,
            ctx.zkvm_fixed_traces.clone(),
            &zkvm_witness,
            &pi,
            &ctx.program,
        );
        tracing::info!("Mock proving passed");
    }

    // Run proof phase
    let transcript = Transcript::new(b"riscv");

    let start = std::time::Instant::now();
    let zkvm_proof = prover
        .create_proof(zkvm_witness, pi, transcript)
        .expect("create_proof failed");
    tracing::debug!("proof created in {:?}", start.elapsed());
    tracing::info!("e2e proof stat: {}", zkvm_proof);

    let verifier = ZKVMVerifier::new(vk.clone());

    if let Checkpoint::PrepVerify = checkpoint {
        return E2ECheckpointResult {
            proof: Some(zkvm_proof.clone()),
            vk: Some(vk),
            next_step: Some(Box::new(move || {
                run_e2e_verify(&verifier, zkvm_proof, exit_code, max_steps)
            })),
        };
    }

    let start = std::time::Instant::now();
    run_e2e_verify(&verifier, zkvm_proof.clone(), exit_code, max_steps);
    tracing::debug!("verified in {:?}", start.elapsed());

    E2ECheckpointResult {
        proof: Some(zkvm_proof),
        vk: Some(vk),
        next_step: None,
    }
}

// Runs program emulation + witness generation + proving
#[allow(clippy::too_many_arguments)]
pub fn run_e2e_proof<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + 'static,
>(
    ctx: &E2EProgramCtx<E>,
    init_full_mem: &InitMemState,
    pk: ZKVMProvingKey<E, PCS>,
    max_steps: usize,
    is_mock_proving: bool,
) -> ZKVMProof<E, PCS> {
    // Emulate program
    let emul_result = emulate_program(ctx.program.clone(), max_steps, init_full_mem, &ctx.platform);

    // clone pi before consuming
    let pi = emul_result.pi.clone();

    // Generate witness
    let zkvm_witness = generate_witness(
        &ctx.system_config,
        emul_result,
        &ctx.program,
        is_mock_proving,
    );

    // proving
    let backend: CpuBackend<E, PCS> = CpuBackend::new();
    let device = CpuProver::new(backend);
    let mut prover = ZKVMProver::new(pk, device);

    if is_mock_proving {
        MockProver::assert_satisfied_full(
            &ctx.system_config.zkvm_cs,
            ctx.zkvm_fixed_traces.clone(),
            &zkvm_witness,
            &pi,
            &ctx.program,
        );
        tracing::info!("Mock proving passed");
    }

    let transcript = Transcript::new(b"riscv");
    prover
        .create_proof(zkvm_witness, pi, transcript)
        .expect("create_proof failed")
}

pub fn run_e2e_verify<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    verifier: &ZKVMVerifier<E, PCS>,
    zkvm_proof: ZKVMProof<E, PCS>,
    exit_code: Option<u32>,
    max_steps: usize,
) {
    let transcript = Transcript::new(b"riscv");
    assert!(
        verifier
            .verify_proof_halt(zkvm_proof, transcript, exit_code.is_some())
            .expect("verify proof return with error"),
    );
    match exit_code {
        Some(0) => tracing::info!("exit code 0. Success."),
        Some(code) => tracing::error!("exit code {}. Failure.", code),
        None => tracing::error!("Unfinished execution. max_steps={:?}.", max_steps),
    }
}

fn debug_memory_ranges<'a, I: Iterator<Item = &'a MemFinalRecord>>(vm: &VMState, mem_final: I) {
    let accessed_addrs = vm
        .tracer()
        .final_accesses()
        .iter()
        .filter(|(_, &cycle)| (cycle != 0))
        .map(|(&addr, _)| addr.baddr())
        .filter(|addr| vm.platform().can_read(addr.0))
        .collect_vec();

    let handled_addrs = mem_final
        .filter(|rec| rec.cycle != 0)
        .map(|rec| ByteAddr(rec.addr))
        .collect::<HashSet<_>>();

    tracing::trace!(
        "Memory range (accessed): {:?}",
        format_segments(vm.platform(), accessed_addrs.iter().copied())
    );
    tracing::trace!(
        "Memory range (handled):  {:?}",
        format_segments(vm.platform(), handled_addrs.iter().copied())
    );

    for addr in &accessed_addrs {
        assert!(handled_addrs.contains(addr), "unhandled addr: {:?}", addr);
    }
}

fn format_segments(
    platform: &Platform,
    addrs: impl Iterator<Item = ByteAddr>,
) -> HashMap<String, MinMaxResult<ByteAddr>> {
    addrs
        .into_grouping_map_by(|addr| format_segment(platform, addr.0))
        .minmax()
}

fn format_segment(platform: &Platform, addr: u32) -> String {
    format!(
        "{}{}",
        if platform.can_read(addr) { "R" } else { "-" },
        if platform.can_write(addr) { "W" } else { "-" },
    )
}

pub fn verify<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + serde::Serialize>(
    zkvm_proof: &ZKVMProof<E, PCS>,
    verifier: &ZKVMVerifier<E, PCS>,
) -> Result<(), ZKVMError> {
    #[cfg(debug_assertions)]
    {
        Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::clear_metrics();
    }
    let transcript = Transcript::new(b"riscv");
    verifier.verify_proof_halt(
        zkvm_proof.clone(),
        transcript,
        zkvm_proof.has_halt(&verifier.vk),
    )?;
    // print verification statistics such as hash count
    #[cfg(debug_assertions)]
    {
        tracing::debug!(
            "instrumented metrics\n{}",
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::format_metrics(
            )
        );
    }
    Ok(())
}
