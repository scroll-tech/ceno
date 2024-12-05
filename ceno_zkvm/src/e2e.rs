use crate::{
    instructions::riscv::{DummyExtraConfig, MemPadder, MmuConfig, Rv32imConfig},
    scheme::{
        PublicValues, ZKVMProof, constants::MAX_NUM_VARIABLES, mock_prover::MockProver,
        prover::ZKVMProver, verifier::ZKVMVerifier,
    },
    state::GlobalState,
    structs::{ProgramParams, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{MemFinalRecord, MemInitRecord, ProgramTableCircuit},
};
use ceno_emul::{
    ByteAddr, EmuContext, InsnKind::EANY, IterAddresses, Platform, Program, StepRecord, Tracer,
    VMState, WORD_SIZE, WordAddr,
};
use ff_ext::ExtensionField;
use itertools::{Itertools, MinMaxResult, chain, enumerate};
use mpcs::PolynomialCommitmentScheme;
use std::{
    collections::{HashMap, HashSet},
    iter::zip,
    time::Instant,
};
use transcript::Transcript;

type E2EWitnessGen<E, PCS> = (
    ZKVMProver<E, PCS>,
    ZKVMVerifier<E, PCS>,
    ZKVMWitnesses<E>,
    PublicValues<u32>,
    usize,   // number of cycles
    Instant, // e2e start, excluding key gen time
    Option<u32>,
);

pub fn run_e2e_gen_witness<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    program: Program,
    platform: Platform,
    stack_size: u32,
    heap_size: u32,
    hints: Vec<u32>,
    max_steps: usize,
) -> E2EWitnessGen<E, PCS> {
    let stack_addrs = platform.stack_top - stack_size..platform.stack_top;

    // Detect heap as starting after program data.
    let heap_start = program.image.keys().max().unwrap() + WORD_SIZE as u32;
    let heap_addrs = heap_start..heap_start + heap_size;

    let mut mem_padder = MemPadder::new(heap_addrs.end..platform.ram.end);

    let mem_init = {
        let program_addrs = program.image.iter().map(|(addr, value)| MemInitRecord {
            addr: *addr,
            value: *value,
        });

        let stack = stack_addrs
            .iter_addresses()
            .map(|addr| MemInitRecord { addr, value: 0 });

        let heap = heap_addrs
            .iter_addresses()
            .map(|addr| MemInitRecord { addr, value: 0 });

        let mem_init = chain!(program_addrs, stack, heap).collect_vec();

        mem_padder.padded_sorted(mem_init.len().next_power_of_two(), mem_init)
    };

    let mut vm = VMState::new(platform.clone(), program);

    for (addr, value) in zip(platform.hints.iter_addresses(), &hints) {
        vm.init_memory(addr.into(), *value);
    }

    // keygen
    let pcs_param = PCS::setup(1 << MAX_NUM_VARIABLES).expect("Basefold PCS setup");
    let (pp, vp) = PCS::trim(pcs_param, 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let program_params = ProgramParams {
        platform: platform.clone(),
        program_size: vm.program().instructions.len(),
        static_memory_len: mem_init.len(),
        ..ProgramParams::default()
    };
    let mut zkvm_cs = ZKVMConstraintSystem::new_with_platform(program_params);

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let mmu_config = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    let dummy_config = DummyExtraConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();

    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();

    zkvm_fixed_traces.register_table_circuit::<ProgramTableCircuit<E>>(
        &zkvm_cs,
        &prog_config,
        vm.program(),
    );

    // IO is not used in this program, but it must have a particular size at the moment.
    let io_init = mem_padder.padded_sorted(mmu_config.public_io_len(), vec![]);

    let reg_init = mmu_config.initial_registers();
    config.generate_fixed_traces(&zkvm_cs, &mut zkvm_fixed_traces);
    mmu_config.generate_fixed_traces(
        &zkvm_cs,
        &mut zkvm_fixed_traces,
        &reg_init,
        &mem_init,
        &io_init.iter().map(|rec| rec.addr).collect_vec(),
    );
    dummy_config.generate_fixed_traces(&zkvm_cs, &mut zkvm_fixed_traces);

    let pk = zkvm_cs
        .clone()
        .key_gen::<PCS>(pp.clone(), vp.clone(), zkvm_fixed_traces.clone())
        .expect("keygen failed");
    let vk = pk.get_vk();

    // proving
    let e2e_start = Instant::now();
    let prover = ZKVMProver::new(pk);
    let verifier = ZKVMVerifier::new(vk);

    let all_records = vm
        .iter_until_halt()
        .take(max_steps)
        .collect::<Result<Vec<StepRecord>, _>>()
        .expect("vm exec failed");

    let cycle_num = all_records.len();
    tracing::info!("Proving {} execution steps", cycle_num);
    for (i, step) in enumerate(&all_records).rev().take(5).rev() {
        tracing::trace!("Step {i}: {:?} - {:?}\n", step.insn().codes().kind, step);
    }

    // Find the exit code from the HALT step, if halting at all.
    let exit_code = all_records
        .iter()
        .rev()
        .find(|record| {
            record.insn().codes().kind == EANY
                && record.rs1().unwrap().value == Platform::ecall_halt()
        })
        .and_then(|halt_record| halt_record.rs2())
        .map(|rs2| rs2.value);

    let final_access = vm.tracer().final_accesses();
    let end_cycle: u32 = vm.tracer().cycle().try_into().unwrap();

    let pi = PublicValues::new(
        exit_code.unwrap_or(0),
        vm.program().entry,
        Tracer::SUBCYCLES_PER_INSN as u32,
        vm.get_pc().into(),
        end_cycle,
        io_init.iter().map(|rec| rec.value).collect_vec(),
    );

    let mut zkvm_witness = ZKVMWitnesses::default();
    // assign opcode circuits
    let dummy_records = config
        .assign_opcode_circuit(&zkvm_cs, &mut zkvm_witness, all_records)
        .unwrap();
    dummy_config
        .assign_opcode_circuit(&zkvm_cs, &mut zkvm_witness, dummy_records)
        .unwrap();
    zkvm_witness.finalize_lk_multiplicities();

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
    debug_memory_ranges(&vm, &mem_final);

    // Find the final public IO cycles.
    let io_final = io_init
        .iter()
        .map(|rec| *final_access.get(&rec.addr.into()).unwrap_or(&0))
        .collect_vec();

    let priv_io_final = zip(platform.hints.iter_addresses(), &hints)
        .map(|(addr, &value)| MemFinalRecord {
            addr,
            value,
            cycle: *final_access.get(&addr.into()).unwrap_or(&0),
        })
        .collect_vec();

    // assign table circuits
    config
        .assign_table_circuit(&zkvm_cs, &mut zkvm_witness)
        .unwrap();
    mmu_config
        .assign_table_circuit(
            &zkvm_cs,
            &mut zkvm_witness,
            &reg_final,
            &mem_final,
            &io_final,
            &priv_io_final,
        )
        .unwrap();
    // assign program circuit
    zkvm_witness
        .assign_table_circuit::<ProgramTableCircuit<E>>(&zkvm_cs, &prog_config, vm.program())
        .unwrap();

    if std::env::var("MOCK_PROVING").is_ok() {
        MockProver::assert_satisfied_full(zkvm_cs, zkvm_fixed_traces, &zkvm_witness, &pi);
        tracing::info!("Mock proving passed");
    }
    (
        prover,
        verifier,
        zkvm_witness,
        pi,
        cycle_num,
        e2e_start,
        exit_code,
    )
}

pub fn run_e2e_proof<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    prover: ZKVMProver<E, PCS>,
    zkvm_witness: ZKVMWitnesses<E>,
    pi: PublicValues<u32>,
) -> ZKVMProof<E, PCS> {
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

fn debug_memory_ranges(vm: &VMState, mem_final: &[MemFinalRecord]) {
    let accessed_addrs = vm
        .tracer()
        .final_accesses()
        .iter()
        .filter(|(_, &cycle)| (cycle != 0))
        .map(|(&addr, _)| addr.baddr())
        .filter(|addr| vm.platform().can_read(addr.0))
        .collect_vec();

    let handled_addrs = mem_final
        .iter()
        .filter(|rec| rec.cycle != 0)
        .map(|rec| ByteAddr(rec.addr))
        .collect::<HashSet<_>>();

    tracing::debug!(
        "Memory range (accessed): {:?}",
        format_segments(vm.platform(), accessed_addrs.iter().copied())
    );
    tracing::debug!(
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
        "{}{}{}",
        if platform.can_read(addr) { "R" } else { "-" },
        if platform.can_write(addr) { "W" } else { "-" },
        if platform.can_execute(addr) { "X" } else { "-" },
    )
}
