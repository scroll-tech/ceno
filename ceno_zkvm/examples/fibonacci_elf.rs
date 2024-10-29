use ceno_emul::{
    ByteAddr, CENO_PLATFORM, EmuContext, InsnKind::EANY, Platform, StepRecord, Tracer, VMState,
    WordAddr,
};
use ceno_zkvm::{
    instructions::riscv::{Rv32imConfig, constants::EXIT_PC},
    scheme::{
        PublicValues, constants::MAX_NUM_VARIABLES, prover::ZKVMProver, verifier::ZKVMVerifier,
    },
    state::GlobalState,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{MemFinalRecord, ProgramTableCircuit, initial_memory, initial_registers},
};
use ff_ext::ff::Field;
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use rand_chacha::ChaCha8Rng;
use std::{panic, time::Instant};
use tracing_flame::FlameLayer;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};
use transcript::Transcript;

fn main() {
    type E = GoldilocksExt2;
    type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams, ChaCha8Rng>;
    const PROGRAM_SIZE: usize = 1 << 14;
    type ExampleProgramTableCircuit<E> = ProgramTableCircuit<E, PROGRAM_SIZE>;

    // set up logger
    let (flame_layer, _guard) = FlameLayer::with_file("./tracing.folded").unwrap();
    let subscriber = Registry::default()
        .with(
            fmt::layer()
                .compact()
                .with_thread_ids(false)
                .with_thread_names(false),
        )
        .with(EnvFilter::from_default_env())
        .with(flame_layer.with_threads_collapsed(true));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let sp1_platform = Platform {
        rom_start: 0x0020_0800,
        rom_end: 0x003f_ffff,
        ram_start: 0x0020_0000,
        ram_end: 0xffff_ffff,
    };
    let elf_bytes = include_bytes!(r"fibonacci.elf");
    let mut vm = VMState::new_from_elf(sp1_platform, elf_bytes).unwrap();

    // keygen
    let pcs_param = Pcs::setup(1 << MAX_NUM_VARIABLES).expect("Basefold PCS setup");
    let (pp, vp) = Pcs::trim(&pcs_param, 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let mut zkvm_cs = ZKVMConstraintSystem::default();

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ExampleProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();

    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();

    zkvm_fixed_traces.register_table_circuit::<ExampleProgramTableCircuit<E>>(
        &zkvm_cs,
        prog_config.clone(),
        vm.program(),
    );

    let reg_init = initial_registers();
    let mem_init = initial_memory(&[]);

    config.generate_fixed_traces(&zkvm_cs, &mut zkvm_fixed_traces, &reg_init, &mem_init);

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp.clone(), vp.clone(), zkvm_fixed_traces)
        .expect("keygen failed");
    let vk = pk.get_vk();

    // proving
    let prover = ZKVMProver::new(pk);
    let verifier = ZKVMVerifier::new(vk);

    let all_records = vm
        .iter_until_halt()
        .collect::<Result<Vec<StepRecord>, _>>()
        .expect("vm exec failed");

    let halt_record = all_records
        .iter()
        .rev()
        .find(|record| {
            record.insn().codes().kind == EANY
                && record.rs1().unwrap().value == CENO_PLATFORM.ecall_halt()
        })
        .expect("halt record not found");

    let final_access = vm.tracer().final_accesses();

    let end_cycle: u32 = vm.tracer().cycle().try_into().unwrap();
    let exit_code = halt_record.rs2().unwrap().value;
    let pi = PublicValues::new(
        exit_code,
        vm.program().entry,
        Tracer::SUBCYCLES_PER_INSN as u32,
        EXIT_PC as u32,
        end_cycle,
    );

    let mut zkvm_witness = ZKVMWitnesses::default();
    // assign opcode circuits
    config
        .assign_opcode_circuit(&zkvm_cs, &mut zkvm_witness, all_records)
        .unwrap();
    zkvm_witness.finalize_lk_multiplicities();

    // Find the final register values and cycles.
    let reg_final = reg_init
        .iter()
        .map(|rec| {
            let index = rec.addr as usize;
            let vma: WordAddr = sp1_platform.register_vma(index).into();
            MemFinalRecord {
                value: vm.peek_register(index),
                cycle: *final_access.get(&vma).unwrap_or(&0),
            }
        })
        .collect_vec();

    // Find the final memory values and cycles.
    let mem_final = vm
        .tracer()
        .final_accesses()
        .iter()
        .filter_map(|(&addr, &cycle)| {
            if addr >= ByteAddr::from(sp1_platform.ram_start()).waddr() {
                Some(MemFinalRecord {
                    value: vm.peek_memory(addr),
                    cycle,
                })
            } else {
                None
            }
        })
        .collect_vec();

    // assign table circuits
    config
        .assign_table_circuit(&zkvm_cs, &mut zkvm_witness, &reg_final, &mem_final)
        .unwrap();
    // assign program circuit
    zkvm_witness
        .assign_table_circuit::<ExampleProgramTableCircuit<E>>(
            &zkvm_cs,
            &prog_config,
            vm.program(),
        )
        .unwrap();

    let timer = Instant::now();

    let transcript = Transcript::new(b"riscv");
    let mut zkvm_proof = prover
        .create_proof(zkvm_witness, pi, transcript)
        .expect("create_proof failed");

    println!(
        "riscv_opcodes::create_proof, time = {}",
        timer.elapsed().as_secs_f64()
    );

    let transcript = Transcript::new(b"riscv");
    assert!(
        verifier
            .verify_proof(zkvm_proof.clone(), transcript)
            .expect("verify proof return with error"),
    );

    let transcript = Transcript::new(b"riscv");
    // change public input maliciously should cause verifier to reject proof
    zkvm_proof.pv[0] = <GoldilocksExt2 as ff_ext::ExtensionField>::BaseField::ONE;
    zkvm_proof.pv[1] = <GoldilocksExt2 as ff_ext::ExtensionField>::BaseField::ONE;

    // capture panic message, if have
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|_info| {
        // by default it will print msg to stdout/stderr
        // we override it to avoid print msg since we will capture the msg by our own
    }));
    let result = panic::catch_unwind(|| verifier.verify_proof(zkvm_proof, transcript));
    panic::set_hook(default_hook);
    match result {
        Ok(res) => {
            res.expect_err("verify proof should return with error");
        }
        Err(err) => {
            let msg: String = if let Some(message) = err.downcast_ref::<&str>() {
                message.to_string()
            } else if let Some(message) = err.downcast_ref::<String>() {
                message.to_string()
            } else if let Some(message) = err.downcast_ref::<&String>() {
                message.to_string()
            } else {
                unreachable!()
            };

            if !msg.starts_with("0th round's prover message is not consistent with the claim") {
                println!("unknown panic {msg:?}");
                panic::resume_unwind(err);
            };
        }
    };
}
