//! Direct proof and verifier E2E for one 4096-word resident Llama-shaped layer.

use std::sync::Arc;

use ceno_zkvm::{
    e2e::{
        KECCAK_EMPTY_WORDS, MultiProver, Preset, prepare_fulltracer_aot_program,
        prepare_preflight_aot_program, run_e2e_full_trace_verify, run_e2e_proof, setup_platform,
        setup_program,
    },
    scheme::{
        create_backend, create_prover, hal::ProverDevice, prover::ZKVMProver,
        verifier::ZKVMVerifier,
    },
};
use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use mpcs::BasefoldDefault;

type E = BabyBearExt4;
type Pcs = BasefoldDefault<E>;

fn main() {
    rayon::ThreadPoolBuilder::new()
        .stack_size(256 * 1024 * 1024)
        .build()
        .expect("construct resident E2E Rayon pool")
        .install(run);
}

fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let program = ceno_emul::Program::load_elf(ceno_examples::tensor_bus_handle_7b_v1, u32::MAX)
        .expect("load default-width resident TensorBus guest");
    let platform = setup_platform(Preset::Ceno, &program, 256 * 1024, 2 * 1024 * 1024);
    let mut ctx = setup_program::<E>(program, platform, MultiProver::default());
    let init_mem = ctx.setup_init_mem(&[]);
    let raw_step_cell_extractor = Arc::clone(&ctx.system_config.config);
    let step_cell_extractor: Arc<dyn ceno_emul::StepCellExtractor> = raw_step_cell_extractor;
    let preflight_aot = prepare_preflight_aot_program(
        Arc::clone(&ctx.program),
        &ctx.platform,
        &ctx.multi_prover,
        step_cell_extractor,
        &init_mem,
    );
    ctx.fulltracer_aot_program = Some(prepare_fulltracer_aot_program(preflight_aot.as_ref()));
    ctx.preflight_aot_program = Some(preflight_aot);

    let (max_num_variables, security_level) = default_backend_config();
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
    let device = create_prover(backend);
    let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
    let prover = ZKVMProver::new(pk.into(), device);
    let init_mem = prover.setup_init_mem(&[]);
    let proofs = run_e2e_proof(&prover, &init_mem, KECCAK_EMPTY_WORDS, 1 << 20, false, None);
    assert_eq!(
        proofs.len(),
        1,
        "one atomic resident segment must use one shard"
    );
    let names = [
        "TensorBusCircuit",
        "TensorBusTENSOR_IMPORT_BEGIN_V1Ecall",
        "TensorBusTENSOR_HANDLE_ATTENTION_V1Ecall",
        "TensorBusTENSOR_HANDLE_FFN_V1Ecall",
        "TensorBusTENSOR_EXPORT_END_V1Ecall",
    ];
    for name in names {
        let index = vk
            .circuit_index_to_name
            .iter()
            .find_map(|(index, candidate)| (candidate == name).then_some(*index))
            .unwrap_or_else(|| panic!("default registry is missing {name}"));
        assert!(
            proofs[0].chip_proofs.contains_key(&index),
            "resident segment did not prove {name}"
        );
    }
    run_e2e_full_trace_verify(&ZKVMVerifier::new(vk), proofs, Some(0), 1 << 20);
    println!("default-width resident TensorBus E2E verified: words=4096");
}
