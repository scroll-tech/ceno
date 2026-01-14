use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{arith::AddInstruction, ecall::HaltInstruction},
    },
    scheme::{
        constants::DYNAMIC_RANGE_MAX_BITS,
        cpu::CpuTowerProver,
        create_backend, create_prover,
        hal::{ProofInput, TowerProverSpec},
    },
    structs::{ProgramParams, RAMType, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::ProgramTableCircuit,
    witness::{LkMultiplicity, set_val},
};
use ceno_emul::{
    CENO_PLATFORM,
    InsnKind::{ADD, ECALL},
    Platform, Program, StepRecord, VMState, encode_rv32,
};
use ff_ext::{ExtensionField, FieldInto, FromUniformBytes, GoldilocksExt2};
use gkr_iop::cpu::default_backend_config;
#[cfg(feature = "gpu")]
use gkr_iop::gpu::{MultilinearExtensionGpu, gpu_prover::*};
use multilinear_extensions::{ToExpr, WitIn, mle::MultilinearExtension};
use std::marker::PhantomData;
#[cfg(feature = "gpu")]
use std::sync::Arc;

#[cfg(debug_assertions)]
use ff_ext::{Instrumented, PoseidonField};

use super::{
    PublicValues,
    constants::MAX_NUM_VARIABLES,
    prover::ZKVMProver,
    utils::infer_tower_product_witness,
    verifier::{TowerVerify, ZKVMVerifier},
};
use crate::{
    e2e::ShardContext, scheme::constants::NUM_FANIN, structs::PointAndEval,
    tables::DynamicRangeTableCircuit,
};
use itertools::Itertools;
use mpcs::{
    PolynomialCommitmentScheme, SecurityLevel, SecurityLevel::Conjecture100bits, WhirDefault,
};
use multilinear_extensions::{mle::IntoMLE, util::ceil_log2};
use p3::field::FieldAlgebra;
use rand::thread_rng;
use transcript::{BasicTranscript, Transcript};

struct TestConfig {
    pub(crate) reg_id: WitIn,
}

struct TestCircuit<E: ExtensionField, const RW: usize, const L: usize> {
    phantom: PhantomData<E>,
}

impl<E: ExtensionField, const L: usize, const RW: usize> Instruction<E> for TestCircuit<E, RW, L> {
    type InstructionConfig = TestConfig;

    fn name() -> String {
        "TEST".into()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let reg_id = cb.create_witin(|| "reg_id");
        (0..RW).try_for_each(|_| {
            let record = vec![1.into(), reg_id.expr()];
            cb.read_record(|| "read", RAMType::Register, record.clone())?;
            cb.write_record(|| "write", RAMType::Register, record)?;
            Result::<(), ZKVMError>::Ok(())
        })?;
        (0..L).try_for_each(|_| {
            cb.assert_ux::<_, _, 16>(|| "regid_in_range", reg_id.expr())?;
            Result::<(), ZKVMError>::Ok(())
        })?;
        assert_eq!(cb.cs.lk_expressions.len(), L);
        assert_eq!(cb.cs.r_expressions.len(), RW);
        assert_eq!(cb.cs.w_expressions.len(), RW);

        Ok(TestConfig { reg_id })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        _shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, config.reg_id, E::BaseField::ONE);

        Ok(())
    }
}

#[test]
fn test_rw_lk_expression_combination() {
    type E = GoldilocksExt2;
    type Pcs = WhirDefault<E>;

    fn test_rw_lk_expression_combination_inner<
        const L: usize,
        const RW: usize,
        E: ExtensionField,
        Pcs: PolynomialCommitmentScheme<E> + 'static,
    >() {
        // configure
        let (max_num_variables, security_level) = (8, Conjecture100bits);
        let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
        let device = create_prover(backend.clone());
        let name = TestCircuit::<E, RW, L>::name();
        let mut zkvm_cs = ZKVMConstraintSystem::default();
        let config = zkvm_cs.register_opcode_circuit::<TestCircuit<E, RW, L>>();
        let mut shard_ctx = ShardContext::default();

        // generate fixed traces
        let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
        zkvm_fixed_traces.register_opcode_circuit::<TestCircuit<E, RW, L>>(&zkvm_cs, &config);

        // keygen
        let pk = zkvm_cs
            .clone()
            .key_gen::<Pcs>(
                device.backend.pp.clone(),
                device.backend.vp.clone(),
                0,
                zkvm_fixed_traces,
            )
            .unwrap();
        let vk = pk.get_vk_slow();

        // generate mock witness
        let num_instances = 1 << 8;
        let mut zkvm_witness = ZKVMWitnesses::default();
        zkvm_witness
            .assign_opcode_circuit::<TestCircuit<E, RW, L>>(
                &zkvm_cs,
                &mut shard_ctx,
                &config,
                vec![&StepRecord::default(); num_instances],
            )
            .unwrap();

        // get proof
        let prover = ZKVMProver::new_with_single_shard(pk, device);
        let mut transcript = BasicTranscript::new(b"test");
        let mut rmm: Vec<_> = zkvm_witness
            .into_iter_sorted()
            .next()
            .unwrap()
            .witness_rmms
            .into();
        let (rmm, structural_rmm) = (rmm.remove(0), rmm.remove(0));
        let wits_in = rmm.to_mles();
        let structural_wits_in = structural_rmm.to_mles();
        // commit to main traces
        let commit_with_witness =
            Pcs::batch_commit_and_write(&prover.pk.pp, vec![rmm], &mut transcript).unwrap();
        let witin_commit = Pcs::get_pure_commitment(&commit_with_witness);

        // TODO: better way to handle this
        #[cfg(not(feature = "gpu"))]
        let (wits_in, structural_in) = {
            (
                wits_in.into_iter().map(|v| v.into()).collect_vec(),
                structural_wits_in
                    .into_iter()
                    .map(|v| v.into())
                    .collect_vec(),
            )
        };

        #[cfg(feature = "gpu")]
        let (wits_in, structural_in) = {
            let cuda_hal = get_cuda_hal().unwrap();
            (
                wits_in
                    .iter()
                    .map(|v| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, v)))
                    .collect_vec(),
                structural_in = structural_wits_in
                    .iter()
                    .map(|v| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, v)))
                    .collect_vec(),
            )
        };

        let prover_challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];

        let input = ProofInput {
            fixed: vec![],
            witness: wits_in,
            structural_witness: structural_in,
            public_input: vec![],
            pub_io_evals: vec![],
            num_instances: vec![num_instances],
            has_ecc_ops: false,
        };
        let (proof, _, _) = prover
            .create_chip_proof(
                name.as_str(),
                prover.pk.circuit_pks.get(&name).unwrap(),
                input,
                &mut transcript,
                &prover_challenges,
            )
            .expect("create_proof failed");

        // verify proof
        let verifier = ZKVMVerifier::new(vk.clone());
        let mut v_transcript = BasicTranscript::new(b"test");
        // write commitment into transcript and derive challenges from it
        Pcs::write_commitment(&witin_commit, &mut v_transcript).unwrap();
        let verifier_challenges = [
            v_transcript.read_challenge().elements,
            v_transcript.read_challenge().elements,
        ];

        assert_eq!(prover_challenges, verifier_challenges);
        #[cfg(debug_assertions)]
        {
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::clear_metrics();
        }
        verifier
            .verify_chip_proof(
                name.as_str(),
                verifier.vk.circuit_vks.get(&name).unwrap(),
                &proof,
                &[],
                &[],
                &mut v_transcript,
                NUM_FANIN,
                &PointAndEval::default(),
                &verifier_challenges,
            )
            .expect("verifier failed");
        #[cfg(debug_assertions)]
        {
            println!(
            "instrumented metrics {}",
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::format_metrics(
            )
        );
        }
    }

    // <lookup count, rw count>
    test_rw_lk_expression_combination_inner::<19, 17, E, Pcs>();
    test_rw_lk_expression_combination_inner::<61, 17, E, Pcs>();
    test_rw_lk_expression_combination_inner::<17, 61, E, Pcs>();
}

const PROGRAM_CODE: [ceno_emul::Instruction; 4] = [
    encode_rv32(ADD, 4, 1, 4, 0),
    encode_rv32(ECALL, 0, 0, 0, 0),
    encode_rv32(ECALL, 0, 0, 0, 0),
    encode_rv32(ECALL, 0, 0, 0, 0),
];

#[ignore = "this case is already tested in riscv_example as ecall_halt has only one instance"]
#[test]
fn test_single_add_instance_e2e() {
    type E = GoldilocksExt2;
    type Pcs = WhirDefault<E>;

    // set up program
    let program = Program::new(
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.heap.start,
        PROGRAM_CODE.to_vec(),
        Default::default(),
    );

    Pcs::setup(1 << MAX_NUM_VARIABLES, SecurityLevel::default()).expect("Basefold PCS setup");
    let (pp, vp) = Pcs::trim((), 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let mut zkvm_cs = ZKVMConstraintSystem::default();
    let mut shard_ctx = ShardContext::default();
    // opcode circuits
    let add_config = zkvm_cs.register_opcode_circuit::<AddInstruction<E>>();
    let halt_config = zkvm_cs.register_opcode_circuit::<HaltInstruction<E>>();
    let dynamic_range_config =
        zkvm_cs.register_table_circuit::<DynamicRangeTableCircuit<E, DYNAMIC_RANGE_MAX_BITS>>();

    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E>>();

    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
    zkvm_fixed_traces.register_opcode_circuit::<AddInstruction<E>>(&zkvm_cs, &add_config);
    zkvm_fixed_traces.register_opcode_circuit::<HaltInstruction<E>>(&zkvm_cs, &halt_config);

    zkvm_fixed_traces
        .register_table_circuit::<DynamicRangeTableCircuit<E, DYNAMIC_RANGE_MAX_BITS>>(
            &zkvm_cs,
            &dynamic_range_config,
            &(),
        );

    zkvm_fixed_traces.register_table_circuit::<ProgramTableCircuit<E>>(
        &zkvm_cs,
        &prog_config,
        &program,
    );

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp, vp, program.entry, zkvm_fixed_traces)
        .expect("keygen failed");
    let vk = pk.get_vk_slow();

    // single instance
    let mut vm = VMState::new(CENO_PLATFORM.clone(), program.clone().into());
    let all_records = vm
        .iter_until_halt()
        .collect::<Result<Vec<StepRecord>, _>>()
        .expect("vm exec failed")
        .into_iter()
        .collect::<Vec<_>>();
    let mut add_records = vec![];
    let mut halt_records = vec![];
    all_records.iter().for_each(|record| {
        let kind = record.insn().kind;
        match kind {
            ADD => add_records.push(record),
            ECALL => {
                if record.rs1().unwrap().value == Platform::ecall_halt() {
                    halt_records.push(record);
                }
            }
            _ => {}
        }
    });
    assert_eq!(add_records.len(), 1);
    assert_eq!(halt_records.len(), 1);

    // proving
    let (max_num_variables, security_level) = default_backend_config();
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
    let device = create_prover(backend);
    let prover = ZKVMProver::new_with_single_shard(pk, device);
    let verifier = ZKVMVerifier::new(vk);
    let mut zkvm_witness = ZKVMWitnesses::default();
    // assign opcode circuits
    zkvm_witness
        .assign_opcode_circuit::<AddInstruction<E>>(
            &zkvm_cs,
            &mut shard_ctx,
            &add_config,
            add_records,
        )
        .unwrap();
    zkvm_witness
        .assign_opcode_circuit::<HaltInstruction<E>>(
            &zkvm_cs,
            &mut shard_ctx,
            &halt_config,
            halt_records,
        )
        .unwrap();
    zkvm_witness.finalize_lk_multiplicities();
    zkvm_witness
        .assign_table_circuit::<DynamicRangeTableCircuit<E, DYNAMIC_RANGE_MAX_BITS>>(
            &zkvm_cs,
            &dynamic_range_config,
            &(),
        )
        .unwrap();
    zkvm_witness
        .assign_table_circuit::<ProgramTableCircuit<E>>(&zkvm_cs, &prog_config, &program)
        .unwrap();

    let pi = PublicValues::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, vec![0], vec![0; 14]);
    let transcript = BasicTranscript::new(b"riscv");
    let zkvm_proof = prover
        .create_proof(&shard_ctx, zkvm_witness, pi, transcript)
        .expect("create_proof failed");

    println!("encoded zkvm proof {}", &zkvm_proof,);

    #[cfg(debug_assertions)]
    {
        Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::clear_metrics();
    }
    let transcript = BasicTranscript::new(b"riscv");
    assert!(
        verifier
            .verify_proof(zkvm_proof, transcript)
            .expect("verify proof return with error"),
    );
    #[cfg(debug_assertions)]
    {
        println!(
            "instrumented metrics {}",
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::format_metrics(
            )
        );
    }
}

/// test various product argument size, starting from minimal leaf size 2
#[test]
fn test_tower_proof_various_prod_size() {
    fn _test_tower_proof_prod_size_2(leaf_layer_size: usize) {
        let num_vars = ceil_log2(leaf_layer_size);
        let mut rng = thread_rng();
        type E = GoldilocksExt2;
        let mut transcript = BasicTranscript::new(b"test_tower_proof");
        let leaf_layer: MultilinearExtension<E> = (0..leaf_layer_size)
            .map(|_| E::random(&mut rng))
            .collect_vec()
            .into_mle();
        let (first, second): (&[E], &[E]) = leaf_layer
            .get_ext_field_vec()
            .split_at(leaf_layer.evaluations().len() / 2);
        let last_layer_splitted_fanin: Vec<MultilinearExtension<E>> =
            vec![first.to_vec().into_mle(), second.to_vec().into_mle()];
        let layers = infer_tower_product_witness(num_vars, last_layer_splitted_fanin, 2);
        let (rt_tower_p, tower_proof) = CpuTowerProver::create_proof::<E, WhirDefault<E>>(
            vec![TowerProverSpec {
                witness: layers.clone(),
            }],
            vec![],
            2,
            &mut transcript,
        );

        let mut transcript = BasicTranscript::new(b"test_tower_proof");
        let (rt_tower_v, prod_point_and_eval, _, _) = TowerVerify::verify(
            vec![
                layers[0]
                    .iter()
                    .flat_map(|mle| mle.get_ext_field_vec().to_vec())
                    .collect_vec(),
            ],
            vec![],
            &tower_proof,
            vec![num_vars],
            2,
            &mut transcript,
        )
        .unwrap();

        assert_eq!(rt_tower_p, rt_tower_v);
        assert_eq!(rt_tower_v.len(), num_vars);
        assert_eq!(prod_point_and_eval.len(), 1);
        assert_eq!(
            leaf_layer.evaluate(&rt_tower_v),
            prod_point_and_eval[0].eval
        );
    }

    for leaf_layer_size in 1..10 {
        _test_tower_proof_prod_size_2(1 << leaf_layer_size);
    }
}
