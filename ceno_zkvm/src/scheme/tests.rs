use std::{marker::PhantomData, mem::MaybeUninit};

use ark_std::test_rng;
use ceno_emul::{
    CENO_PLATFORM,
    InsnKind::{ADD, EANY},
    PC_WORD_SIZE, Platform, Program, StepRecord, VMState,
};
use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use mpcs::{Basefold, BasefoldDefault, BasefoldRSParams, PolynomialCommitmentScheme};
use multilinear_extensions::{
    mle::IntoMLE, util::ceil_log2, virtual_poly_v2::ArcMultilinearExtension,
};
use transcript::{BasicTranscript, Transcript};

use crate::{
    circuit_builder::CircuitBuilder,
    declare_program,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        Instruction,
        riscv::{arith::AddInstruction, ecall::HaltInstruction},
    },
    set_val,
    structs::{
        PointAndEval, RAMType::Register, TowerProver, TowerProverSpec, ZKVMConstraintSystem,
        ZKVMFixedTraces, ZKVMWitnesses,
    },
    tables::{ProgramTableCircuit, U16TableCircuit},
    witness::LkMultiplicity,
};

use super::{
    PublicValues,
    constants::{MAX_NUM_VARIABLES, NUM_FANIN},
    prover::ZKVMProver,
    utils::infer_tower_product_witness,
    verifier::{TowerVerify, ZKVMVerifier},
};

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

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        let reg_id = cb.create_witin(|| "reg_id");
        (0..RW).try_for_each(|_| {
            let record = vec![1.into(), reg_id.expr()];
            cb.read_record(|| "read", Register, record.clone())?;
            cb.write_record(|| "write", Register, record)?;
            Result::<(), ZKVMError>::Ok(())
        })?;
        (0..L).try_for_each(|_| {
            cb.assert_ux::<_, _, 16>(|| "regid_in_range", reg_id)?;
            Result::<(), ZKVMError>::Ok(())
        })?;
        assert_eq!(cb.cs.lk_expressions.len(), L);
        assert_eq!(cb.cs.r_expressions.len(), RW);
        assert_eq!(cb.cs.w_expressions.len(), RW);

        Ok(TestConfig { reg_id })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        set_val!(instance, config.reg_id, E::BaseField::ONE);

        Ok(())
    }
}

#[test]
fn test_rw_lk_expression_combination() {
    fn test_rw_lk_expression_combination_inner<const L: usize, const RW: usize>() {
        type E = GoldilocksExt2;
        type Pcs = BasefoldDefault<E>;

        // pcs setup
        let param = Pcs::setup(1 << 13).unwrap();
        let (pp, vp) = Pcs::trim(param, 1 << 13).unwrap();

        // configure
        let name = TestCircuit::<E, RW, L>::name();
        let mut zkvm_cs = ZKVMConstraintSystem::default();
        let config = zkvm_cs.register_opcode_circuit::<TestCircuit<E, RW, L>>();

        // generate fixed traces
        let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
        zkvm_fixed_traces.register_opcode_circuit::<TestCircuit<E, RW, L>>(&zkvm_cs);

        // keygen
        let pk = zkvm_cs
            .clone()
            .key_gen::<Pcs>(pp, vp, zkvm_fixed_traces)
            .unwrap();
        let vk = pk.get_vk();

        // generate mock witness
        let num_instances = 1 << 8;
        let mut zkvm_witness = ZKVMWitnesses::default();
        zkvm_witness
            .assign_opcode_circuit::<TestCircuit<E, RW, L>>(
                &zkvm_cs,
                &config,
                vec![StepRecord::default(); num_instances],
            )
            .unwrap();

        // get proof
        let prover = ZKVMProver::new(pk);
        let mut transcript = BasicTranscript::new(b"test");
        let wits_in = zkvm_witness
            .into_iter_sorted()
            .next()
            .unwrap()
            .1
            .into_mles();
        // commit to main traces
        let commit = Pcs::batch_commit_and_write(&prover.pk.pp, &wits_in, &mut transcript).unwrap();
        let wits_in = wits_in.into_iter().map(|v| v.into()).collect_vec();
        let prover_challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];

        let proof = prover
            .create_opcode_proof(
                name.as_str(),
                &prover.pk.pp,
                prover.pk.circuit_pks.get(&name).unwrap(),
                wits_in,
                commit,
                &[],
                num_instances,
                &mut transcript,
                &prover_challenges,
            )
            .expect("create_proof failed");

        // verify proof
        let verifier = ZKVMVerifier::new(vk.clone());
        let mut v_transcript = BasicTranscript::new(b"test");
        // write commitment into transcript and derive challenges from it
        Pcs::write_commitment(&proof.wits_commit, &mut v_transcript).unwrap();
        let verifier_challenges = [
            v_transcript.read_challenge().elements,
            v_transcript.read_challenge().elements,
        ];

        assert_eq!(prover_challenges, verifier_challenges);
        let _rt_input = verifier
            .verify_opcode_proof(
                name.as_str(),
                &vk.vp,
                verifier.vk.circuit_vks.get(&name).unwrap(),
                &proof,
                &[],
                &mut v_transcript,
                NUM_FANIN,
                &PointAndEval::default(),
                &verifier_challenges,
            )
            .expect("verifier failed");
    }

    // <lookup count, rw count>
    test_rw_lk_expression_combination_inner::<19, 17>();
    test_rw_lk_expression_combination_inner::<61, 17>();
    test_rw_lk_expression_combination_inner::<17, 61>();
}

const PROGRAM_SIZE: usize = 4;
#[allow(clippy::unusual_byte_groupings)]
const ECALL_HALT: u32 = 0b_000000000000_00000_000_00000_1110011;
#[allow(clippy::unusual_byte_groupings)]
const PROGRAM_CODE: [u32; PROGRAM_SIZE] = {
    let mut program: [u32; PROGRAM_SIZE] = [ECALL_HALT; PROGRAM_SIZE];

    declare_program!(
        program,
        // func7   rs2   rs1   f3  rd    opcode
        0b_0000000_00100_00001_000_00100_0110011, // add x4, x4, x1 <=> addi x4, x4, 1
        ECALL_HALT,                               // ecall halt
        ECALL_HALT,                               // ecall halt
        ECALL_HALT,                               // ecall halt
    );
    program
};

#[ignore = "this case is already tested in riscv_example as ecall_halt has only one instance"]
#[test]
fn test_single_add_instance_e2e() {
    type E = GoldilocksExt2;
    type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;

    // set up program
    let program = Program::new(
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.pc_base(),
        PROGRAM_CODE.to_vec(),
        PROGRAM_CODE
            .iter()
            .enumerate()
            .map(|(insn_idx, &insn)| {
                (
                    (insn_idx * PC_WORD_SIZE) as u32 + CENO_PLATFORM.pc_base(),
                    insn,
                )
            })
            .collect(),
    );

    let pcs_param = Pcs::setup(1 << MAX_NUM_VARIABLES).expect("Basefold PCS setup");
    let (pp, vp) = Pcs::trim(pcs_param, 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let mut zkvm_cs = ZKVMConstraintSystem::default();
    // opcode circuits
    let add_config = zkvm_cs.register_opcode_circuit::<AddInstruction<E>>();
    let halt_config = zkvm_cs.register_opcode_circuit::<HaltInstruction<E>>();
    let u16_range_config = zkvm_cs.register_table_circuit::<U16TableCircuit<E>>();

    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E>>();

    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
    zkvm_fixed_traces.register_opcode_circuit::<AddInstruction<E>>(&zkvm_cs);
    zkvm_fixed_traces.register_opcode_circuit::<HaltInstruction<E>>(&zkvm_cs);

    zkvm_fixed_traces.register_table_circuit::<U16TableCircuit<E>>(
        &zkvm_cs,
        &u16_range_config,
        &(),
    );

    zkvm_fixed_traces.register_table_circuit::<ProgramTableCircuit<E>>(
        &zkvm_cs,
        &prog_config,
        &program,
    );

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp, vp, zkvm_fixed_traces)
        .expect("keygen failed");
    let vk = pk.get_vk();

    // single instance
    let mut vm = VMState::new(CENO_PLATFORM, program.clone().into());
    let all_records = vm
        .iter_until_halt()
        .collect::<Result<Vec<StepRecord>, _>>()
        .expect("vm exec failed")
        .into_iter()
        .collect::<Vec<_>>();
    let mut add_records = vec![];
    let mut halt_records = vec![];
    all_records.into_iter().for_each(|record| {
        let kind = record.insn().codes().kind;
        match kind {
            ADD => add_records.push(record),
            EANY => {
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
    let prover = ZKVMProver::new(pk);
    let verifier = ZKVMVerifier::new(vk);
    let mut zkvm_witness = ZKVMWitnesses::default();
    // assign opcode circuits
    zkvm_witness
        .assign_opcode_circuit::<AddInstruction<E>>(&zkvm_cs, &add_config, add_records)
        .unwrap();
    zkvm_witness
        .assign_opcode_circuit::<HaltInstruction<E>>(&zkvm_cs, &halt_config, halt_records)
        .unwrap();
    zkvm_witness.finalize_lk_multiplicities();
    zkvm_witness
        .assign_table_circuit::<U16TableCircuit<E>>(&zkvm_cs, &u16_range_config, &())
        .unwrap();
    zkvm_witness
        .assign_table_circuit::<ProgramTableCircuit<E>>(&zkvm_cs, &prog_config, &program)
        .unwrap();

    let pi = PublicValues::new(0, 0, 0, 0, 0, vec![0]);
    let transcript = BasicTranscript::new(b"riscv");
    let zkvm_proof = prover
        .create_proof(zkvm_witness, pi, transcript)
        .expect("create_proof failed");

    let transcript = BasicTranscript::new(b"riscv");
    assert!(
        verifier
            .verify_proof(zkvm_proof, transcript)
            .expect("verify proof return with error"),
    );
}

/// test various product argument size, starting from minimal leaf size 2
#[test]
fn test_tower_proof_various_prod_size() {
    fn _test_tower_proof_prod_size_2(leaf_layer_size: usize) {
        let num_vars = ceil_log2(leaf_layer_size);
        let mut rng = test_rng();
        type E = GoldilocksExt2;
        let mut transcript = BasicTranscript::new(b"test_tower_proof");
        let leaf_layer: ArcMultilinearExtension<E> = (0..leaf_layer_size)
            .map(|_| E::random(&mut rng))
            .collect_vec()
            .into_mle()
            .into();
        let (first, second): (&[E], &[E]) = leaf_layer
            .get_ext_field_vec()
            .split_at(leaf_layer.evaluations().len() / 2);
        let last_layer_splitted_fanin: Vec<ArcMultilinearExtension<E>> = vec![
            first.to_vec().into_mle().into(),
            second.to_vec().into_mle().into(),
        ];
        let layers = infer_tower_product_witness(num_vars, last_layer_splitted_fanin, 2);
        let (rt_tower_p, tower_proof) = TowerProver::create_proof(
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
