use std::{marker::PhantomData, mem::MaybeUninit};

use ceno_emul::StepRecord;
use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLEs;
use rand::rngs::ThreadRng;
use transcript::Transcript;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::Instruction,
    set_val,
    structs::{PointAndEval, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    witness::LkMultiplicity,
};

use super::{constants::NUM_FANIN, prover::ZKVMProver, verifier::ZKVMVerifier};

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
        let reg_id = cb.create_witin(|| "reg_id")?;
        (0..RW).try_for_each(|_| {
            let record = cb.rlc_chip_record(vec![
                Expression::<E>::Constant(E::BaseField::ONE),
                reg_id.expr(),
            ]);
            cb.read_record(|| "read", record.clone())?;
            cb.write_record(|| "write", record)?;
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
        let name = TestCircuit::<E, RW, L>::name();
        let mut zkvm_cs = ZKVMConstraintSystem::default();
        let config = zkvm_cs.register_opcode_circuit::<TestCircuit<E, RW, L>>();

        let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
        zkvm_fixed_traces.register_opcode_circuit::<TestCircuit<E, RW, L>>(&zkvm_cs);

        let pk = zkvm_cs.clone().key_gen(zkvm_fixed_traces).unwrap();
        let vk = pk.get_vk();

        // generate mock witness
        let num_instances = 1 << 2;
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
        let mut transcript = Transcript::new(b"test");
        let mut rng = ThreadRng::default();
        let challenges = [E::random(&mut rng), E::random(&mut rng)];

        let wits_in = zkvm_witness
            .witnesses
            .remove(&name)
            .unwrap()
            .de_interleaving()
            .into_mles()
            .into_iter()
            .map(|v| v.into())
            .collect_vec();
        let proof = prover
            .create_opcode_proof(
                &prover.pk.circuit_pks.get(&name).unwrap(),
                wits_in,
                num_instances,
                1,
                &mut transcript,
                &challenges,
            )
            .expect("create_proof failed");

        let verifier = ZKVMVerifier::new(vk.clone());
        let mut v_transcript = Transcript::new(b"test");
        let _rt_input = verifier
            .verify_opcode_proof(
                verifier.vk.circuit_vks.get(&name).unwrap(),
                &proof,
                &mut v_transcript,
                NUM_FANIN,
                &PointAndEval::default(),
                &challenges,
            )
            .expect("verifier failed");
    }

    // <lookup count, rw count>
    test_rw_lk_expression_combination_inner::<19, 17>();
    test_rw_lk_expression_combination_inner::<61, 17>();
    test_rw_lk_expression_combination_inner::<17, 61>();
}
