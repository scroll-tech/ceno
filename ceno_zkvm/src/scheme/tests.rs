use std::marker::PhantomData;

use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::{Goldilocks, GoldilocksExt2};
use itertools::Itertools;
use multilinear_extensions::mle::IntoMLE;
use transcript::Transcript;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
    structs::PointAndEval,
};

use super::{constants::NUM_FANIN, prover::ZKVMProver, verifier::ZKVMVerifier};

struct TestCircuit<E: ExtensionField> {
    phantom: PhantomData<E>,
}

impl<E: ExtensionField> TestCircuit<E> {
    pub fn construct_circuit<const L: usize, const RW: usize>(
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        let regid = cb.create_witin();
        (0..RW).try_for_each(|_| {
            let record = cb.rlc_chip_record(vec![
                Expression::<E>::Constant(E::BaseField::ONE),
                regid.expr(),
            ]);
            cb.read_record(record.clone())?;
            cb.write_record(record)?;
            Result::<(), ZKVMError>::Ok(())
        })?;
        (0..L).try_for_each(|_| {
            cb.assert_ux::<16>(regid.expr())?;
            Result::<(), ZKVMError>::Ok(())
        })?;
        assert_eq!(cb.lk_expressions.len(), L);
        assert_eq!(cb.r_expressions.len(), RW);
        assert_eq!(cb.w_expressions.len(), RW);
        Ok(Self {
            phantom: PhantomData,
        })
    }
}

#[test]
fn test_rw_lk_expression_combination() {
    fn test_rw_lk_expression_combination_inner<const L: usize, const RW: usize>() {
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();
        let _ = TestCircuit::construct_circuit::<L, RW>(&mut circuit_builder);
        let circuit = circuit_builder.finalize_circuit();

        // generate mock witness
        let num_instances = 1 << 2;
        let wits_in = (0..circuit.num_witin as usize)
            .map(|_| {
                (0..num_instances)
                    .map(|_| Goldilocks::ONE)
                    .collect::<Vec<Goldilocks>>()
                    .into_mle()
                    .into()
            })
            .collect_vec();

        // get proof
        let prover = ZKVMProver::new(circuit.clone()); // circuit clone due to verifier alos need circuit reference
        let mut transcript = Transcript::new(b"test");
        let challenges = [1.into(), 2.into()];

        let proof = prover
            .create_proof(wits_in, num_instances, 1, &mut transcript, &challenges)
            .expect("create_proof failed");

        let verifier = ZKVMVerifier::new(circuit);
        let mut v_transcript = Transcript::new(b"test");
        let _rt_input = verifier
            .verify(
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
