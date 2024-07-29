use std::marker::PhantomData;

use ff_ext::ExtensionField;

use singer_utils::{
    self,
    chip_handler_v2::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    constants::OpcodeType,
    structs::{PCUIntV2, TSUIntV2, UInt64V2},
    structs_v2::CircuitBuilderV2,
    util_v2::{self, ToExpr, WitIn},
};

use util_v2::{InstructionV2, ZKVMV2Error};

pub struct AddInstruction;

// impl<E: ExtensionField> InstructionGraph<E> for AddInstruction {
//     type InstType = Self;
// }

pub struct InstructionConfig<E: ExtensionField> {
    pub pc: PCUIntV2,
    pub memory_ts: TSUIntV2,
    pub clk: WitIn,
    phantom: PhantomData<E>,
    pub prev_rd_memory_value: UInt64V2,
    pub addend_0: UInt64V2,
    pub addend_1: UInt64V2,
    pub outcome: UInt64V2,
    pub rs1_id: WitIn,
    pub rs2_id: WitIn,
    pub rd_id: WitIn,
    pub prev_rs1_memory_ts: TSUIntV2,
    pub prev_rs2_memory_ts: TSUIntV2,
    pub prev_rd_memory_ts: TSUIntV2,
}

impl<E: ExtensionField> InstructionV2<E> for AddInstruction {
    const OPCODE: OpcodeType = OpcodeType::ADD;
    const NAME: &'static str = "ADD";
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilderV2<E>,
    ) -> Result<InstructionConfig<E>, ZKVMV2Error> {
        let pc = PCUIntV2::new(circuit_builder);
        let memory_ts = TSUIntV2::new(circuit_builder);
        let clk = circuit_builder.create_witin();

        // state in
        // all of them should implement expr
        circuit_builder.state_in(&pc, &memory_ts, clk.expr())?;

        let next_pc = pc.add_const(circuit_builder, 1.into())?;
        let next_memory_ts = memory_ts.add_const(circuit_builder, 1.into())?;

        circuit_builder.state_out(&next_pc, &next_memory_ts, clk.expr() + 1.into())?;

        // Execution result = addend0 + addend1, with carry.
        let prev_rd_memory_value = UInt64V2::new(circuit_builder);
        let addend_0 = UInt64V2::new(circuit_builder);
        let addend_1 = UInt64V2::new(circuit_builder);
        let outcome = UInt64V2::new(circuit_builder);

        let computed_outcome = addend_0.add(circuit_builder, &addend_1)?;
        outcome.eq(circuit_builder, &computed_outcome)?;

        let rs1_id = circuit_builder.create_witin();
        let rs2_id = circuit_builder.create_witin();
        let rd_id = circuit_builder.create_witin();
        let prev_rs1_memory_ts = TSUIntV2::new(circuit_builder);
        let prev_rs2_memory_ts = TSUIntV2::new(circuit_builder);
        let prev_rd_memory_ts = TSUIntV2::new(circuit_builder);

        let is_lt_0 = prev_rs1_memory_ts.lt(circuit_builder, &memory_ts)?;
        let is_lt_1 = prev_rs2_memory_ts.lt(circuit_builder, &memory_ts)?;
        let is_lt_2 = prev_rd_memory_ts.lt(circuit_builder, &memory_ts)?;

        // less than = true
        circuit_builder.require_one(is_lt_0)?;
        circuit_builder.require_one(is_lt_1)?;
        circuit_builder.require_one(is_lt_2)?;

        circuit_builder.register_read(&rs1_id, &prev_rs1_memory_ts, &memory_ts, &addend_0)?;

        circuit_builder.register_read(&rs2_id, &prev_rs2_memory_ts, &memory_ts, &addend_1)?;

        circuit_builder.register_write(
            &rd_id,
            &prev_rd_memory_ts,
            &memory_ts,
            &prev_rd_memory_value,
            &computed_outcome,
        )?;

        Ok(InstructionConfig {
            pc,
            memory_ts,
            clk,
            prev_rd_memory_value,
            addend_0,
            addend_1,
            outcome,
            rs1_id,
            rs2_id,
            rd_id,
            prev_rs1_memory_ts,
            prev_rs2_memory_ts,
            prev_rd_memory_ts,
            phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use ark_std::test_rng;
    use ff::Field;
    use ff_ext::ExtensionField;
    use gkr::{structs::PointAndEval, util::ceil_log2};
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use multilinear_extensions::mle::DenseMultilinearExtension;
    use simple_frontend::structs::WitnessId;
    use singer_utils::{structs_v2::CircuitBuilderV2, util_v2::InstructionV2};
    use transcript::Transcript;

    use crate::scheme::{prover::ZKVMProver, verifier::ZKVMVerifier};

    use super::AddInstruction;

    #[test]
    fn test_add_construct_circuit() {
        let mut rng = test_rng();

        let mut circuit_builder = CircuitBuilderV2::<GoldilocksExt2>::new();
        let _ = AddInstruction::construct_circuit(&mut circuit_builder);
        let circuit = circuit_builder.finalize_circuit();

        // generate mock witness
        let mut wits_in = BTreeMap::new();
        let num_instances = 4;
        (0..circuit.num_witin as usize).for_each(|witness_id| {
            wits_in.insert(
                witness_id as WitnessId,
                DenseMultilinearExtension::from_evaluations_vec(
                    ceil_log2(num_instances),
                    (0..num_instances)
                        .map(|_| Goldilocks::random(&mut rng))
                        .collect(),
                ),
            );
        });

        // get proof
        let prover = ZKVMProver::new(circuit.clone()); // circuit clone due to verifier alos need circuit reference
        let mut transcript = Transcript::new(b"riscv");
        let challenges = vec![1.into(), 2.into()];

        let proof = prover
            .create_proof(wits_in, num_instances, &mut transcript, &challenges)
            .expect("create_proof failed");

        let verifier = ZKVMVerifier::new(circuit);
        let mut v_transcript = Transcript::new(b"riscv");
        verifier
            .verify(
                &proof,
                &mut v_transcript,
                &PointAndEval::default(),
                &challenges,
            )
            .expect("verifier failed");
        // println!("circuit_builder {:?}", circuit_builder);
    }

    fn bench_add_instruction_helper<E: ExtensionField>(_instance_num_vars: usize) {}

    #[test]
    fn bench_add_instruction() {
        bench_add_instruction_helper::<GoldilocksExt2>(10);
    }
}
