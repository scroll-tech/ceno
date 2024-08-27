use std::marker::PhantomData;

use ff_ext::ExtensionField;

use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::Instruction,
    structs::{PCUInt, TSUInt, UInt64},
};

use super::{
    constants::{OPType, OpcodeType, PC_STEP_SIZE},
    RIVInstruction,
};

pub struct AddInstruction;
pub struct SubInstruction;

pub struct InstructionConfig<E: ExtensionField> {
    pub pc: PCUInt<E>,
    pub ts: TSUInt<E>,
    pub prev_rd_value: UInt64<E>,
    pub addend_0: UInt64<E>,
    pub addend_1: UInt64<E>,
    pub outcome: UInt64<E>,
    pub rs1_id: WitIn,
    pub rs2_id: WitIn,
    pub rd_id: WitIn,
    pub prev_rs1_ts: TSUInt<E>,
    pub prev_rs2_ts: TSUInt<E>,
    pub prev_rd_ts: TSUInt<E>,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField> RIVInstruction<E> for AddInstruction {
    const OPCODE_TYPE: OpcodeType = OpcodeType::RType(OPType::OP, 0x000, 0x0000000);
}

impl<E: ExtensionField> RIVInstruction<E> for SubInstruction {
    const OPCODE_TYPE: OpcodeType = OpcodeType::RType(OPType::OP, 0x000, 0x0100000);
}

fn add_sub_gadget<E: ExtensionField, const IS_ADD: bool>(
    circuit_builder: &mut CircuitBuilder<E>,
) -> Result<InstructionConfig<E>, ZKVMError> {
    let pc = PCUInt::new(circuit_builder);
    let mut ts = TSUInt::new(circuit_builder);

    // state in
    circuit_builder.state_in(&pc, &ts)?;

    let next_pc = pc.add_const(circuit_builder, PC_STEP_SIZE.into())?;

    // Execution result = addend0 + addend1, with carry.
    let prev_rd_value = UInt64::new(circuit_builder);

    let (addend_0, addend_1, outcome) = if IS_ADD {
        // outcome = addend_0 + addend_1
        let addend_0 = UInt64::new(circuit_builder);
        let addend_1 = UInt64::new(circuit_builder);
        (
            addend_0.clone(),
            addend_1.clone(),
            addend_0.add(circuit_builder, &addend_1)?,
        )
    } else {
        // outcome + addend_1 = addend_0
        let outcome = UInt64::new(circuit_builder);
        let addend_1 = UInt64::new(circuit_builder);
        (
            addend_1.clone().add(circuit_builder, &outcome.clone())?,
            addend_1,
            outcome,
        )
    };

    let rs1_id = circuit_builder.create_witin();
    let rs2_id = circuit_builder.create_witin();
    let rd_id = circuit_builder.create_witin();

    // TODO remove me, this is just for testing degree > 1 sumcheck in main constraints
    circuit_builder.require_zero(rs1_id.expr() * rs1_id.expr() - rs1_id.expr() * rs1_id.expr())?;

    let mut prev_rs1_ts = TSUInt::new(circuit_builder);
    let mut prev_rs2_ts = TSUInt::new(circuit_builder);
    let mut prev_rd_ts = TSUInt::new(circuit_builder);

    let mut ts = circuit_builder.register_read(&rs1_id, &mut prev_rs1_ts, &mut ts, &addend_0)?;
    let mut ts = circuit_builder.register_read(&rs2_id, &mut prev_rs2_ts, &mut ts, &addend_1)?;

    let ts = circuit_builder.register_write(
        &rd_id,
        &mut prev_rd_ts,
        &mut ts,
        &prev_rd_value,
        &outcome,
    )?;

    let next_ts = ts.add_const(circuit_builder, 1.into())?;
    circuit_builder.state_out(&next_pc, &next_ts)?;

    Ok(InstructionConfig {
        pc,
        ts,
        prev_rd_value,
        addend_0,
        addend_1,
        outcome,
        rs1_id,
        rs2_id,
        rd_id,
        prev_rs1_ts,
        prev_rs2_ts,
        prev_rd_ts,
        phantom: PhantomData,
    })
}

impl<E: ExtensionField> Instruction<E> for AddInstruction {
    // const NAME: &'static str = "ADD";
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        add_sub_gadget::<E, true>(circuit_builder)
    }
}

impl<E: ExtensionField> Instruction<E> for SubInstruction {
    // const NAME: &'static str = "ADD";
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        add_sub_gadget::<E, false>(circuit_builder)
    }
}

#[cfg(test)]
mod test {

    use ark_std::test_rng;
    use ff::Field;
    use ff_ext::ExtensionField;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLE;
    use transcript::Transcript;

    use crate::{
        circuit_builder::CircuitBuilder,
        instructions::Instruction,
        scheme::{constants::NUM_FANIN, prover::ZKVMProver, verifier::ZKVMVerifier},
        structs::PointAndEval,
    };

    use super::AddInstruction;

    #[test]
    #[ignore = "hit tower verification bug, PR#165"]
    fn test_add_construct_circuit() {
        let mut rng = test_rng();

        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();
        let _ = AddInstruction::construct_circuit(&mut circuit_builder);
        let circuit = circuit_builder.finalize_circuit();

        // generate mock witness
        let num_instances = 1 << 2;
        let wits_in = (0..circuit.num_witin as usize)
            .map(|_| {
                (0..num_instances)
                    .map(|_| Goldilocks::random(&mut rng))
                    .collect::<Vec<Goldilocks>>()
                    .into_mle()
                    .into()
            })
            .collect_vec();

        // get proof
        let prover = ZKVMProver::new(circuit.clone()); // circuit clone due to verifier alos need circuit reference
        let mut transcript = Transcript::new(b"riscv");
        let challenges = [1.into(), 2.into()];

        let proof = prover
            .create_proof(wits_in, num_instances, 1, &mut transcript, &challenges)
            .expect("create_proof failed");

        let verifier = ZKVMVerifier::new(circuit);
        let mut v_transcript = Transcript::new(b"riscv");
        let _rt_input = verifier
            .verify(
                &proof,
                &mut v_transcript,
                NUM_FANIN,
                &PointAndEval::default(),
                &challenges,
            )
            .expect("verifier failed");
        // TODO verify opening via PCS
    }

    fn bench_add_instruction_helper<E: ExtensionField>(_instance_num_vars: usize) {}

    #[test]
    fn bench_add_instruction() {
        bench_add_instruction_helper::<GoldilocksExt2>(10);
    }
}
