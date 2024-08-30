use std::marker::PhantomData;

use ff_ext::ExtensionField;

use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::Instruction,
};

use super::{
    constants::{OPType, OpcodeType, RegUInt, RegUInt8, PC_STEP_SIZE},
    RIVInstruction,
};

pub struct BltInstruction;

pub struct InstructionConfig<E: ExtensionField> {
    pub pc: WitIn,
    pub ts: WitIn,
    pub imm: WitIn,
    pub lhs: RegUInt<E>,
    pub rhs: RegUInt<E>,
    pub lhs_limb8: RegUInt8<E>,
    pub rhs_limb8: RegUInt8<E>,
    pub rs1_id: WitIn,
    pub rs2_id: WitIn,
    pub prev_rs1_ts: WitIn,
    pub prev_rs2_ts: WitIn,
    phantom: PhantomData<E>,
}

impl<E: ExtensionField> RIVInstruction<E> for BltInstruction {
    const OPCODE_TYPE: OpcodeType = OpcodeType::BType(OPType::Branch, 0x004);
}

/// if (rs1 < rs2) PC += sext(imm)
fn blt_gadget<E: ExtensionField>(
    circuit_builder: &mut CircuitBuilder<E>,
) -> Result<InstructionConfig<E>, ZKVMError> {
    let pc = circuit_builder.create_witin(|| "pc")?;
    // imm is already sext(imm) from instruction
    let imm = circuit_builder.create_witin(|| "imm")?;
    let cur_ts = circuit_builder.create_witin(|| "ts")?;
    circuit_builder.state_in(pc.expr(), cur_ts.expr())?;

    // TODO: constraint rs1_id, rs2_id by bytecode lookup
    let rs1_id = circuit_builder.create_witin(|| "rs1_id")?;
    let rs2_id = circuit_builder.create_witin(|| "rs2_id")?;

    let lhs_limb8 = RegUInt8::new(|| "lhs_limb8", circuit_builder)?;
    let rhs_limb8 = RegUInt8::new(|| "rhs_limb8", circuit_builder)?;

    let is_lt = lhs_limb8.lt_limb8(circuit_builder, &rhs_limb8)?;

    // update pc
    let next_pc = pc.expr()
        + is_lt.clone() * imm.expr()
        + PC_STEP_SIZE.into()
        + is_lt.clone() * PC_STEP_SIZE.into();

    // update ts
    let prev_rs1_ts = circuit_builder.create_witin(|| "prev_rs1_ts")?;
    let prev_rs2_ts = circuit_builder.create_witin(|| "prev_rs2_ts")?;
    let lhs = RegUInt::from_u8_limbs(circuit_builder, &lhs_limb8);
    let rhs = RegUInt::from_u8_limbs(circuit_builder, &rhs_limb8);

    let ts = circuit_builder.register_read(
        || "read ts for lhs",
        &rs1_id,
        prev_rs1_ts.expr(),
        cur_ts.expr(),
        &lhs,
    )?;
    let ts = circuit_builder.register_read(
        || "read ts for rhs",
        &rs2_id,
        prev_rs2_ts.expr(),
        ts,
        &rhs,
    )?;

    let next_ts = ts + 1.into();
    circuit_builder.state_out(next_pc, next_ts)?;

    Ok(InstructionConfig {
        pc,
        ts: cur_ts,
        lhs,
        rhs,
        lhs_limb8,
        rhs_limb8,
        imm,
        rs1_id,
        rs2_id,
        prev_rs1_ts,
        prev_rs2_ts,
        phantom: PhantomData,
    })
}

impl<E: ExtensionField> Instruction<E> for BltInstruction {
    // const NAME: &'static str = "BLT";
    type InstructionConfig = InstructionConfig<E>;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<InstructionConfig<E>, ZKVMError> {
        blt_gadget::<E>(circuit_builder)
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
        circuit_builder::{CircuitBuilder, ConstraintSystem, ProvingKey},
        instructions::Instruction,
        scheme::{constants::NUM_FANIN, prover::ZKVMProver, verifier::ZKVMVerifier},
        structs::PointAndEval,
    };

    use super::BltInstruction;

    #[test]
    fn test_blt_circuit() {
        let mut rng = test_rng();

        let mut cs = ConstraintSystem::new(|| "riscv");
        let _ = cs.namespace(
            || "blt",
            |cs| {
                let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(cs);
                let config = BltInstruction::construct_circuit(&mut circuit_builder);
                Ok(config)
            },
        );
        let vk = cs.key_gen();
        let pk = ProvingKey::create_pk(vk);

        // generate mock witness
        let num_instances = 1 << 2;
        let wits_in = (0..pk.get_cs().num_witin as usize)
            .map(|_| {
                (0..num_instances)
                    .map(|_| Goldilocks::random(&mut rng))
                    .collect::<Vec<Goldilocks>>()
                    .into_mle()
                    .into()
            })
            .collect_vec();

        // get proof
        let prover = ZKVMProver::new(pk.clone());
        let mut transcript = Transcript::new(b"riscv");
        let challenges = [1.into(), 2.into()];

        let proof = prover
            .create_proof(wits_in, num_instances, 1, &mut transcript, &challenges)
            .expect("create_proof failed");

        let verifier = ZKVMVerifier::new(pk.vk);
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

    fn bench_blt_instruction_helper<E: ExtensionField>(_instance_num_vars: usize) {}

    #[test]
    fn bench_blt_instruction() {
        bench_blt_instruction_helper::<GoldilocksExt2>(10);
    }
}
