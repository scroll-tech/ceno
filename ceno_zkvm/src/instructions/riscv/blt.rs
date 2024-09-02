use ff_ext::ExtensionField;

use crate::{
    chip_handler::{GlobalStateRegisterMachineChipOperations, RegisterChipOperations},
    circuit_builder::CircuitBuilder,
    create_witin_from_expr,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        riscv::config::{LtConfig, LtInput},
        Instruction,
    },
    utils::{i64_to_ext, limb_u8_to_u16},
};

use super::{
    constants::{OPType, OpcodeType, RegUInt, RegUInt8, PC_STEP_SIZE},
    RIVInstruction,
};

pub struct BltInstruction;

pub struct InstructionConfig<E: ExtensionField> {
    pub pc: WitIn,
    pub next_pc: WitIn,
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
    pub is_lt: LtConfig,
}

pub struct BltInput {
    pub pc: u16,
    pub ts: u16,
    pub imm: i16, // rust don't have i12
    pub lhs_limb8: Vec<u8>,
    pub rhs_limb8: Vec<u8>,
    pub rs1_id: u8,
    pub rs2_id: u8,
    pub prev_rs1_ts: u16,
    pub prev_rs2_ts: u16,
}

impl BltInput {
    /// TODO: refactor after formalize the interface of opcode inputs
    pub fn generate_witness<E: ExtensionField>(
        &self,
        witin: &mut [E],
        config: InstructionConfig<E>,
    ) {
        assert!(!self.lhs_limb8.is_empty() && (self.lhs_limb8.len() == self.rhs_limb8.len()));
        // TODO: add boundary check for witin
        let lt_input = LtInput {
            lhs_limbs: &self.lhs_limb8,
            rhs_limbs: &self.rhs_limb8,
        };
        let is_lt = lt_input.generate_witness(witin, &config.is_lt);

        config.pc.assign(witin, || i64_to_ext(self.pc as i64));
        config.next_pc.assign(witin, || {
            if is_lt {
                i64_to_ext(self.pc as i64 + self.imm as i64)
            } else {
                i64_to_ext(self.pc as i64 + PC_STEP_SIZE as i64)
            }
        });
        config.ts.assign(witin, || i64_to_ext(self.ts as i64));
        config.imm.assign(witin, || i64_to_ext(self.imm as i64));
        config
            .rs1_id
            .assign(witin, || i64_to_ext(self.rs1_id as i64));
        config
            .rs2_id
            .assign(witin, || i64_to_ext(self.rs2_id as i64));
        config
            .prev_rs1_ts
            .assign(witin, || i64_to_ext(self.prev_rs1_ts as i64));
        config
            .prev_rs2_ts
            .assign(witin, || i64_to_ext(self.prev_rs2_ts as i64));

        config.lhs_limb8.assign(witin, || {
            self.lhs_limb8
                .iter()
                .map(|&limb| i64_to_ext(limb as i64))
                .collect()
        });
        config.rhs_limb8.assign(witin, || {
            self.lhs_limb8
                .iter()
                .map(|&limb| i64_to_ext(limb as i64))
                .collect()
        });
        let lhs = limb_u8_to_u16(&self.lhs_limb8);
        let rhs = limb_u8_to_u16(&self.rhs_limb8);
        config.lhs.assign(witin, || {
            lhs.iter().map(|&limb| i64_to_ext(limb as i64)).collect()
        });
        config.rhs.assign(witin, || {
            rhs.iter().map(|&limb| i64_to_ext(limb as i64)).collect()
        });
    }
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
        + is_lt.is_lt.expr() * imm.expr()
        + PC_STEP_SIZE.into()
        + is_lt.is_lt.expr() * PC_STEP_SIZE.into();

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

    let next_pc = create_witin_from_expr!(circuit_builder, next_pc)?;
    let next_ts = ts + 1.into();
    circuit_builder.state_out(next_pc.expr(), next_ts)?;

    Ok(InstructionConfig {
        pc,
        next_pc,
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
        is_lt,
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
