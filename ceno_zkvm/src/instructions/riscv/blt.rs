use goldilocks::SmallField;
use std::mem::MaybeUninit;

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
    set_val,
    utils::{i64_to_base, limb_u8_to_u16},
    witness::LkMultiplicity,
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
    pub fn assign<F: SmallField, E: ExtensionField<BaseField = F>>(
        &self,
        config: &InstructionConfig<E>,
        instance: &mut [MaybeUninit<F>],
    ) {
        assert!(!self.lhs_limb8.is_empty() && (self.lhs_limb8.len() == self.rhs_limb8.len()));
        // TODO: add boundary check for witin
        let lt_input = LtInput {
            lhs_limbs: &self.lhs_limb8,
            rhs_limbs: &self.rhs_limb8,
        };
        let is_lt = lt_input.assign(instance, &config.is_lt);

        set_val!(instance, config.pc, { i64_to_base::<F>(self.pc as i64) });
        set_val!(instance, config.next_pc, {
            if is_lt {
                i64_to_base::<F>(self.pc as i64 + self.imm as i64)
            } else {
                i64_to_base::<F>(self.pc as i64 + PC_STEP_SIZE as i64)
            }
        });
        set_val!(instance, config.ts, { i64_to_base::<F>(self.ts as i64) });
        set_val!(instance, config.imm, { i64_to_base::<F>(self.imm as i64) });
        set_val!(instance, config.rs1_id, {
            i64_to_base::<F>(self.rs1_id as i64)
        });
        set_val!(instance, config.rs2_id, {
            i64_to_base::<F>(self.rs2_id as i64)
        });
        set_val!(instance, config.prev_rs1_ts, {
            i64_to_base::<F>(self.prev_rs1_ts as i64)
        });
        set_val!(instance, config.prev_rs2_ts, {
            i64_to_base::<F>(self.prev_rs2_ts as i64)
        });

        config.lhs_limb8.assign_limbs(instance, {
            self.lhs_limb8
                .iter()
                .map(|&limb| i64_to_base::<F>(limb as i64))
                .collect()
        });
        config.rhs_limb8.assign_limbs(instance, {
            self.rhs_limb8
                .iter()
                .map(|&limb| i64_to_base::<F>(limb as i64))
                .collect()
        });
        let lhs = limb_u8_to_u16(&self.lhs_limb8);
        let rhs = limb_u8_to_u16(&self.rhs_limb8);
        config.lhs.assign_limbs(instance, {
            lhs.iter()
                .map(|&limb| i64_to_base::<F>(limb as i64))
                .collect()
        });
        config.rhs.assign_limbs(instance, {
            rhs.iter()
                .map(|&limb| i64_to_base::<F>(limb as i64))
                .collect()
        });
    }

    pub fn random() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // hack to generate valid inputs
        let ts_bound: u16 = rng.gen_range(100..1000);
        let pc_bound: u16 = rng.gen_range(100..1000);

        Self {
            pc: rng.gen_range(pc_bound..(1 << 15)),
            ts: rng.gen_range(ts_bound..(1 << 15)),
            imm: rng.gen_range(-(pc_bound as i16)..2047),
            // this is for riscv32 inputs
            lhs_limb8: (0..4).map(|_| rng.gen()).collect(),
            rhs_limb8: (0..4).map(|_| rng.gen()).collect(),
            rs1_id: rng.gen(),
            rs2_id: rng.gen(),
            prev_rs1_ts: rng.gen_range(0..ts_bound),
            prev_rs2_ts: rng.gen_range(0..ts_bound),
        }
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
    let next_pc = pc.expr() + is_lt.is_lt.expr() * imm.expr() + PC_STEP_SIZE.into()
        - is_lt.is_lt.expr() * PC_STEP_SIZE.into();

    // update ts
    let prev_rs1_ts = circuit_builder.create_witin(|| "prev_rs1_ts")?;
    let prev_rs2_ts = circuit_builder.create_witin(|| "prev_rs2_ts")?;
    // TODO: replace it with `new_from_exprs_unchecked` after PR 181
    // so we can remove lhs/rhs from config
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

    let next_pc = create_witin_from_expr!(circuit_builder, false, next_pc)?;
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

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [std::mem::MaybeUninit<E::BaseField>],
        _lk_multiplicity: &mut LkMultiplicity,
        _step: &ceno_emul::StepRecord,
    ) -> Result<(), ZKVMError> {
        // take input from _step
        let input = BltInput::random();
        input.assign(config, instance);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ceno_emul::StepRecord;
    use goldilocks::GoldilocksExt2;
    use itertools::Itertools;
    use multilinear_extensions::mle::IntoMLEs;

    use crate::{circuit_builder::ConstraintSystem, scheme::mock_prover::MockProver};

    #[test]
    fn test_blt_circuit() -> Result<(), ZKVMError> {
        let mut cs = ConstraintSystem::new(|| "riscv");
        let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new(&mut cs);
        let config = BltInstruction::construct_circuit(&mut circuit_builder)?;

        let num_wits = circuit_builder.cs.num_witin as usize;
        // generate mock witness
        let num_instances = 1 << 4;
        let (raw_witin, _) = BltInstruction::assign_instances(
            &config,
            num_wits,
            vec![StepRecord::default(); num_instances],
        )
        .unwrap();

        MockProver::run(
            &mut circuit_builder,
            &raw_witin
                .de_interleaving()
                .into_mles()
                .into_iter()
                .map(|v| v.into())
                .collect_vec(),
            None,
        )
        .expect_err("lookup will fail");
        Ok(())
    }

    fn bench_blt_instruction_helper<E: ExtensionField>(_instance_num_vars: usize) {}

    #[test]
    fn bench_blt_instruction() {
        bench_blt_instruction_helper::<GoldilocksExt2>(10);
    }
}
