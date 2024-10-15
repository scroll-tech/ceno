use crate::{
    chip_handler::RegisterChipOperations,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    gadgets::AssertLTConfig,
    instructions::{
        riscv::{
            constants::{ECALL_HALT_OPCODE, EXIT_PC},
            ecall_insn::EcallInstructionConfig,
        },
        Instruction,
    },
    set_val,
    witness::LkMultiplicity,
};
use ceno_emul::{StepRecord, Tracer};
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct HaltConfig {
    ecall_cfg: EcallInstructionConfig,
    prev_x10_ts: WitIn,
    lt_x10_cfg: AssertLTConfig,
}

pub struct HaltInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for HaltInstruction<E> {
    type InstructionConfig = HaltConfig;

    fn name() -> String {
        "ECALL_HALT".into()
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        let prev_x10_ts = cb.create_witin(|| "prev_x10_ts")?;
        let exit_code = {
            let exit_code = cb.query_exit_code()?;
            [exit_code[0].expr(), exit_code[1].expr()]
        };

        let ecall_cfg = EcallInstructionConfig::construct_circuit(
            cb,
            [ECALL_HALT_OPCODE[0].into(), ECALL_HALT_OPCODE[1].into()],
            None,
            Some(EXIT_PC.into()),
        )?;

        // read exit_code from arg0 (X10 register)
        let (_, lt_x10_cfg) = cb.register_read(
            || "read x10",
            E::BaseField::from(ceno_emul::CENO_PLATFORM.reg_arg0() as u64),
            prev_x10_ts.expr(),
            ecall_cfg.ts.expr() + (Tracer::SUBCYCLE_RS2 as usize).into(),
            exit_code,
        )?;

        Ok(HaltConfig {
            ecall_cfg,
            prev_x10_ts,
            lt_x10_cfg,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        assert_eq!(
            step.rs1().unwrap().value,
            (ECALL_HALT_OPCODE[0] + (ECALL_HALT_OPCODE[1] << 16)) as u32
        );
        assert_eq!(
            step.pc().after.0,
            0,
            "pc after ecall/halt {:x}",
            step.pc().after.0
        );

        // the access of X10 register is stored in rs2()
        set_val!(
            instance,
            config.prev_x10_ts,
            step.rs2().unwrap().previous_cycle
        );

        config.lt_x10_cfg.assign_instance(
            instance,
            lk_multiplicity,
            step.rs2().unwrap().previous_cycle,
            step.cycle() + Tracer::SUBCYCLE_RS2,
        )?;

        config
            .ecall_cfg
            .assign_instance::<E>(instance, lk_multiplicity, step)?;

        Ok(())
    }
}
