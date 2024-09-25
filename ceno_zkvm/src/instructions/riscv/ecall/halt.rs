use crate::{
    chip_handler::RegisterChipOperations,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        riscv::{
            config::{ExprLtConfig, ExprLtInput},
            constants::{UInt, ECALL_HALT},
            ecall_insn::EcallInstructionConfig,
        },
        Instruction,
    },
    set_val,
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::StepRecord;
use ff_ext::ExtensionField;
use std::{marker::PhantomData, mem::MaybeUninit};

pub struct HaltConfig<E: ExtensionField> {
    ecall_cfg: EcallInstructionConfig,
    prev_x10_value: UInt<E>,
    prev_x10_ts: WitIn,
    lt_x10_cfg: ExprLtConfig,
}

pub struct HaltInstruction<E>(PhantomData<E>);

impl<E: ExtensionField> Instruction<E> for HaltInstruction<E> {
    type InstructionConfig = HaltConfig<E>;

    fn name() -> String {
        "ECALL_HALT".into()
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
        let prev_x10_ts = cb.create_witin(|| "prev_x10_ts")?;
        let prev_x10_value = UInt::new_unchecked(|| "prev_x10_value", cb)?;

        let ecall_cfg = EcallInstructionConfig::construct_circuit(
            cb,
            [ECALL_HALT[0].into(), ECALL_HALT[1].into()],
            None,
            Some(0.into()),
            Some(prev_x10_value.register_expr()),
        )?;

        // read exit_code from arg0 (X10 register) and write it to global state
        let (_, lt_x10_cfg) = cb.register_read(
            || "read x10",
            E::BaseField::from(ceno_emul::CENO_PLATFORM.reg_arg0() as u64),
            prev_x10_ts.expr(),
            ecall_cfg.ts.expr(),
            prev_x10_value.register_expr(),
        )?;

        Ok(HaltConfig {
            ecall_cfg,
            prev_x10_value,
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
            (ECALL_HALT[0] + (ECALL_HALT[1] << 16)) as u32
        );
        assert_eq!(step.pc().after.0, 0);

        set_val!(
            instance,
            config.prev_x10_ts,
            step.rs2().unwrap().previous_cycle
        );
        config.prev_x10_value.assign_limbs(
            instance,
            Value::new_unchecked(step.rs2().unwrap().value).u16_fields(),
        );

        ExprLtInput {
            lhs: step.rs2().unwrap().previous_cycle,
            rhs: step.cycle(),
        }
        .assign(instance, &config.lt_x10_cfg, lk_multiplicity);

        config
            .ecall_cfg
            .assign_instance::<E>(instance, lk_multiplicity, step)?;

        Ok(())
    }
}
