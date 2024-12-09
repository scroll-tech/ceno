use std::marker::PhantomData;

use ceno_emul::{InsnKind, StepRecord};
use ff_ext::ExtensionField;
use itertools::izip;

use super::{super::insn_base::WriteMEM, dummy_circuit::DummyConfig};
use crate::{
    circuit_builder::CircuitBuilder, error::ZKVMError, expression::Expression,
    instructions::Instruction, witness::LkMultiplicity,
};
use core::mem::MaybeUninit;

trait EcallSpec {
    const NAME: &'static str;

    const MEM_WRITE_COUNT: usize;
}

/// DummyEcall can handle any instruction and produce its side-effects.
pub struct DummyEcall<E, I>(PhantomData<(E, I)>);

impl<E: ExtensionField, I: EcallSpec> Instruction<E> for DummyEcall<E, I> {
    type InstructionConfig = DummyEcallConfig<E>;

    fn name() -> String {
        format!("{}_DUMMY", I::NAME)
    }

    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let dummy_insn = DummyConfig::construct_circuit(
            circuit_builder,
            InsnKind::EANY,
            true,
            true,
            false,
            false,
            false,
            false,
        )?;

        // TODO.
        let mem_addr = Expression::ZERO;
        let val_before = Expression::ZERO;
        let val_after = Expression::ZERO;

        let mem_writes = (0..I::MEM_WRITE_COUNT)
            .map(|_| {
                WriteMEM::construct_circuit(
                    circuit_builder,
                    mem_addr.clone(), // TODO: + offset.
                    val_before.clone(),
                    val_after.clone(),
                    dummy_insn.ts(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(DummyEcallConfig {
            dummy_insn,
            mem_writes,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [MaybeUninit<E::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let ops = &step.syscall().unwrap().mem_writes;
        for (mem_write, op) in izip!(&config.mem_writes, ops) {
            mem_write.assign_op(instance, lk_multiplicity, step.cycle(), op)?;
        }

        config
            .dummy_insn
            .assign_instance(instance, lk_multiplicity, step)
    }
}

#[derive(Debug)]
pub struct DummyEcallConfig<E: ExtensionField> {
    dummy_insn: DummyConfig<E>,

    mem_writes: Vec<WriteMEM>,
}
