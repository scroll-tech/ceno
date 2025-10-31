use std::marker::PhantomData;

use ceno_emul::{Change, InsnKind, StepRecord, SyscallSpec};
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{super::insn_base::WriteMEM, dummy_circuit::DummyConfig};
use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::{constants::UInt, insn_base::WriteRD},
    },
    structs::ProgramParams,
    witness::LkMultiplicity,
};
use ff_ext::FieldInto;
use multilinear_extensions::{ToExpr, WitIn};
use witness::set_val;

/// LargeEcallDummy can handle any instruction and produce its effects,
/// including multiple memory operations.
///
/// Unsafe: The content is not constrained.
#[derive(Default)]
pub struct LargeEcallDummy<E, S>(PhantomData<(E, S)>);

impl<E: ExtensionField, S: SyscallSpec> Instruction<E> for LargeEcallDummy<E, S> {
    type InstructionConfig = LargeEcallConfig<E>;
    type Record = StepRecord;

    fn name() -> String {
        S::NAME.to_owned()
    }
    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let dummy_insn = DummyConfig::construct_circuit(
            cb,
            InsnKind::ECALL,
            true, // Read the ecall function code.
            false,
            false,
            false,
            false,
            false,
        )?;

        let start_addr = cb.create_witin(|| "mem_addr");

        let reg_writes = (0..S::REG_OPS_COUNT)
            .map(|i| {
                let val_after = UInt::new_unchecked(|| format!("reg_after_{}", i), cb)?;

                WriteRD::construct_circuit(cb, val_after.register_expr(), dummy_insn.ts())
                    .map(|writer| (val_after, writer))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mem_writes = (0..S::MEM_OPS_COUNT)
            .map(|i| {
                let val_before = UInt::new_unchecked(|| format!("mem_before_{}_WRITE_ARG", i), cb)?;
                let val_after = UInt::new(|| format!("mem_after_{}_WRITE_ARG", i), cb)?;
                let addr = cb.create_witin(|| format!("addr_{}", i));
                WriteMEM::construct_circuit(
                    cb,
                    addr.expr(),
                    val_before.memory_expr(),
                    val_after.memory_expr(),
                    dummy_insn.ts(),
                )
                .map(|writer| (addr, Change::new(val_before, val_after), writer))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(LargeEcallConfig {
            dummy_insn,
            start_addr,
            reg_writes,
            mem_writes,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let ops = &step.syscall().expect("syscall step");

        // Assign instruction.
        config
            .dummy_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

        set_val!(instance, config.start_addr, u64::from(ops.mem_ops[0].addr));

        // Assign registers.
        for ((value, writer), op) in config.reg_writes.iter().zip_eq(&ops.reg_ops) {
            value.assign_value(instance, Value::new_unchecked(op.value.after));
            writer.assign_op(instance, shard_ctx, lk_multiplicity, step.cycle(), op)?;
        }

        // Assign memory.
        for ((addr, value, writer), op) in config.mem_writes.iter().zip_eq(&ops.mem_ops) {
            value
                .before
                .assign_value(instance, Value::new_unchecked(op.value.before));
            value
                .after
                .assign_value(instance, Value::new(op.value.after, lk_multiplicity));
            set_val!(instance, addr, u64::from(op.addr));
            writer.assign_op(instance, shard_ctx, lk_multiplicity, step.cycle(), op)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct LargeEcallConfig<E: ExtensionField> {
    dummy_insn: DummyConfig<E>,

    reg_writes: Vec<(UInt<E>, WriteRD<E>)>,

    start_addr: WitIn,
    mem_writes: Vec<(WitIn, Change<UInt<E>>, WriteMEM)>,
}
