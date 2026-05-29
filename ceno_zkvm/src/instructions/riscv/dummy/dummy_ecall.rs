use std::marker::PhantomData;

use ceno_emul::{Change, FullTracer as Tracer, InsnKind, StepRecord, SyscallSpec};
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{super::insn_base::WriteMEM, dummy_circuit::DummyConfig};
use crate::{
    Value,
    chip_handler::RegisterChipOperations,
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    gadgets::AssertLtConfig,
    instructions::{Instruction, riscv::constants::UInt},
    structs::{ProgramParams, RAMType},
    witness::LkMultiplicity,
};
use ff_ext::FieldInto;
use multilinear_extensions::{ToExpr, WitIn};
use witness::set_val;

/// LargeEcallDummy can handle any instruction and produce its effects,
/// including multiple memory operations.
///
/// Unsafe: The content is not constrained.
pub struct LargeEcallDummy<E, S>(PhantomData<(E, S)>);

impl<E: ExtensionField, S: SyscallSpec> Instruction<E> for LargeEcallDummy<E, S> {
    type InstructionConfig = LargeEcallConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [Self::InsnType] {
        &[InsnKind::ECALL]
    }

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

        let start_addr = if S::MEM_OPS_COUNT > 0 {
            Some(cb.create_witin(|| "mem_addr"))
        } else {
            None
        };

        // Syscall argument registers are read-only pointers. The emulator
        // tracks them at `SUBCYCLE_RS1` (`SyscallEffects::finalize`), so read
        // them here at the same subcycle; treating them as RD writes would
        // desync the register-bus timestamps and break `prod_r == prod_w`.
        let reg_reads = (0..S::REG_OPS_COUNT)
            .map(|i| {
                let val = UInt::new_unchecked(|| format!("reg_read_{i}"), cb)?;
                let id = cb.create_witin(|| format!("reg_id_{i}"));
                let prev_ts = cb.create_witin(|| format!("prev_reg_ts_{i}"));
                let (_, lt_cfg) = cb.register_read(
                    || format!("read_reg_{i}"),
                    id,
                    prev_ts.expr(),
                    dummy_insn.ts().expr() + Tracer::SUBCYCLE_RS1,
                    val.register_expr(),
                )?;
                Ok(RegReadOp {
                    val,
                    id,
                    prev_ts,
                    lt_cfg,
                })
            })
            .collect::<Result<Vec<_>, ZKVMError>>()?;

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
            reg_reads,
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
        let sw = shard_ctx.syscall_witnesses.clone();
        let ops = &step.syscall(&sw).expect("syscall step");

        // Assign instruction.
        config
            .dummy_insn
            .assign_instance(instance, shard_ctx, lk_multiplicity, step)?;

        if S::MEM_OPS_COUNT > 0 {
            set_val!(
                instance,
                config.start_addr.as_ref().unwrap(),
                u64::from(ops.mem_ops[0].addr)
            );
        }

        // Assign registers (read-only, tracked at SUBCYCLE_RS1).
        for (reg, op) in config.reg_reads.iter().zip_eq(&ops.reg_ops) {
            reg.val
                .assign_value(instance, Value::new_unchecked(op.value.after));
            let shard_prev_cycle = shard_ctx.aligned_prev_ts(op.previous_cycle);
            let shard_cycle = step.cycle() - shard_ctx.current_shard_offset_cycle();
            set_val!(instance, reg.id, op.register_index() as u64);
            set_val!(instance, reg.prev_ts, shard_prev_cycle);
            reg.lt_cfg.assign_instance(
                instance,
                lk_multiplicity,
                shard_prev_cycle,
                shard_cycle + Tracer::SUBCYCLE_RS1,
            )?;
            shard_ctx.send(
                RAMType::Register,
                op.addr,
                op.register_index() as u64,
                step.cycle() + Tracer::SUBCYCLE_RS1,
                op.previous_cycle,
                op.value.after,
                None,
            );
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

/// Read-only access to a syscall argument register, tracked at
/// `SUBCYCLE_RS1` to match `SyscallEffects::finalize` (#1296).
#[derive(Debug)]
struct RegReadOp<E: ExtensionField> {
    val: UInt<E>,
    id: WitIn,
    prev_ts: WitIn,
    lt_cfg: AssertLtConfig,
}

#[derive(Debug)]
pub struct LargeEcallConfig<E: ExtensionField> {
    dummy_insn: DummyConfig<E>,

    reg_reads: Vec<RegReadOp<E>>,

    start_addr: Option<WitIn>,
    mem_writes: Vec<(WitIn, Change<UInt<E>>, WriteMEM)>,
}
