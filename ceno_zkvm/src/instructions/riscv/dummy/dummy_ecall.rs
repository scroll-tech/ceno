use std::marker::PhantomData;

use ceno_emul::{Change, InsnKind, KeccakSpec, StepRecord, SyscallSpec};
use ff_ext::{ExtensionField, SmallField};
use itertools::Itertools;

use super::{super::insn_base::WriteMEM, dummy_circuit::DummyConfig};
use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        GKRIOPInstruction, Instruction,
        riscv::{constants::UInt, insn_base::WriteRD},
    },
    set_val,
    witness::LkMultiplicity,
};
use ff_ext::FieldInto;

use gkr_iop::{
    ProtocolWitnessGenerator,
    precompiles::{
        AND_LOOKUPS_PER_ROUND, KeccakLayout, KeccakTrace, RANGE_LOOKUPS_PER_ROUND,
        XOR_LOOKUPS_PER_ROUND,
    },
};

/// LargeEcallDummy can handle any instruction and produce its effects,
/// including multiple memory operations.
///
/// Unsafe: The content is not constrained.
pub struct LargeEcallDummy<E, S>(PhantomData<(E, S)>);

impl<E: ExtensionField, S: SyscallSpec> Instruction<E> for LargeEcallDummy<E, S> {
    type InstructionConfig = LargeEcallConfig<E>;

    fn name() -> String {
        format!("{}_DUMMY", S::NAME)
    }
    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::InstructionConfig, ZKVMError> {
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
                let val_before = cb.create_witin(|| format!("mem_before_{}", i));
                let val_after = cb.create_witin(|| format!("mem_after_{}", i));
                let addr = cb.create_witin(|| format!("addr_{}", i));
                WriteMEM::construct_circuit(
                    cb,
                    addr.expr(),
                    val_before.expr(),
                    val_after.expr(),
                    dummy_insn.ts(),
                )
                .map(|writer| (addr, Change::new(val_before, val_after), writer))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Temporarily set this to < 24 to avoid cb.num_witin overflow
        let active_rounds = 12;

        let mut lookups = Vec::with_capacity(
            active_rounds
                * (3 * AND_LOOKUPS_PER_ROUND + 3 * XOR_LOOKUPS_PER_ROUND + RANGE_LOOKUPS_PER_ROUND),
        );

        dbg!(lookups.capacity());

        for round in 0..active_rounds {
            for i in 0..AND_LOOKUPS_PER_ROUND {
                let a = cb.create_witin(|| format!("and_lookup_{round}_{i}_a"));
                let b = cb.create_witin(|| format!("and_lookup_{round}_{i}_b"));
                let c = cb.create_witin(|| format!("and_lookup_{round}_{i}_c"));
                cb.lookup_and_byte(a.into(), b.into(), c.into())?;
                lookups.extend(vec![a, b, c]);
            }
            for i in 0..XOR_LOOKUPS_PER_ROUND {
                let a = cb.create_witin(|| format!("xor_lookup_{round}_{i}_a"));
                let b = cb.create_witin(|| format!("xor_lookup_{round}_{i}_b"));
                let c = cb.create_witin(|| format!("xor_lookup_{round}_{i}_c"));
                cb.lookup_xor_byte(a.into(), b.into(), c.into())?;
                lookups.extend(vec![a, b, c]);
            }
            for i in 0..RANGE_LOOKUPS_PER_ROUND {
                let wit = cb.create_witin(|| format!("range_lookup_{round}_{i}"));
                cb.assert_ux::<_, _, 16>(|| "nada", wit.into())?;
                lookups.push(wit);
            }
        }

        Ok(LargeEcallConfig {
            dummy_insn,
            start_addr,
            reg_writes,
            mem_writes,
            lookups,
        })
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        let ops = &step.syscall().expect("syscall step");

        // Assign instruction.
        config
            .dummy_insn
            .assign_instance(instance, lk_multiplicity, step)?;

        set_val!(instance, config.start_addr, u64::from(ops.mem_ops[0].addr));

        // Assign registers.
        for ((value, writer), op) in config.reg_writes.iter().zip_eq(&ops.reg_ops) {
            value.assign_value(instance, Value::new_unchecked(op.value.after));
            writer.assign_op(instance, lk_multiplicity, step.cycle(), op)?;
        }

        // Assign memory.
        for ((addr, value, writer), op) in config.mem_writes.iter().zip_eq(&ops.mem_ops) {
            set_val!(instance, value.before, op.value.before as u64);
            set_val!(instance, value.after, op.value.after as u64);
            set_val!(instance, addr, u64::from(op.addr));
            writer.assign_op(instance, lk_multiplicity, step.cycle(), op)?;
        }

        Ok(())
    }
}

impl<E: ExtensionField> GKRIOPInstruction<E> for LargeEcallDummy<E, KeccakSpec> {
    type Layout = KeccakLayout<E>;

    fn phase1_witness_from_steps(
        layout: &Self::Layout,
        steps: Vec<StepRecord>,
    ) -> Vec<Vec<<E as ExtensionField>::BaseField>> {
        let instances = steps
            .iter()
            .map(|step| {
                step.syscall()
                    .unwrap()
                    .mem_ops
                    .iter()
                    .map(|op| op.value.before)
                    .collect_vec()
                    .try_into()
                    .unwrap()
            })
            .collect_vec();

        layout.phase1_witness(KeccakTrace { instances })
    }

    fn assign_instance_with_gkr_iop(
        config: &Self::InstructionConfig,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
        lookups: Vec<E::BaseField>,
    ) -> Result<(), ZKVMError> {
        Self::assign_instance(config, instance, lk_multiplicity, step)?;

        let active_rounds = 12;
        let mut wit_iter = lookups.iter().map(|f| f.to_canonical_u64());
        let mut var_iter = config.lookups.iter();

        let mut pop_arg = || -> u64 {
            let wit = wit_iter.next().unwrap();
            let var = var_iter.next().unwrap();
            set_val!(instance, var, wit);
            wit
        };

        for round in 0..active_rounds {
            for i in 0..AND_LOOKUPS_PER_ROUND {
                lk_multiplicity.lookup_and_byte(pop_arg(), pop_arg());
            }
            for i in 0..XOR_LOOKUPS_PER_ROUND {
                lk_multiplicity.lookup_xor_byte(pop_arg(), pop_arg());
            }
            for i in 0..RANGE_LOOKUPS_PER_ROUND {
                lk_multiplicity.assert_ux::<16>(pop_arg());
            }
        }

        Ok(())
    }
}
#[derive(Debug)]
pub struct LargeEcallConfig<E: ExtensionField> {
    dummy_insn: DummyConfig<E>,

    reg_writes: Vec<(UInt<E>, WriteRD<E>)>,

    start_addr: WitIn,
    mem_writes: Vec<(WitIn, Change<WitIn>, WriteMEM)>,
    lookups: Vec<WitIn>,
}
