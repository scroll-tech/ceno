use std::marker::PhantomData;

use ceno_emul::{Change, InsnKind, KeccakSpec, StepRecord, SyscallSpec};
use ff_ext::{ExtensionField, SmallField};
use itertools::{Itertools, zip_eq};
use witness::RowMajorMatrix;

use super::{super::insn_base::WriteMEM, dummy_circuit::DummyConfig};
use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::{
        GKRIOPInstruction, GKRinfo, Instruction,
        riscv::{constants::UInt, insn_base::WriteRD},
    },
    set_val,
    witness::LkMultiplicity,
};
use ff_ext::FieldInto;
use multilinear_extensions::{ToExpr, WitIn};

use gkr_iop::{
    ProtocolWitnessGenerator,
    precompiles::{AND_LOOKUPS, KeccakLayout, KeccakTrace, RANGE_LOOKUPS, XOR_LOOKUPS},
};

/// LargeEcallDummy can handle any instruction and produce its effects,
/// including multiple memory operations.
///
/// Unsafe: The content is not constrained.
pub struct LargeEcallDummy<E, S>(PhantomData<(E, S)>);

impl<E: ExtensionField, S: SyscallSpec> Instruction<E> for LargeEcallDummy<E, S> {
    type InstructionConfig = LargeEcallConfig<E>;

    fn name() -> String {
        S::NAME.to_owned()
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
                let val_before = cb.create_witin(|| format!("mem_before_{}_READ_ARG", i));
                let val_after = cb.create_witin(|| format!("mem_after_{}_WRITE_ARG", i));
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

        // Will be filled in by GKR Instruction trait
        let lookups = vec![];
        let aux_wits = vec![];

        Ok(LargeEcallConfig {
            dummy_insn,
            start_addr,
            reg_writes,
            mem_writes,
            lookups,
            aux_wits,
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
    type Layout<'a> = KeccakLayout<E>;

    fn gkr_info() -> crate::instructions::GKRinfo {
        GKRinfo {
            and_lookups: AND_LOOKUPS,
            xor_lookups: XOR_LOOKUPS,
            range_lookups: RANGE_LOOKUPS,
            aux_wits: 40144, // TODO fix the hardcode value as now we have rlc lookup records
        }
    }

    fn construct_circuit_with_gkr_iop(
        cb: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let mut partial_config = Self::construct_circuit(cb)?;

        assert!(partial_config.lookups.is_empty());
        assert!(partial_config.aux_wits.is_empty());

        // TODO: capacity
        let mut lookups = vec![];
        let mut aux_wits = vec![];

        for i in 0..AND_LOOKUPS {
            let a = cb.create_witin(|| format!("and_lookup_{i}_a_LOOKUP_ARG"));
            let b = cb.create_witin(|| format!("and_lookup_{i}_b_LOOKUP_ARG"));
            let c = cb.create_witin(|| format!("and_lookup_{i}_c_LOOKUP_ARG"));
            cb.lookup_and_byte(a.into(), b.into(), c.into())?;
            lookups.extend(vec![a, b, c]);
        }
        for i in 0..XOR_LOOKUPS {
            let a = cb.create_witin(|| format!("xor_lookup_{i}_a_LOOKUP_ARG"));
            let b = cb.create_witin(|| format!("xor_lookup_{i}_b_LOOKUP_ARG"));
            let c = cb.create_witin(|| format!("xor_lookup_{i}_c_LOOKUP_ARG"));
            cb.lookup_xor_byte(a.into(), b.into(), c.into())?;
            lookups.extend(vec![a, b, c]);
        }
        for i in 0..RANGE_LOOKUPS {
            let wit = cb.create_witin(|| format!("range_lookup_{i}_LOOKUP_ARG"));
            cb.assert_ux::<_, _, 16>(|| "nada", wit.into())?;
            lookups.push(wit);
        }

        for i in 0..40144 {
            aux_wits.push(cb.create_witin(|| format!("{i}_GKR_WITNESS")));
        }

        partial_config.lookups = lookups;
        partial_config.aux_wits = aux_wits;

        Ok(partial_config)
    }

    // TODO: make this nicer without access to config
    // one alternative: the verifier uses the namespaces
    // contained in the constraint system to select
    // gkr-specific fields
    fn output_evals_map(i: usize) -> usize {
        if i < 50 {
            27 + 6 * i
        } else if i < 100 {
            26 + 6 * (i - 50)
        } else {
            326 + i - 100
        }
    }

    fn phase1_witness_from_steps<'a>(
        layout: &Self::Layout<'a>,
        steps: &[StepRecord],
    ) -> RowMajorMatrix<E::BaseField> {
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

        layout.phase1_witness_group(KeccakTrace { instances })
    }

    fn assign_instance_with_gkr_iop(
        config: &Self::InstructionConfig,
        instance: &mut [<E as ExtensionField>::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
        lookups: &[E::BaseField],
        aux_wits: &[E::BaseField],
    ) -> Result<(), ZKVMError> {
        Self::assign_instance(config, instance, lk_multiplicity, step)?;

        let mut wit_iter = lookups.iter().map(|f| f.to_canonical_u64());
        let mut var_iter = config.lookups.iter();

        let mut pop_arg = || -> u64 {
            let wit = wit_iter.next().unwrap();
            let var = var_iter.next().unwrap();
            set_val!(instance, var, wit);
            wit
        };

        for _i in 0..AND_LOOKUPS {
            lk_multiplicity.lookup_and_byte(pop_arg(), pop_arg());
            pop_arg();
        }
        for _i in 0..XOR_LOOKUPS {
            lk_multiplicity.lookup_xor_byte(pop_arg(), pop_arg());
            pop_arg();
        }
        for _i in 0..RANGE_LOOKUPS {
            lk_multiplicity.assert_ux::<16>(pop_arg());
        }

        for (aux_wit_var, aux_wit) in zip_eq(config.aux_wits.iter(), aux_wits) {
            set_val!(instance, aux_wit_var, (aux_wit.to_canonical_u64()));
        }
        assert!(var_iter.next().is_none());

        Ok(())
    }
}
#[derive(Debug)]
pub struct LargeEcallConfig<E: ExtensionField> {
    dummy_insn: DummyConfig<E>,

    reg_writes: Vec<(UInt<E>, WriteRD<E>)>,

    start_addr: WitIn,
    mem_writes: Vec<(WitIn, Change<WitIn>, WriteMEM)>,

    aux_wits: Vec<WitIn>,
    lookups: Vec<WitIn>,
}
