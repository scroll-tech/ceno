use std::marker::PhantomData;

use ceno_emul::{
    COORDINATE_WORDS, Change, InsnKind, KECCAK_PERMUTE, KECCAK_WORDS, SECP256K1_ADD,
    SECP256K1_ARG_WORDS, SECP256K1_DECOMPRESS, SECP256K1_DOUBLE, SHA_EXTEND, SHA_EXTEND_WORDS,
    StepRecord, WORD_SIZE,
};
use ff_ext::ExtensionField;
use itertools::Itertools;

use super::{super::insn_base::WriteMEM, dummy_circuit::DummyConfig};
use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{ToExpr, WitIn},
    instructions::{
        Instruction,
        riscv::{constants::UInt, insn_base::WriteRD},
    },
    set_val,
    witness::LkMultiplicity,
};

pub trait EcallSpec {
    const NAME: &'static str;

    const REG_OPS_COUNT: usize;
    const MEM_OPS_COUNT: usize;
    const CODE: u32;
}

pub struct KeccakSpec;
pub struct Secp256k1AddSpec;
pub struct Secp256k1DoubleSpec;
pub struct Secp256k1DecompressSpec;

pub struct Sha256ExtendSpec;

impl EcallSpec for KeccakSpec {
    const NAME: &'static str = "KECCAK";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = KECCAK_WORDS;
    const CODE: u32 = KECCAK_PERMUTE;
}

impl EcallSpec for Secp256k1AddSpec {
    const NAME: &'static str = "SECP256K1_ADD";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * SECP256K1_ARG_WORDS;
    const CODE: u32 = SECP256K1_ADD;
}

impl EcallSpec for Secp256k1DoubleSpec {
    const NAME: &'static str = "SECP256K1_DOUBLE";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = SECP256K1_ARG_WORDS;
    const CODE: u32 = SECP256K1_DOUBLE;
}

impl EcallSpec for Secp256k1DecompressSpec {
    const NAME: &'static str = "SECP256K1_DECOMPRESS";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = 2 * COORDINATE_WORDS;
    const CODE: u32 = SECP256K1_DECOMPRESS;
}

impl EcallSpec for Sha256ExtendSpec {
    const NAME: &'static str = "SHA256_EXTEND";

    const REG_OPS_COUNT: usize = 2;
    const MEM_OPS_COUNT: usize = SHA_EXTEND_WORDS;
    const CODE: u32 = SHA_EXTEND;
}

/// LargeEcallDummy can handle any instruction and produce its effects,
/// including multiple memory operations.
///
/// Unsafe: The content is not constrained.
pub struct LargeEcallDummy<E, S>(PhantomData<(E, S)>);

impl<E: ExtensionField, S: EcallSpec> Instruction<E> for LargeEcallDummy<E, S> {
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

                WriteMEM::construct_circuit(
                    cb,
                    start_addr.expr() + (i * WORD_SIZE) as u64,
                    val_before.expr(),
                    val_after.expr(),
                    dummy_insn.ts(),
                )
                .map(|writer| (Change::new(val_before, val_after), writer))
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
        for ((value, writer), op) in config.mem_writes.iter().zip_eq(&ops.mem_ops) {
            set_val!(instance, value.before, op.value.before as u64);
            set_val!(instance, value.after, op.value.after as u64);
            writer.assign_op(instance, lk_multiplicity, step.cycle(), op)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct LargeEcallConfig<E: ExtensionField> {
    dummy_insn: DummyConfig<E>,

    reg_writes: Vec<(UInt<E>, WriteRD<E>)>,

    start_addr: WitIn,
    mem_writes: Vec<(Change<WitIn>, WriteMEM)>,
}
