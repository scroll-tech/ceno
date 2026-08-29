//! Fixed-width Llama-tiny TensorBus ABI emitters.
//!
//! The generic large-ecall chip binds RAM effects but deliberately leaves
//! syscall content unconstrained. These wrappers retain its fixed `WriteMEM`
//! trace and additionally bind the ecall code, ABI/length metadata, and a
//! canonical custom-bus event for the offline TensorBus relation.

use std::marker::PhantomData;

use ceno_emul::{
    InsnKind, StepRecord, SyscallSpec, TensorExportEndV1Spec, TensorHandleAttentionV1Spec,
    TensorHandleFfnV1Spec, TensorImportBeginV1Spec,
};
use ff_ext::{ExtensionField, FieldInto};
use multilinear_extensions::{Expression, ToExpr};
use p3::field::PrimeCharacteristicRing;

use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{
        Instruction,
        riscv::dummy::{LargeEcallConfig, LargeEcallDummy},
    },
    structs::{CustomRWTag, ProgramParams, RAMType},
    witness::LkMultiplicity,
};
use witness::set_val;

const ABI: usize = 0;
const FLAGS: usize = 1;
const INPUT_LEN: usize = 3;
const META_LEN: usize = 5;
const OUTPUT_LEN: usize = 4;
const RESERVED: usize = 7;
const META_START: usize = 8;
// Import writes descriptor (8 words), metadata (4 words), the fixed payload,
// then the output handle.  The tiny profile happened to put this at 16; the
// default 7B-shaped profile must skip its complete 4096-word payload.
const HANDLE_START_IMPORT: usize =
    META_START + 4 + ceno_emul::TENSOR_BUS_FIXED_TRANSFER_WORDS as usize;
const HANDLE_START_EXPORT: usize = 8;
const META_START_EXPORT: usize = 12;
const HANDLE_START_OP_INPUT: usize = 8;
const META_START_OP: usize = 12;
const HANDLE_START_OP_OUTPUT: usize = 16;

/// The emitted event has a fixed field layout so an offline table can consume
/// all four ABI calls with one record type.
fn event_record<E: ExtensionField, S: SyscallSpec>(
    config: &TensorBusEcallConfig<E>,
) -> Vec<Expression<E>> {
    let ecall = &config.ecall;
    let before = |index: usize| ecall.mem_writes[index].1.before.value();
    let after = |index: usize| ecall.mem_writes[index].1.after.value();
    let mut record = vec![
        CustomRWTag::TensorBusEvent.expr::<E>(),
        E::BaseField::from_u32(S::CODE).expr(),
    ];
    // Import-begin/export-end retain descriptor, metadata, and opaque handle;
    // their bulk payload is proved by
    // the fixed WriteMEM trace but is intentionally not TensorBus metadata.
    if S::CODE == TensorImportBeginV1Spec::CODE {
        record.extend((0..8).map(before));
        record.extend((META_START..META_START + 4).map(before));
        record.extend((HANDLE_START_IMPORT..HANDLE_START_IMPORT + 4).map(after));
        record.extend(std::iter::repeat_n(E::BaseField::ZERO.expr(), 4));
    } else if S::CODE == TensorExportEndV1Spec::CODE {
        record.extend((0..8).map(before));
        record.extend((META_START_EXPORT..META_START_EXPORT + 4).map(before));
        record.extend((HANDLE_START_EXPORT..HANDLE_START_EXPORT + 4).map(before));
        record.extend(std::iter::repeat_n(E::BaseField::ZERO.expr(), 4));
    } else {
        record.extend((0..8).map(before));
        record.extend((META_START_OP..META_START_OP + 4).map(before));
        record.extend((HANDLE_START_OP_INPUT..HANDLE_START_OP_INPUT + 4).map(before));
        record.extend((HANDLE_START_OP_OUTPUT..HANDLE_START_OP_OUTPUT + 4).map(after));
    }
    record.extend([
        config.key_shard_id.expr(),
        config.key_local_shard_cycle.expr(),
        config.key_ordinal.expr(),
    ]);
    record
}

fn constrain_fixed_tensor_bus<E: ExtensionField, S: SyscallSpec>(
    cb: &mut CircuitBuilder<E>,
    config: &TensorBusEcallConfig<E>,
) -> Result<(), ZKVMError> {
    let ecall = &config.ecall;
    let code = ecall
        .dummy_insn
        .rs1_value()
        .expect("TensorBus ECALL reads rs1")
        .value();
    cb.require_equal(
        || "tensor_bus_ecall_code",
        code,
        E::BaseField::from_u32(S::CODE).expr(),
    )?;
    let before = |index: usize| ecall.mem_writes[index].1.before.value();
    cb.require_equal(|| "tensor_bus_abi", before(ABI), E::BaseField::ONE.expr())?;
    cb.require_equal(
        || "tensor_bus_flags",
        before(FLAGS),
        E::BaseField::ZERO.expr(),
    )?;

    cb.require_equal(
        || "tensor_bus_reserved",
        before(RESERVED),
        E::BaseField::ZERO.expr(),
    )?;
    if S::CODE == TensorHandleAttentionV1Spec::CODE || S::CODE == TensorHandleFfnV1Spec::CODE {
        cb.require_equal(
            || "tensor_bus_op_reserved_0",
            before(6),
            E::BaseField::ZERO.expr(),
        )?;
        cb.require_equal(
            || "tensor_bus_op_reserved_1",
            before(7),
            E::BaseField::ZERO.expr(),
        )?;
    }
    cb.require_equal(
        || "tensor_bus_meta_len",
        before(META_LEN),
        E::BaseField::from_u32(4).expr(),
    )?;
    let length = if S::CODE == TensorImportBeginV1Spec::CODE {
        INPUT_LEN
    } else {
        OUTPUT_LEN
    };
    cb.require_equal(
        || "tensor_bus_fixed_words",
        before(length),
        E::BaseField::from_u32(ceno_emul::TENSOR_BUS_FIXED_TRANSFER_WORDS).expr(),
    )?;
    cb.require_equal(
        || "tensor_bus_key_local_shard_cycle",
        config.key_local_shard_cycle.expr(),
        ecall.dummy_insn.ts().expr(),
    )?;
    cb.require_equal(
        || "tensor_bus_key_ordinal",
        config.key_ordinal.expr(),
        E::BaseField::ZERO.expr(),
    )?;
    // TensorBus is only the host/device boundary.  Internal handle operators
    // remain ordinary proof-bound ECALLs and RAM transitions, but do not
    // create TensorBus records or guest-visible intermediate TensorBus values.
    if S::CODE == TensorImportBeginV1Spec::CODE || S::CODE == TensorExportEndV1Spec::CODE {
        let event_record = event_record::<E, S>(config);
        cb.write_record(|| "tensor_bus_event", RAMType::Custom, event_record)?;
    }
    Ok(())
}

pub struct TensorBusFixedEcall<E, S>(PhantomData<(E, S)>);
pub type TensorBusImportBeginEcallInstruction<E> = TensorBusFixedEcall<E, TensorImportBeginV1Spec>;
pub type TensorBusExportEndEcallInstruction<E> = TensorBusFixedEcall<E, TensorExportEndV1Spec>;
pub type TensorBusHandleAttentionEcallInstruction<E> =
    TensorBusFixedEcall<E, TensorHandleAttentionV1Spec>;
pub type TensorBusHandleFfnEcallInstruction<E> = TensorBusFixedEcall<E, TensorHandleFfnV1Spec>;

impl<E: ExtensionField, S: SyscallSpec> Instruction<E> for TensorBusFixedEcall<E, S> {
    type InstructionConfig = TensorBusEcallConfig<E>;
    type InsnType = InsnKind;

    fn inst_kinds() -> &'static [InsnKind] {
        &[InsnKind::ECALL]
    }
    fn name() -> String {
        format!("TensorBus{}Ecall", S::NAME)
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self::InstructionConfig, ZKVMError> {
        let ecall = LargeEcallDummy::<E, S>::construct_circuit(cb, params)?;
        let config = TensorBusEcallConfig {
            ecall,
            key_shard_id: cb.create_witin(|| "tensor_bus_key_shard_id"),
            key_local_shard_cycle: cb.create_witin(|| "tensor_bus_key_local_shard_cycle"),
            key_ordinal: cb.create_witin(|| "tensor_bus_key_ordinal"),
        };
        constrain_fixed_tensor_bus::<E, S>(cb, &config)?;
        Ok(config)
    }

    fn assign_instance(
        config: &Self::InstructionConfig,
        shard_ctx: &mut ShardContext,
        instance: &mut [E::BaseField],
        lk_multiplicity: &mut LkMultiplicity,
        step: &StepRecord,
    ) -> Result<(), ZKVMError> {
        LargeEcallDummy::<E, S>::assign_instance(
            &config.ecall,
            shard_ctx,
            instance,
            lk_multiplicity,
            step,
        )?;
        set_val!(instance, config.key_shard_id, shard_ctx.shard_id as u64);
        set_val!(
            instance,
            config.key_local_shard_cycle,
            shard_ctx.aligned_current_ts(step.cycle())
        );
        set_val!(instance, config.key_ordinal, 0_u64);
        Ok(())
    }
}

#[derive(Debug)]
pub struct TensorBusEcallConfig<E: ExtensionField> {
    ecall: LargeEcallConfig<E>,
    key_shard_id: multilinear_extensions::WitIn,
    key_local_shard_cycle: multilinear_extensions::WitIn,
    key_ordinal: multilinear_extensions::WitIn,
}
