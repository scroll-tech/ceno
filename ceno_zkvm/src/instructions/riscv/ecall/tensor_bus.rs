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

#[cfg(feature = "llama-tiny")]
use super::{
    tensor_batched_matmul::tensor_space_record, tensor_llama_tiny::llama_tiny_layer_state_record,
};

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
#[cfg(feature = "llama-tiny")]
const VALUE_START_IMPORT: usize = META_START + 4;
#[cfg(feature = "llama-tiny")]
const VALUE_START_EXPORT: usize = META_START_EXPORT + 4;

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
    #[cfg(not(feature = "llama-tiny"))]
    cb.require_equal(|| "tensor_bus_abi", before(ABI), E::BaseField::ONE.expr())?;
    #[cfg(feature = "llama-tiny")]
    {
        cb.assert_bit(|| "tensor_bus_abi_v2_bit", config.abi_v2.expr())?;
        cb.require_equal(
            || "tensor_bus_abi",
            before(ABI),
            E::BaseField::ONE.expr() + config.abi_v2.expr(),
        )?;
    }
    cb.require_equal(
        || "tensor_bus_flags",
        before(FLAGS),
        E::BaseField::ZERO.expr(),
    )?;

    if S::CODE == TensorImportBeginV1Spec::CODE || S::CODE == TensorExportEndV1Spec::CODE {
        cb.require_equal(
            || "tensor_bus_reserved",
            before(RESERVED),
            E::BaseField::ZERO.expr(),
        )?;
    } else {
        #[cfg(not(feature = "llama-tiny"))]
        cb.require_equal(
            || "tensor_bus_op_reserved",
            before(RESERVED),
            E::BaseField::ZERO.expr(),
        )?;
        #[cfg(feature = "llama-tiny")]
        {
            let abi_v1 = E::BaseField::ONE.expr() - config.abi_v2.expr();
            cb.require_zero(|| "tensor_bus_v1_op_reserved", abi_v1 * before(RESERVED))?;
            cb.require_zero(
                || "tensor_bus_v2_profile",
                config.abi_v2.expr()
                    * (before(6)
                        - E::BaseField::from_u32(ceno_emul::tensor::TENSOR_PROFILE_LLAMA_TINY)
                            .expr()),
            )?;
            cb.require_zero(|| "tensor_bus_v2_layer", config.abi_v2.expr() * before(7))?;
        }
    }
    // Descriptor layouts intentionally differ at the boundary:
    //
    // import: abi, flags, input_ptr, input_len, meta_ptr, meta_len, ...
    // export: abi, flags, handle_ptr, output_ptr, output_len, meta_ptr,
    //         meta_len, ...
    // op:     abi, flags, input_handle, output_handle, meta_ptr, meta_len,
    //         hint_base, ...
    let meta_len = if S::CODE == TensorExportEndV1Spec::CODE {
        6
    } else {
        META_LEN
    };
    cb.require_equal(
        || "tensor_bus_meta_len",
        before(meta_len),
        E::BaseField::from_u32(4).expr(),
    )?;
    if S::CODE == TensorImportBeginV1Spec::CODE || S::CODE == TensorExportEndV1Spec::CODE {
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
    } else {
        // Handle operators have no descriptor transfer-length field. Their
        // metadata begins after descriptor + input handle, and binds the same
        // fixed activation width in bytes.
        cb.require_equal(
            || "tensor_bus_op_meta_byte_len",
            before(META_START_OP),
            E::BaseField::from_u32(ceno_emul::TENSOR_BUS_FIXED_TRANSFER_WORDS * 4).expr(),
        )?;
    }
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
    #[cfg(feature = "llama-tiny")]
    constrain_v2_tensor_records::<E, S>(cb, config)?;
    Ok(())
}

#[cfg(feature = "llama-tiny")]
fn constrain_v2_tensor_records<E: ExtensionField, S: SyscallSpec>(
    cb: &mut CircuitBuilder<E>,
    config: &TensorBusEcallConfig<E>,
) -> Result<(), ZKVMError> {
    let ecall = &config.ecall;
    let before = |index: usize| ecall.mem_writes[index].1.before.value();
    let after = |index: usize| ecall.mem_writes[index].1.after.value();
    let enabled = config.abi_v2.expr();
    let enabled_ram_type = E::BaseField::from_u64(RAMType::Custom as u64).expr() * enabled.clone()
        + E::BaseField::from_u64(RAMType::Undefined as u64).expr()
            * (E::BaseField::ONE.expr() - enabled.clone());

    if S::CODE == TensorImportBeginV1Spec::CODE {
        cb.require_zero(
            || "tensor_bus_v2_import_cycle",
            enabled.clone() * (config.import_cycle.expr() - ecall.dummy_insn.ts().expr()),
        )?;
        for row in 0..4 {
            let record = tensor_space_record(
                config.import_cycle.expr(),
                after(HANDLE_START_IMPORT),
                after(HANDLE_START_IMPORT + 1),
                after(HANDLE_START_IMPORT + 2),
                E::BaseField::from_u32(row).expr(),
                config.boundary_values[row as usize].expr(),
            );
            let rlc = cb.rlc_chip_record(record.clone()) * enabled.clone()
                + (E::BaseField::ONE.expr() - enabled.clone());
            cb.write_rlc_record(
                || format!("tensor_bus_v2_import_value_{row}"),
                enabled_ram_type.clone(),
                record,
                rlc,
            )?;
        }
    } else if S::CODE == TensorExportEndV1Spec::CODE {
        for row in 0..4 {
            let record = tensor_space_record(
                config.import_cycle.expr(),
                before(HANDLE_START_EXPORT),
                before(HANDLE_START_EXPORT + 1),
                before(HANDLE_START_EXPORT + 2),
                E::BaseField::from_u32(row).expr(),
                config.boundary_values[row as usize].expr(),
            );
            let rlc = cb.rlc_chip_record(record.clone()) * enabled.clone()
                + (E::BaseField::ONE.expr() - enabled.clone());
            cb.read_rlc_record(
                || format!("tensor_bus_v2_export_value_{row}"),
                enabled_ram_type.clone(),
                record,
                rlc,
            )?;
        }
    } else {
        let attention = S::CODE == TensorHandleAttentionV1Spec::CODE;
        let (ordinal, family, op, coordinate_row) = if attention {
            (0, 0, 0, 0)
        } else {
            (112, 7, 112, 56)
        };
        let anchor = llama_tiny_layer_state_record(
            config.import_cycle.expr(),
            ecall.dummy_insn.ts().expr(),
            before(HANDLE_START_OP_INPUT),
            before(HANDLE_START_OP_INPUT + 1),
            before(HANDLE_START_OP_INPUT + 2),
            after(HANDLE_START_OP_OUTPUT),
            after(HANDLE_START_OP_OUTPUT + 1),
            after(HANDLE_START_OP_OUTPUT + 2),
            E::BaseField::from_u32(ordinal).expr(),
            E::BaseField::from_u32(family).expr(),
            E::BaseField::from_u32(family).expr(),
            E::BaseField::from_u32(op).expr(),
            E::BaseField::from_u32(coordinate_row).expr(),
            E::BaseField::ZERO.expr(),
            config.layer_anchor_value.expr(),
            config.layer_anchor_value.expr(),
            std::array::from_fn(|_| E::BaseField::ZERO.expr()),
        );
        let anchor_rlc = cb.rlc_chip_record(anchor.clone()) * enabled.clone()
            + (E::BaseField::ONE.expr() - enabled.clone());
        if attention {
            cb.write_rlc_record(
                || "llama_tiny_layer_start",
                enabled_ram_type,
                anchor,
                anchor_rlc,
            )?;
        } else {
            cb.read_rlc_record(
                || "llama_tiny_layer_end",
                enabled_ram_type,
                anchor,
                anchor_rlc,
            )?;
        }
    }

    if S::CODE == TensorImportBeginV1Spec::CODE || S::CODE == TensorExportEndV1Spec::CODE {
        let raw_value = |row: usize| {
            if S::CODE == TensorImportBeginV1Spec::CODE {
                before(VALUE_START_IMPORT + row)
            } else {
                after(VALUE_START_EXPORT + row)
            }
        };
        for row in 0..4 {
            cb.assert_bit(
                || format!("tensor_bus_v2_boundary_sign_{row}"),
                config.boundary_signs[row].expr(),
            )?;
            cb.require_zero(
                || format!("tensor_bus_v2_boundary_twos_complement_{row}"),
                enabled.clone()
                    * (raw_value(row)
                        - config.boundary_values[row].expr()
                        - config.boundary_signs[row].expr() * (1_u64 << 32)),
            )?;
        }
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
            #[cfg(feature = "llama-tiny")]
            abi_v2: cb.create_witin(|| "tensor_bus_abi_v2"),
            #[cfg(feature = "llama-tiny")]
            import_cycle: cb.create_witin(|| "tensor_bus_import_cycle"),
            #[cfg(feature = "llama-tiny")]
            boundary_values: std::array::from_fn(|row| {
                cb.create_witin(|| format!("tensor_bus_boundary_value_{row}"))
            }),
            #[cfg(feature = "llama-tiny")]
            boundary_signs: std::array::from_fn(|row| {
                cb.create_witin(|| format!("tensor_bus_boundary_sign_{row}"))
            }),
            #[cfg(feature = "llama-tiny")]
            layer_anchor_value: cb.create_witin(|| "llama_tiny_layer_anchor_value"),
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
        #[cfg(feature = "llama-tiny")]
        {
            let syscall = step
                .syscall(&shard_ctx.syscall_witnesses)
                .ok_or_else(|| ZKVMError::InvalidWitness("TensorBus syscall missing".into()))?;
            let abi = syscall
                .mem_ops
                .first()
                .ok_or_else(|| ZKVMError::InvalidWitness("TensorBus descriptor missing".into()))?
                .value
                .before;
            let abi_v2 = u64::from(abi == ceno_emul::tensor::TENSOR_ABI_V2);
            set_val!(instance, config.abi_v2, abi_v2);
            if abi_v2 == 1 {
                let import_cycle = if S::CODE == TensorImportBeginV1Spec::CODE {
                    step.cycle()
                } else if S::CODE == TensorExportEndV1Spec::CODE {
                    syscall
                        .tensor_resident_boundary
                        .ok_or_else(|| {
                            ZKVMError::InvalidWitness("TensorBus v2 export boundary missing".into())
                        })?
                        .import_cycle
                } else {
                    syscall
                        .tensor_resident_matmul
                        .ok_or_else(|| {
                            ZKVMError::InvalidWitness(
                                "TensorBus v2 resident operator missing".into(),
                            )
                        })?
                        .import_cycle
                };
                set_val!(
                    instance,
                    config.import_cycle,
                    shard_ctx.aligned_current_ts(import_cycle)
                );
                if S::CODE == TensorImportBeginV1Spec::CODE
                    || S::CODE == TensorExportEndV1Spec::CODE
                {
                    let boundary = syscall.tensor_resident_boundary.ok_or_else(|| {
                        ZKVMError::InvalidWitness("TensorBus v2 boundary missing".into())
                    })?;
                    for (row, value) in boundary.values.into_iter().enumerate() {
                        instance[config.boundary_values[row].id as usize] = if value < 0 {
                            -E::BaseField::from_u64(u64::from(value.unsigned_abs()))
                        } else {
                            E::BaseField::from_u64(value as u64)
                        };
                        set_val!(instance, config.boundary_signs[row], u64::from(value < 0));
                    }
                } else {
                    let _resident = syscall.tensor_resident_matmul.ok_or_else(|| {
                        ZKVMError::InvalidWitness("TensorBus v2 resident operator missing".into())
                    })?;
                    let anchor_value = if S::CODE == TensorHandleAttentionV1Spec::CODE {
                        ceno_emul::tensor::llama_tiny::execute()
                            .map_err(|error| ZKVMError::InvalidWitness(error.to_string().into()))?
                            .input_norm[0][0]
                    } else {
                        ceno_emul::tensor::llama_tiny::execute()
                            .map_err(|error| ZKVMError::InvalidWitness(error.to_string().into()))?
                            .swiglu[0][0]
                    };
                    instance[config.layer_anchor_value.id as usize] = if anchor_value < 0 {
                        -E::BaseField::from_u64(u64::from(anchor_value.unsigned_abs()))
                    } else {
                        E::BaseField::from_u64(anchor_value as u64)
                    };
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct TensorBusEcallConfig<E: ExtensionField> {
    ecall: LargeEcallConfig<E>,
    key_shard_id: multilinear_extensions::WitIn,
    key_local_shard_cycle: multilinear_extensions::WitIn,
    key_ordinal: multilinear_extensions::WitIn,
    #[cfg(feature = "llama-tiny")]
    abi_v2: multilinear_extensions::WitIn,
    #[cfg(feature = "llama-tiny")]
    import_cycle: multilinear_extensions::WitIn,
    #[cfg(feature = "llama-tiny")]
    boundary_values: [multilinear_extensions::WitIn; 4],
    #[cfg(feature = "llama-tiny")]
    boundary_signs: [multilinear_extensions::WitIn; 4],
    #[cfg(feature = "llama-tiny")]
    layer_anchor_value: multilinear_extensions::WitIn,
}
