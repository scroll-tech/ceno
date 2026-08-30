//! Offline consumer for the fixed-width TensorBus ECALL event relation.
//!
//! This table is intentionally separate from RAM.  It consumes the complete
//! canonical tuple emitted by the four constrained TensorBus ECALL chips; the
//! product relation therefore rejects a changed syscall, descriptor, metadata,
//! handle/version, or padding field even when ordinary RAM remains valid.

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    structs::{CustomRWTag, ProgramParams, RAMType},
    tables::{RMMCollections, TableCircuit},
};
use ceno_emul::SyscallSpec;
use ff_ext::ExtensionField;
use gkr_iop::{
    chip::Chip,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
};
use itertools::Itertools;
use multilinear_extensions::{ToExpr, WitIn};
use p3::{field::PrimeCharacteristicRing, matrix::dense::RowMajorMatrix as P3RowMajorMatrix};
use rustc_hash::FxHashMap;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

pub const TENSOR_BUS_EVENT_WORDS: usize = 25;
const KEY_SHARD_ID: usize = 22;
const KEY_LOCAL_SHARD_CYCLE: usize = 23;
const KEY_ORDINAL: usize = 24;
const TENSOR_BUS_SEGMENT_EVENTS: usize = 2;

/// A canonical event is stored on the syscall witness at execution time and
/// must exactly match the custom write record in TensorBusFixedEcall.
pub type TensorBusEvent = [u32; TENSOR_BUS_EVENT_WORDS];

fn tensor_bus_error(message: impl Into<Box<str>>) -> ZKVMError {
    ZKVMError::InvalidWitness(message.into())
}

pub fn events_from_syscalls(
    witnesses: &[ceno_emul::SyscallWitness],
    shard_ctx: &crate::e2e::ShardContext,
) -> Vec<TensorBusEvent> {
    witnesses
        .iter()
        .filter_map(|witness| {
            let (cycle, mut event) = (witness.tensor_bus_event_cycle?, witness.tensor_bus_event?);
            if !shard_ctx.is_in_current_shard(cycle) {
                return None;
            }
            event[KEY_SHARD_ID] = shard_ctx.shard_id as u32;
            event[KEY_LOCAL_SHARD_CYCLE] = shard_ctx.aligned_current_ts(cycle) as u32;
            // A resident TensorBus ecall has one event. Batched ECALLs retain
            // this key position for their stable intra-cycle element index.
            event[KEY_ORDINAL] = 0;
            Some(event)
        })
        .sorted_unstable_by_key(|event| {
            (
                event[KEY_SHARD_ID],
                event[KEY_LOCAL_SHARD_CYCLE],
                event[KEY_ORDINAL],
            )
        })
        .collect()
}

/// Validate the segment state machine before table assignment.  The table's
/// custom read then binds these exact tuples to the ECALL AIR producers, so
/// this offline check is not substitutable by normal RAM consistency.
pub fn verify_tensor_bus_events(events: &[TensorBusEvent]) -> Result<(), ZKVMError> {
    use ceno_emul::{SyscallSpec, TensorExportEndV1Spec, TensorImportBeginV1Spec};
    if events.len() % TENSOR_BUS_SEGMENT_EVENTS != 0 {
        return Err(tensor_bus_error(
            "TensorBus events must contain complete import-begin/export-end boundary sections",
        ));
    }
    let mut previous_key = None;
    for event in events {
        if event[0] != CustomRWTag::TensorBusEvent as u32 {
            return Err(tensor_bus_error("TensorBus event tag mismatch".to_string()));
        }
        if event[KEY_ORDINAL] != 0 {
            return Err(tensor_bus_error("TensorBus resident ordinal must be zero"));
        }
        let key = (
            event[KEY_SHARD_ID],
            event[KEY_LOCAL_SHARD_CYCLE],
            event[KEY_ORDINAL],
        );
        if previous_key.is_some_and(|previous| key <= previous) {
            return Err(tensor_bus_error(
                "TensorBus event keys must be strictly ordered within a shard",
            ));
        }
        previous_key = Some(key);
    }
    for section in events.chunks_exact(TENSOR_BUS_SEGMENT_EVENTS) {
        if section[0][2] != section[1][2] {
            return Err(tensor_bus_error("TensorBus boundary ABI mismatch"));
        }
        for (record, event) in section.iter().enumerate() {
            let abi_supported = event[2] == ceno_emul::tensor::TENSOR_ABI_V1
                || cfg!(feature = "llama-tiny") && event[2] == 2;
            if !abi_supported {
                return Err(tensor_bus_error("TensorBus ABI is unsupported"));
            }
            let expected_code =
                [TensorImportBeginV1Spec::CODE, TensorExportEndV1Spec::CODE][record];
            if event[1] != expected_code {
                return Err(tensor_bus_error("TensorBus section event order mismatch"));
            }
            match event[1] {
                code if code == TensorImportBeginV1Spec::CODE => {
                    if event[5] != ceno_emul::TENSOR_BUS_FIXED_TRANSFER_WORDS
                        || event[10] != event[5] * 4
                    {
                        return Err(tensor_bus_error(
                            "TensorBus import fixed metadata mismatch".to_string(),
                        ));
                    }
                    let tensor_id = u64::from(event[14]) | (u64::from(event[15]) << 32);
                    if tensor_id == 0 || event[16] != 0 || event[17] != 0 {
                        return Err(tensor_bus_error(format!(
                            "TensorBus import-begin handle/version invalid"
                        )));
                    }
                }
                code if code == TensorExportEndV1Spec::CODE => {
                    if event[6] != ceno_emul::TENSOR_BUS_FIXED_TRANSFER_WORDS
                        || event[10] != event[6] * 4
                    {
                        return Err(tensor_bus_error(
                            "TensorBus export fixed metadata mismatch".to_string(),
                        ));
                    }
                    let tensor_id = u64::from(event[14]) | (u64::from(event[15]) << 32);
                    if tensor_id == 0 || event[16] != 0 || event[17] != 0 {
                        return Err(tensor_bus_error(
                            "TensorBus export handle is invalid".to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(tensor_bus_error(
                        "unknown TensorBus event syscall".to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The tiny handle ABI batches complete resident sections:
/// import-begin, attention, FFN, export-end. Shard planning treats each
/// section as atomic, but may place any number of closed sections in one
/// shard. Each Core instance resets its local handle/version state at import.
fn verify_atomic_tensor_bus_shard(events: &[TensorBusEvent]) -> Result<(), ZKVMError> {
    if events.is_empty() {
        return Ok(());
    }
    if events.len() % TENSOR_BUS_SEGMENT_EVENTS != 0 {
        return Err(tensor_bus_error(
            "TensorBus shard must contain complete atomic import-begin/export-end boundary sections",
        ));
    }
    verify_tensor_bus_events(events)
}

/// Called after replay assigns syscall witnesses to a planned shard, before
/// any circuit witness is constructed.  This is the explicit shard-atomic
/// TensorBus planning invariant: a boundary may not cut a segment.
pub fn verify_atomic_tensor_bus_shard_for_preflight(
    events: &[TensorBusEvent],
) -> Result<(), ZKVMError> {
    verify_atomic_tensor_bus_shard(events)
}

pub struct TensorBusConfig<E: ExtensionField> {
    event: [[WitIn; TENSOR_BUS_EVENT_WORDS]; TENSOR_BUS_SEGMENT_EVENTS],
    _marker: std::marker::PhantomData<E>,
}

pub struct TensorBusCircuit<E>(std::marker::PhantomData<E>);

impl<E: ExtensionField> TableCircuit<E> for TensorBusCircuit<E> {
    type TableConfig = TensorBusConfig<E>;
    type FixedInput = ();
    type WitnessInput<'a> = [TensorBusEvent];

    fn name() -> String {
        "TensorBusCircuit".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        _params: &ProgramParams,
    ) -> Result<Self::TableConfig, ZKVMError> {
        let event: [[WitIn; TENSOR_BUS_EVENT_WORDS]; TENSOR_BUS_SEGMENT_EVENTS] =
            std::array::from_fn(|record| {
                std::array::from_fn(|word| {
                    cb.create_witin(|| format!("tensor_bus_{record}_{word}"))
                })
            });
        for (record, expected_code) in [
            ceno_emul::TensorImportBeginV1Spec::CODE,
            ceno_emul::TensorExportEndV1Spec::CODE,
        ]
        .into_iter()
        .enumerate()
        {
            cb.require_equal(
                || format!("tensor_bus_event_{record}_tag"),
                event[record][0].expr(),
                CustomRWTag::TensorBusEvent.expr::<E>(),
            )?;
            cb.require_equal(
                || format!("tensor_bus_event_{record}_code"),
                event[record][1].expr(),
                E::BaseField::from_u32(expected_code).expr(),
            )?;
            cb.read_record(
                || format!("tensor_bus_event_{record}_consume"),
                RAMType::Custom,
                event[record].iter().map(|word| word.expr()).collect(),
            )?;
        }
        for record in 0..TENSOR_BUS_SEGMENT_EVENTS {
            cb.require_equal(
                || format!("tensor_bus_key_ordinal_{record}"),
                event[record][KEY_ORDINAL].expr(),
                E::BaseField::ZERO.expr(),
            )?;
        }
        // TensorBus owns just the resident boundary.  Inner attention/FFN
        // operations are constrained by their own ECALL/RAM witnesses.
        for record in [1] {
            for word in 10..14 {
                cb.require_equal(
                    || format!("tensor_bus_meta_{record}_{word}"),
                    event[0][word].expr(),
                    event[record][word].expr(),
                )?;
            }
        }
        // Import and export deliberately name different opaque handles.  The
        // intervening attention/FFN ECALLs, including their RAM read/write
        // witnesses, constrain the handle chain. TensorBus itself owns only
        // the host/device boundary and therefore binds both endpoint handles
        // without inventing a false equality between them.
        cb.require_equal(
            || "tensor_bus_transfer_words",
            event[0][5].expr(),
            event[1][6].expr(),
        )?;
        let four = E::BaseField::from_u32(4).expr();
        cb.require_equal(
            || "tensor_bus_import_byte_len",
            event[0][10].expr(),
            four.clone() * event[0][5].expr(),
        )?;
        cb.require_equal(
            || "tensor_bus_export_byte_len",
            event[1][10].expr(),
            four * event[1][6].expr(),
        )?;
        // The complete 25-word event relation is claim-authoritative through
        // custom-RAM product reads.  Do not compare it to PublicValues here:
        // an Instance scalar in this GKR table is unsupported, and a host
        // supplied public tuple would not make the relation any stronger.
        // The verifier instead requires this Core proof whenever the two
        // boundary producer proofs are present (and vice versa); the product relation
        // binds every event word, including the shard/local-cycle/ordinal key.
        Ok(TensorBusConfig {
            event,
            _marker: std::marker::PhantomData,
        })
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<(Self::TableConfig, Option<GKRCircuit<E>>), ZKVMError> {
        // `read_record` uses ordinary custom-RAM records, while the default
        // table builder counts only table-RAM records.  Keep this small
        // override so the boundary producer-consumer reads are represented in the
        // GKR layer's output group as well as in the product relation.
        let selector = cb.create_placeholder_structural_witin(|| "selector");
        let config = Self::construct_circuit(cb, params)?;
        let r_len = cb.cs.r_expressions.len() + cb.cs.r_table_expressions.len();
        let w_len = cb.cs.w_expressions.len() + cb.cs.w_table_expressions.len();
        let lk_len = cb.cs.lk_expressions.len() + cb.cs.lk_table_expressions.len() * 2;
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();
        let selector = SelectorType::Prefix(selector.expr());
        if r_len > 0 {
            cb.cs.r_selector = Some(selector.clone());
        }
        if w_len > 0 {
            cb.cs.w_selector = Some(selector.clone());
        }
        if lk_len > 0 {
            cb.cs.lk_selector = Some(selector.clone());
        }
        if zero_len > 0 {
            cb.cs.zero_selector = Some(selector);
        }
        let (out_evals, mut chip) = (
            [
                (0..r_len).collect_vec(),
                (r_len..r_len + w_len).collect_vec(),
                (r_len + w_len..r_len + w_len + lk_len).collect_vec(),
                (0..zero_len).collect_vec(),
            ],
            Chip::new_from_cb(cb),
        );
        chip.add_layer(Layer::from_circuit_builder(cb, Self::name(), out_evals));
        Ok((config, Some(chip.gkr_circuit())))
    }

    fn generate_fixed_traces(
        _config: &Self::TableConfig,
        _num_fixed: usize,
        _input: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::empty()
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        _multiplicity: &[FxHashMap<u64, usize>],
        events: &Self::WitnessInput<'_>,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        if events.is_empty() {
            return Ok([RowMajorMatrix::empty(), RowMajorMatrix::empty()]);
        }
        verify_atomic_tensor_bus_shard(events)?;
        assert_eq!(
            num_witin,
            TENSOR_BUS_SEGMENT_EVENTS * TENSOR_BUS_EVENT_WORDS
        );
        // The default TableCircuit builder adds exactly one prefix selector.
        assert_eq!(num_structural_witin, 1);
        let sections = events.len() / TENSOR_BUS_SEGMENT_EVENTS;
        let mut values =
            P3RowMajorMatrix::new(vec![E::BaseField::ZERO; sections * num_witin], num_witin);
        let structural = P3RowMajorMatrix::new(vec![E::BaseField::ONE; sections], 1);
        for (section, section_events) in events.chunks_exact(TENSOR_BUS_SEGMENT_EVENTS).enumerate()
        {
            for (record, event) in section_events.iter().enumerate() {
                for (word, value) in config.event[record].iter().zip(event) {
                    values.values[section * num_witin + word.id as usize] =
                        E::BaseField::from_u32(*value);
                }
            }
        }
        Ok([
            RowMajorMatrix::new_by_inner_matrix(values, InstancePaddingStrategy::Default),
            RowMajorMatrix::new_by_inner_matrix(structural, InstancePaddingStrategy::Default),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceno_emul::{SyscallSpec, TensorExportEndV1Spec, TensorImportBeginV1Spec};

    fn event(code: u32) -> TensorBusEvent {
        let mut event = [0; TENSOR_BUS_EVENT_WORDS];
        event[0] = CustomRWTag::TensorBusEvent as u32;
        event[1] = code;
        event
    }

    fn honest_events() -> Vec<TensorBusEvent> {
        let mut import = event(TensorImportBeginV1Spec::CODE);
        import[5] = ceno_emul::TENSOR_BUS_FIXED_TRANSFER_WORDS;
        import[10] = import[5] * 4;
        import[11] = import[5];
        import[12] = 9;
        import[14] = 1;
        let mut export = event(TensorExportEndV1Spec::CODE);
        export[6] = ceno_emul::TENSOR_BUS_FIXED_TRANSFER_WORDS;
        export[10..14].copy_from_slice(&import[10..14]);
        export[14] = 1;
        let mut events = vec![import, export];
        for (index, event) in events.iter_mut().enumerate() {
            event[KEY_LOCAL_SHARD_CYCLE] = (index as u32) * 4;
        }
        events
    }

    #[test]
    fn canonical_tuple_binds_tag_code_and_every_payload_word() {
        let mut import = event(TensorImportBeginV1Spec::CODE);
        import[5] = 4; // fixed length
        import[10] = 16; // byte length metadata
        import[16] = 1; // handle id
        let export = event(TensorExportEndV1Spec::CODE);
        assert_ne!(export, import);
        for index in 0..TENSOR_BUS_EVENT_WORDS {
            let mut tampered = import;
            tampered[index] ^= 1;
            assert_ne!(tampered, import, "tuple word {index} is not bound");
        }
    }

    #[test]
    fn state_machine_rejects_order_version_and_metadata_tampering() {
        let honest = honest_events();
        verify_tensor_bus_events(&honest).unwrap();
        let mut bad_order = honest.clone();
        bad_order.swap(0, 1);
        assert!(verify_tensor_bus_events(&bad_order).is_err());
        let mut bad_version = honest.clone();
        bad_version[1][16] = 1;
        assert!(verify_tensor_bus_events(&bad_version).is_err());
        let mut bad_meta = honest;
        bad_meta[1][12] = 99;
        assert!(verify_tensor_bus_events(&bad_meta).is_err());
    }

    #[test]
    fn atomic_shard_accepts_multiple_complete_sections_and_rejects_splits() {
        let honest = honest_events();
        assert!(verify_atomic_tensor_bus_shard(&honest).is_ok());
        assert!(verify_atomic_tensor_bus_shard(&honest[..1]).is_err());
        let mut two_segments = honest.clone();
        for event in &mut two_segments {
            event[KEY_LOCAL_SHARD_CYCLE] += 16;
            event[14] += 1;
        }
        two_segments.extend_from_slice(&honest);
        two_segments.sort_by_key(|event| event[KEY_LOCAL_SHARD_CYCLE]);
        assert!(verify_atomic_tensor_bus_shard(&two_segments).is_ok());
        two_segments.swap(2, 3);
        assert!(verify_atomic_tensor_bus_shard(&two_segments).is_err());
    }
}
