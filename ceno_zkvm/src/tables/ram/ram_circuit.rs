use std::{collections::HashMap, marker::PhantomData};

use super::ram_impl::{
    LocalFinalRAMTableConfig, NonVolatileTableConfigTrait, PubIOTableConfig, RAMBusConfig,
};
use crate::{
    circuit_builder::CircuitBuilder,
    e2e::ShardContext,
    error::ZKVMError,
    structs::{ProgramParams, RAMType},
    tables::{RMMCollections, TableCircuit},
};
use ceno_emul::{Addr, Cycle, GetAddr, WORD_SIZE, Word};
use ff_ext::{ExtensionField, SmallField};
use gkr_iop::{
    chip::Chip,
    error::CircuitBuilderError,
    gkr::{GKRCircuit, layer::Layer},
    selector::SelectorType,
};
use itertools::Itertools;
use multilinear_extensions::{StructuralWitInType, ToExpr};
use p3::field::FieldAlgebra;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

#[derive(Clone, Debug)]
pub struct MemInitRecord {
    pub addr: Addr,
    pub value: Word,
}

#[derive(Clone, Debug)]
pub struct MemFinalRecord {
    pub ram_type: RAMType,
    pub addr: Addr,
    pub cycle: Cycle,
    pub value: Word,
}

impl GetAddr for MemInitRecord {
    fn get_addr(&self) -> Addr {
        self.addr
    }
}

impl GetAddr for MemFinalRecord {
    fn get_addr(&self) -> Addr {
        self.addr
    }
}

/// - **Non-Volatile**: The initial values can be set to any arbitrary value.
///
/// **Special Note**:
/// Setting `WRITABLE = false` does not strictly enforce immutability in this protocol.
/// it only guarantees that the initial and final values remain invariant,
/// allowing for temporary modifications within the lifecycle.
pub trait NonVolatileTable {
    const RAM_TYPE: RAMType;
    const V_LIMBS: usize;
    const WRITABLE: bool;

    fn name() -> &'static str;

    /// Maximum number of words in the table.
    fn len(params: &ProgramParams) -> usize;
}

/// NonVolatileRamCircuit initializes and finalizes memory
/// - at fixed addresses,
/// - with fixed initial content,
/// - with witnessed final content that the program wrote, if WRITABLE,
/// - or final content equal to initial content, if not WRITABLE.
pub struct NonVolatileRamCircuit<E, R, C>(PhantomData<(E, R, C)>);

impl<
    E: ExtensionField,
    NVRAM: NonVolatileTable + Send + Sync + Clone,
    C: NonVolatileTableConfigTrait<NVRAM>,
> TableCircuit<E> for NonVolatileRamCircuit<E, NVRAM, C>
{
    type TableConfig = C::Config;
    type FixedInput = [MemInitRecord];
    type WitnessInput = [MemFinalRecord];

    fn name() -> String {
        format!("RAM_{:?}_{}", NVRAM::RAM_TYPE, NVRAM::name())
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self::TableConfig, ZKVMError> {
        Ok(cb.namespace(|| Self::name(), |cb| C::construct_circuit(cb, params))?)
    }

    fn generate_fixed_traces(
        config: &Self::TableConfig,
        num_fixed: usize,
        init_v: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        // assume returned table is well-formed include padding
        C::gen_init_state(config, num_fixed, init_v)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        final_v: &Self::WitnessInput,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed include padding
        Ok(C::assign_instances(
            config,
            num_witin,
            num_structural_witin,
            final_v,
        )?)
    }
}

/// PubIORamCircuit initializes and finalizes memory
/// - at fixed addresses,
/// - with content from the public input of proofs.
///
/// This circuit does not and cannot decide whether the memory is mutable or not.
/// It supports LOAD where the program reads the public input,
/// or STORE where the memory content must equal the public input after execution.
pub struct PubIORamCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, NVRAM: NonVolatileTable + Send + Sync + Clone> TableCircuit<E>
    for PubIORamCircuit<E, NVRAM>
{
    type TableConfig = PubIOTableConfig<NVRAM>;
    type FixedInput = [Addr];
    type WitnessInput = [Cycle];

    fn name() -> String {
        format!("RAM_{:?}_{}", NVRAM::RAM_TYPE, NVRAM::name())
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self::TableConfig, ZKVMError> {
        Ok(cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb, params),
        )?)
    }

    fn generate_fixed_traces(
        config: &Self::TableConfig,
        num_fixed: usize,
        io_addrs: &[Addr],
    ) -> RowMajorMatrix<E::BaseField> {
        // assume returned table is well-formed including padding
        config.gen_init_state(num_fixed, io_addrs)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        final_cycles: &[Cycle],
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed including padding
        Ok(config.assign_instances(num_witin, num_structural_witin, final_cycles)?)
    }
}

/// - **Dynamic**: The address space is bounded within a specific range,
///   though the range itself may be dynamically determined per proof.
/// - **Volatile**: The initial values are set to `0`
pub trait DynVolatileRamTable {
    const RAM_TYPE: RAMType;
    const V_LIMBS: usize;
    const ZERO_INIT: bool;
    const DESCENDING: bool;

    fn offset_addr(params: &ProgramParams) -> Addr;
    fn end_addr(params: &ProgramParams) -> Addr;

    fn name() -> &'static str;

    fn max_len(params: &ProgramParams) -> usize {
        let max_size = (if Self::DESCENDING {
            Self::offset_addr(params) - Self::end_addr(params)
        } else {
            Self::end_addr(params) - Self::offset_addr(params)
        })
        .div_ceil(WORD_SIZE as u32) as Addr;
        1 << (u32::BITS - 1 - max_size.leading_zeros()) // prev_power_of_2
    }

    fn addr(params: &ProgramParams, entry_index: usize) -> Addr {
        if Self::DESCENDING {
            Self::offset_addr(params) - (entry_index * WORD_SIZE) as Addr
        } else {
            // ascending
            Self::offset_addr(params) + (entry_index * WORD_SIZE) as Addr
        }
    }
}

pub trait DynVolatileRamTableConfigTrait<DVRAM>: Sized + Send + Sync {
    type Config: Sized + Send + Sync;
    fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self::Config, CircuitBuilderError>;
    fn assign_instances<F: SmallField>(
        config: &Self::Config,
        num_witin: usize,
        num_structural_witin: usize,
        final_mem: &[MemFinalRecord],
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError>;
}

/// DynVolatileRamCircuit initializes and finalizes memory
/// - at witnessed addresses, in a contiguous range chosen by the prover,
/// - with zeros as initial content if ZERO_INIT,
/// - with witnessed final content that the program wrote.
///
/// If not ZERO_INIT:
/// - The initial content is an unconstrained prover hint.
/// - The final content is equal to this initial content.
pub struct DynVolatileRamCircuit<E, R, C>(PhantomData<(E, R, C)>);

impl<
    E: ExtensionField,
    DVRAM: DynVolatileRamTable + Send + Sync + Clone,
    C: DynVolatileRamTableConfigTrait<DVRAM>,
> TableCircuit<E> for DynVolatileRamCircuit<E, DVRAM, C>
{
    type TableConfig = C::Config;
    type FixedInput = ();
    type WitnessInput = [MemFinalRecord];

    fn name() -> String {
        format!("RAM_{:?}_{}", DVRAM::RAM_TYPE, DVRAM::name())
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self::TableConfig, ZKVMError> {
        Ok(cb.namespace(|| Self::name(), |cb| C::construct_circuit(cb, params))?)
    }

    fn generate_fixed_traces(
        _config: &Self::TableConfig,
        _num_fixed: usize,
        _init_v: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::<E::BaseField>::new(0, 0, InstancePaddingStrategy::Default)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        final_v: &Self::WitnessInput,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed include padding
        Ok(
            <C as DynVolatileRamTableConfigTrait<DVRAM>>::assign_instances(
                config,
                num_witin,
                num_structural_witin,
                final_v,
            )?,
        )
    }
}

/// This circuit is generalized version to handle all mmio records
pub struct LocalFinalRamCircuit<'a, const V_LIMBS: usize, E>(PhantomData<(&'a (), E)>);

impl<'a, E: ExtensionField, const V_LIMBS: usize> TableCircuit<E>
    for LocalFinalRamCircuit<'a, V_LIMBS, E>
{
    type TableConfig = LocalFinalRAMTableConfig<V_LIMBS>;
    type FixedInput = ();
    type WitnessInput = (
        &'a ShardContext<'a>,
        &'a [(InstancePaddingStrategy, &'a [MemFinalRecord])],
    );

    fn name() -> String {
        "LocalRAMTableFinal".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self::TableConfig, ZKVMError> {
        Ok(cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb, params),
        )?)
    }

    fn build_gkr_iop_circuit(
        cb: &mut CircuitBuilder<E>,
        param: &ProgramParams,
    ) -> Result<(Self::TableConfig, Option<GKRCircuit<E>>), ZKVMError> {
        let config = Self::construct_circuit(cb, param)?;
        let r_table_len = cb.cs.r_table_expressions.len();

        let selector = cb.create_structural_witin(
            || "selector",
            StructuralWitInType::EqualDistanceSequence {
                // TODO determin proper size of max length
                max_len: u32::MAX as usize,
                offset: 0,
                multi_factor: 0,
                descending: false,
            },
        );
        let selector_type = SelectorType::Prefix(E::BaseField::ZERO, selector.expr());

        // all shared the same selector
        let (out_evals, mut chip) = (
            [
                // r_record
                (0..r_table_len).collect_vec(),
                // w_record
                vec![],
                // lk_record
                vec![],
                // zero_record
                vec![],
            ],
            Chip::new_from_cb(cb, 0),
        );

        // register selector to legacy constrain system
        cb.cs.r_selector = Some(selector_type.clone());

        let layer = Layer::from_circuit_builder(cb, "Rounds".to_string(), 0, out_evals);
        chip.add_layer(layer);

        Ok((config, Some(chip.gkr_circuit())))
    }

    fn generate_fixed_traces(
        _config: &Self::TableConfig,
        _num_fixed: usize,
        _init_v: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::<E::BaseField>::new(0, 0, InstancePaddingStrategy::Default)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        (shard_ctx, final_mem): &Self::WitnessInput,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed include padding
        Ok(Self::TableConfig::assign_instances(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            final_mem,
        )?)
    }
}

/// This circuit is generalized version to handle all mmio records
pub struct RamBusCircuit<'a, const V_LIMBS: usize, E>(PhantomData<(&'a (), E)>);

impl<'a, E: ExtensionField, const V_LIMBS: usize> TableCircuit<E>
    for RamBusCircuit<'a, V_LIMBS, E>
{
    type TableConfig = RAMBusConfig<V_LIMBS>;
    type FixedInput = ();
    type WitnessInput = ShardContext<'a>;

    fn name() -> String {
        "RamBusCircuit".to_string()
    }

    fn construct_circuit(
        cb: &mut CircuitBuilder<E>,
        params: &ProgramParams,
    ) -> Result<Self::TableConfig, ZKVMError> {
        Ok(cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb, params),
        )?)
    }

    fn generate_fixed_traces(
        _config: &Self::TableConfig,
        _num_fixed: usize,
        _init_v: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        RowMajorMatrix::<E::BaseField>::new(0, 0, InstancePaddingStrategy::Default)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        num_structural_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        shard_ctx: &Self::WitnessInput,
    ) -> Result<RMMCollections<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed include padding
        Ok(Self::TableConfig::assign_instances(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
        )?)
    }
}
