use std::{collections::HashMap, marker::PhantomData};

use ceno_emul::{Addr, Cycle, GetAddr, WORD_SIZE, Word};
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::InstancePaddingStrategy,
    structs::{ProgramParams, RAMType},
    tables::TableCircuit,
    witness::RowMajorMatrix,
};

use super::ram_impl::{DynVolatileRamTableConfig, NonVolatileTableConfig, PubIOTableConfig};

#[derive(Clone, Debug)]
pub struct MemInitRecord {
    pub addr: Addr,
    pub value: Word,
}

#[derive(Clone, Debug)]
pub struct MemFinalRecord {
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
pub struct NonVolatileRamCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, NVRAM: NonVolatileTable + Send + Sync + Clone> TableCircuit<E>
    for NonVolatileRamCircuit<E, NVRAM>
{
    type TableConfig = NonVolatileTableConfig<NVRAM>;
    type FixedInput = [MemInitRecord];
    type WitnessInput = [MemFinalRecord];

    fn name() -> String {
        format!("RAM_{:?}_{}", NVRAM::RAM_TYPE, NVRAM::name())
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb),
        )
    }

    fn generate_fixed_traces(
        config: &Self::TableConfig,
        num_fixed: usize,
        init_v: &Self::FixedInput,
    ) -> RowMajorMatrix<E::BaseField> {
        // assume returned table is well-formed include padding
        config.gen_init_state(num_fixed, init_v)
    }

    fn assign_instances(
        config: &Self::TableConfig,
        num_witin: usize,
        _multiplicity: &[HashMap<u64, usize>],
        final_v: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed include padding
        config.assign_instances(num_witin, final_v)
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

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb),
        )
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
        _multiplicity: &[HashMap<u64, usize>],
        final_cycles: &[Cycle],
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed including padding
        config.assign_instances(num_witin, final_cycles)
    }
}

/// - **Dynamic**: The address space is bounded within a specific range,
///   though the range itself may be dynamically determined per proof.
/// - **Volatile**: The initial values are set to `0`
pub trait DynVolatileRamTable {
    const RAM_TYPE: RAMType;
    const V_LIMBS: usize;
    const ZERO_INIT: bool;

    fn offset_addr(params: &ProgramParams) -> Addr;
    fn end_addr(params: &ProgramParams) -> Addr;

    fn name() -> &'static str;

    fn max_len(params: &ProgramParams) -> usize {
        let max_size =
            (Self::end_addr(params) - Self::offset_addr(params)).div_ceil(WORD_SIZE as u32) as Addr;
        1 << (u32::BITS - 1 - max_size.leading_zeros()) // prev_power_of_2
    }

    fn addr(params: &ProgramParams, entry_index: usize) -> Addr {
        Self::offset_addr(params) + (entry_index * WORD_SIZE) as Addr
    }
}

/// DynVolatileRamCircuit initializes and finalizes memory
/// - at witnessed addresses, in a contiguous range chosen by the prover,
/// - with zeros as initial content if ZERO_INIT,
/// - with witnessed final content that the program wrote.
///
/// If not ZERO_INIT:
/// - The initial content is an unconstrained prover hint.
/// - The final content is equal to this initial content.
pub struct DynVolatileRamCircuit<E, R>(PhantomData<(E, R)>);

impl<E: ExtensionField, DVRAM: DynVolatileRamTable + Send + Sync + Clone> TableCircuit<E>
    for DynVolatileRamCircuit<E, DVRAM>
{
    type TableConfig = DynVolatileRamTableConfig<DVRAM>;
    type FixedInput = ();
    type WitnessInput = [MemFinalRecord];

    fn name() -> String {
        format!("RAM_{:?}_{}", DVRAM::RAM_TYPE, DVRAM::name())
    }

    fn construct_circuit(cb: &mut CircuitBuilder<E>) -> Result<Self::TableConfig, ZKVMError> {
        cb.namespace(
            || Self::name(),
            |cb| Self::TableConfig::construct_circuit(cb),
        )
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
        _multiplicity: &[HashMap<u64, usize>],
        final_v: &Self::WitnessInput,
    ) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
        // assume returned table is well-formed include padding
        config.assign_instances(num_witin, final_v)
    }
}
