use std::{collections::HashSet, ops::RangeInclusive};

use ceno_emul::{Addr, WORD_SIZE};
use ff_ext::ExtensionField;

use crate::{
    error::ZKVMError,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        MemFinalRecord, MemInitRecord, NonVolatileTable, PubIOCircuit, PubIOTable, RegTableCircuit,
        StaticMemCircuit, StaticMemTable, TableCircuit,
    },
};

pub struct MmuConfig<E: ExtensionField> {
    /// Initialization of registers.
    pub reg_config: <RegTableCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of memory with static addresses.
    pub static_mem_config: <StaticMemCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of public IO.
    pub public_io_config: <PubIOCircuit<E> as TableCircuit<E>>::TableConfig,
}

impl<E: ExtensionField> MmuConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let reg_config = cs.register_table_circuit::<RegTableCircuit<E>>();

        let static_mem_config = cs.register_table_circuit::<StaticMemCircuit<E>>();

        let public_io_config = cs.register_table_circuit::<PubIOCircuit<E>>();

        Self {
            reg_config,
            static_mem_config,
            public_io_config,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
        reg_init: &[MemInitRecord],
        static_mem: &[MemInitRecord],
        io_addrs: &[Addr],
    ) {
        fixed.register_table_circuit::<RegTableCircuit<E>>(cs, &self.reg_config, reg_init);

        fixed.register_table_circuit::<StaticMemCircuit<E>>(
            cs,
            &self.static_mem_config,
            static_mem,
        );

        fixed.register_table_circuit::<PubIOCircuit<E>>(cs, &self.public_io_config, io_addrs);
    }

    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
        reg_final: &[MemFinalRecord],
        program_data_final: &[MemFinalRecord],
        public_io_final: &[MemFinalRecord],
    ) -> Result<(), ZKVMError> {
        witness.assign_table_circuit::<RegTableCircuit<E>>(cs, &self.reg_config, reg_final)?;

        witness.assign_table_circuit::<StaticMemCircuit<E>>(
            cs,
            &self.static_mem_config,
            program_data_final,
        )?;

        witness.assign_table_circuit::<PubIOCircuit<E>>(
            cs,
            &self.public_io_config,
            public_io_final,
        )?;

        Ok(())
    }

    pub fn static_mem_size() -> usize {
        <StaticMemTable as NonVolatileTable>::len()
    }

    pub fn public_io_size() -> usize {
        <PubIOTable as NonVolatileTable>::len()
    }
}

pub struct AddressPadder {
    valid_addresses: RangeInclusive<Addr>,
    used_addresses: HashSet<Addr>,
}

impl AddressPadder {
    pub fn new(valid_addresses: RangeInclusive<Addr>) -> Self {
        Self {
            valid_addresses,
            used_addresses: HashSet::new(),
        }
    }

    /// Pad `records` to `new_len` with valid records.
    /// No addresses will be used more than once.
    pub fn pad_records(&mut self, records: &mut Vec<MemInitRecord>, new_len: usize) {
        let old_len = records.len();
        assert!(
            old_len <= new_len,
            "cannot fit {old_len} memory records in {new_len} space"
        );

        // Keep track of addresses that were explicitly used.
        self.used_addresses
            .extend(records.iter().map(|record| record.addr));

        records.extend(
            // Search for some addresses in the given range.
            (&mut self.valid_addresses)
                .step_by(WORD_SIZE)
                // Exclude addresses already used.
                .filter(|addr| !self.used_addresses.contains(addr))
                // Create the padding records.
                .take(new_len - old_len)
                .map(|addr| MemInitRecord { addr, value: 0 }),
        );
        assert_eq!(
            records.len(),
            new_len,
            "not enough addresses to pad memory records from {old_len} to {new_len}"
        );
    }

    /// Pad `addresses` to `new_len` with valid records.
    /// No addresses will be used more than once.
    pub fn pad_addresses(&mut self, addresses: &mut Vec<Addr>, new_len: usize) {
        let old_len = addresses.len();
        assert!(
            old_len <= new_len,
            "cannot fit {old_len} memory addresses in {new_len} space"
        );

        // Keep track of addresses that were explicitly used.
        self.used_addresses.extend(addresses.iter());

        addresses.extend(
            // Search for some addresses in the given range.
            (&mut self.valid_addresses)
                .step_by(WORD_SIZE)
                // Exclude addresses already used.
                .filter(|addr| !self.used_addresses.contains(addr))
                // Create the padding.
                .take(new_len - old_len),
        );
        assert_eq!(
            addresses.len(),
            new_len,
            "not enough addresses to pad from {old_len} to {new_len}"
        );
    }
}
