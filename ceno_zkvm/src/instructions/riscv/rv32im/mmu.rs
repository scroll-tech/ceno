use std::{collections::HashSet, ops::RangeInclusive};

use ceno_emul::{Addr, WORD_SIZE};
use ff_ext::ExtensionField;

use crate::{
    error::ZKVMError,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        MemFinalRecord, MemInitRecord, NonVolatileTable, ProgramDataCircuit, ProgramDataTable,
        PubIOCircuit, RegTableCircuit, TableCircuit,
    },
};

pub struct MmuConfig<E: ExtensionField> {
    pub reg_config: <RegTableCircuit<E> as TableCircuit<E>>::TableConfig,
    pub program_data_config: <ProgramDataCircuit<E> as TableCircuit<E>>::TableConfig,
    pub public_io_config: <PubIOCircuit<E> as TableCircuit<E>>::TableConfig,
}

impl<E: ExtensionField> MmuConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let reg_config = cs.register_table_circuit::<RegTableCircuit<E>>();

        let program_data_config = cs.register_table_circuit::<ProgramDataCircuit<E>>();

        let public_io_config = cs.register_table_circuit::<PubIOCircuit<E>>();

        Self {
            reg_config,
            program_data_config,
            public_io_config,
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
        reg_init: &[MemInitRecord],
        program_data_init: &[MemInitRecord],
    ) {
        fixed.register_table_circuit::<RegTableCircuit<E>>(cs, &self.reg_config, reg_init);

        fixed.register_table_circuit::<ProgramDataCircuit<E>>(
            cs,
            &self.program_data_config,
            program_data_init,
        );

        fixed.register_table_circuit::<PubIOCircuit<E>>(cs, &self.public_io_config, &());
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

        witness.assign_table_circuit::<ProgramDataCircuit<E>>(
            cs,
            &self.program_data_config,
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
        <ProgramDataTable as NonVolatileTable>::len()
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
    pub fn pad(&mut self, records: &mut Vec<MemInitRecord>, new_len: usize) {
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
}
