use std::{collections::HashSet, iter::zip, ops::Range};

use ceno_emul::{Addr, Cycle, IterAddresses, WORD_SIZE, Word};
use ff_ext::ExtensionField;
use itertools::{Itertools, chain};

use crate::{
    error::ZKVMError,
    structs::{ProgramParams, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        HeapCircuit, HintsCircuit, MemFinalRecord, MemInitRecord, NonVolatileTable, PubIOCircuit,
        PubIOTable, RegTable, RegTableCircuit, StackCircuit, StaticMemCircuit, StaticMemTable,
        TableCircuit,
    },
};

pub struct MmuConfig<E: ExtensionField> {
    /// Initialization of registers.
    pub reg_config: <RegTableCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of memory with static addresses.
    pub static_mem_config: <StaticMemCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of public IO.
    pub public_io_config: <PubIOCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of hints.
    pub hints_config: <HintsCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of heap.
    pub heap_config: <HeapCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of stack.
    pub stack_config: <StackCircuit<E> as TableCircuit<E>>::TableConfig,
    pub params: ProgramParams,
}

impl<E: ExtensionField> MmuConfig<E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let reg_config = cs.register_table_circuit::<RegTableCircuit<E>>();

        let static_mem_config = cs.register_table_circuit::<StaticMemCircuit<E>>();

        let public_io_config = cs.register_table_circuit::<PubIOCircuit<E>>();

        let hints_config = cs.register_table_circuit::<HintsCircuit<E>>();
        let stack_config = cs.register_table_circuit::<StackCircuit<E>>();
        let heap_config = cs.register_table_circuit::<HeapCircuit<E>>();

        Self {
            reg_config,
            static_mem_config,
            public_io_config,
            hints_config,
            stack_config,
            heap_config,
            params: cs.params.clone(),
        }
    }

    pub fn generate_fixed_traces(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        fixed: &mut ZKVMFixedTraces<E>,
        reg_init: &[MemInitRecord],
        static_mem_init: &[MemInitRecord],
        io_addrs: &[Addr],
    ) {
        assert!(
            chain!(
                static_mem_init.iter_addresses(),
                io_addrs.iter_addresses(),
                // TODO: optimize with min_max and Range.
                self.params.platform.hints.iter_addresses(),
            )
            .all_unique(),
            "memory addresses must be unique"
        );

        fixed.register_table_circuit::<RegTableCircuit<E>>(cs, &self.reg_config, reg_init);

        fixed.register_table_circuit::<StaticMemCircuit<E>>(
            cs,
            &self.static_mem_config,
            static_mem_init,
        );

        fixed.register_table_circuit::<PubIOCircuit<E>>(cs, &self.public_io_config, io_addrs);
        fixed.register_table_circuit::<HintsCircuit<E>>(cs, &self.hints_config, &());
        fixed.register_table_circuit::<StackCircuit<E>>(cs, &self.stack_config, &());
        fixed.register_table_circuit::<HeapCircuit<E>>(cs, &self.heap_config, &());
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        witness: &mut ZKVMWitnesses<E>,
        reg_final: &[MemFinalRecord],
        static_mem_final: &[MemFinalRecord],
        io_cycles: &[Cycle],
        hints_final: &[MemFinalRecord],
        stack_final: &[MemFinalRecord],
        heap_final: &[MemFinalRecord],
    ) -> Result<(), ZKVMError> {
        witness.assign_table_circuit::<RegTableCircuit<E>>(cs, &self.reg_config, reg_final)?;

        witness.assign_table_circuit::<StaticMemCircuit<E>>(
            cs,
            &self.static_mem_config,
            static_mem_final,
        )?;

        witness.assign_table_circuit::<PubIOCircuit<E>>(cs, &self.public_io_config, io_cycles)?;
        witness.assign_table_circuit::<HintsCircuit<E>>(cs, &self.hints_config, hints_final)?;
        witness.assign_table_circuit::<StackCircuit<E>>(cs, &self.stack_config, stack_final)?;
        witness.assign_table_circuit::<HeapCircuit<E>>(cs, &self.heap_config, heap_final)?;

        Ok(())
    }

    pub fn initial_registers(&self) -> Vec<MemInitRecord> {
        (0..<RegTable as NonVolatileTable>::len(&self.params))
            .map(|index| MemInitRecord {
                addr: index as Addr,
                value: 0,
            })
            .collect()
    }

    pub fn static_mem_len(&self) -> usize {
        <StaticMemTable as NonVolatileTable>::len(&self.params)
    }

    pub fn public_io_len(&self) -> usize {
        <PubIOTable as NonVolatileTable>::len(&self.params)
    }
}

pub struct MemPadder {
    valid_addresses: Range<Addr>,
    used_addresses: HashSet<Addr>,
}

impl MemPadder {
    /// Create memory records with uninitialized values.
    pub fn new_mem_records_uninit(
        address_range: Range<Addr>,
        padded_len: usize,
    ) -> Vec<MemInitRecord> {
        Self::new(address_range).padded_sorted(padded_len, vec![])
    }

    /// Create initial memory records.
    /// Store `values` at the start of `address_range`, in order.
    /// Pad with zero values up to `padded_len`.
    ///
    /// Require: `values.len() <= padded_len <= address_range.len()`
    pub fn new_mem_records(
        address_range: Range<Addr>,
        padded_len: usize,
        values: &[Word],
    ) -> Vec<MemInitRecord> {
        let mut records = Self::new_mem_records_uninit(address_range, padded_len);
        for (record, &value) in zip(&mut records, values) {
            record.value = value;
        }
        records
    }

    /// Initialize memory records created `new_mem_records_uninit` with values.
    ///
    /// Require: `values.len() <= padded_len <= address_range.len()`
    ///
    /// See `new_mem_records` for more details.
    pub fn init_mem_records(records: &mut Vec<MemInitRecord>, values: &[Word]) {
        for (record, &value) in zip(records, values) {
            record.value = value;
        }
    }

    pub fn new(valid_addresses: Range<Addr>) -> Self {
        Self {
            valid_addresses,
            used_addresses: HashSet::new(),
        }
    }

    /// Pad `records` to `new_len` with valid records.
    /// The padding uses fresh addresses not yet seen by this `MemPadder`.
    /// Sort the records by address.
    pub fn padded_sorted(
        &mut self,
        new_len: usize,
        records: Vec<MemInitRecord>,
    ) -> Vec<MemInitRecord> {
        if records.is_empty() {
            self.padded(new_len, records)
        } else {
            self.padded(new_len, records)
                .into_iter()
                .sorted_by_key(|record| record.addr)
                .collect()
        }
    }

    /// Pad `records` to `new_len` using unused addresses.
    fn padded(&mut self, new_len: usize, mut records: Vec<MemInitRecord>) -> Vec<MemInitRecord> {
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
        records
    }
}
