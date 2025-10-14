use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    structs::{ProgramParams, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{
        DynVolatileRamTable, HeapInitCircuit, HeapTable, HintsCircuit, LocalFinalCircuit,
        MemFinalRecord, MemInitRecord, NonVolatileTable, PubIOCircuit, PubIOTable, RBCircuit,
        RegTable, RegTableInitCircuit, StackInitCircuit, StackTable, StaticMemInitCircuit,
        StaticMemTable, TableCircuit,
    },
};
use ceno_emul::{Addr, Cycle, IterAddresses, WORD_SIZE, Word};
use ff_ext::ExtensionField;
use itertools::{Itertools, chain};
use std::{collections::HashSet, iter::zip, ops::Range, sync::Arc};
use witness::InstancePaddingStrategy;

pub struct MmuConfig<'a, E: ExtensionField> {
    /// Initialization of registers.
    pub reg_init_config: <RegTableInitCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of memory with static addresses.
    pub static_mem_init_config: <StaticMemInitCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of public IO.
    pub public_io_config: <PubIOCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of hints.
    pub hints_config: <HintsCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of heap.
    pub heap_init_config: <HeapInitCircuit<E> as TableCircuit<E>>::TableConfig,
    /// Initialization of stack.
    pub stack_init_config: <StackInitCircuit<E> as TableCircuit<E>>::TableConfig,
    /// finalized circuit for all MMIO
    pub local_final_circuit: <LocalFinalCircuit<'a, E> as TableCircuit<E>>::TableConfig,
    /// ram bus to deal with cross shard read/write
    pub ram_bus_circuit: <RBCircuit<E> as TableCircuit<E>>::TableConfig,
    pub params: ProgramParams,
}

impl<E: ExtensionField> MmuConfig<'_, E> {
    pub fn construct_circuits(cs: &mut ZKVMConstraintSystem<E>) -> Self {
        let reg_init_config = cs.register_table_circuit::<RegTableInitCircuit<E>>();

        let static_mem_init_config = cs.register_table_circuit::<StaticMemInitCircuit<E>>();

        let public_io_config = cs.register_table_circuit::<PubIOCircuit<E>>();

        let hints_config = cs.register_table_circuit::<HintsCircuit<E>>();
        let stack_init_config = cs.register_table_circuit::<StackInitCircuit<E>>();
        let heap_init_config = cs.register_table_circuit::<HeapInitCircuit<E>>();
        let local_final_circuit = cs.register_table_circuit::<LocalFinalCircuit<E>>();
        let ram_bus_circuit = cs.register_table_circuit::<RBCircuit<E>>();

        Self {
            reg_init_config,
            static_mem_init_config,
            public_io_config,
            hints_config,
            stack_init_config,
            heap_init_config,
            local_final_circuit,
            ram_bus_circuit,
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

        fixed.register_table_circuit::<RegTableInitCircuit<E>>(cs, &self.reg_init_config, reg_init);

        fixed.register_table_circuit::<StaticMemInitCircuit<E>>(
            cs,
            &self.static_mem_init_config,
            static_mem_init,
        );

        fixed.register_table_circuit::<PubIOCircuit<E>>(cs, &self.public_io_config, io_addrs);
        fixed.register_table_circuit::<HintsCircuit<E>>(cs, &self.hints_config, &());
        fixed.register_table_circuit::<StackInitCircuit<E>>(cs, &self.stack_init_config, &());
        fixed.register_table_circuit::<HeapInitCircuit<E>>(cs, &self.heap_init_config, &());
        fixed.register_table_circuit::<LocalFinalCircuit<E>>(cs, &self.local_final_circuit, &());
        fixed.register_table_circuit::<RBCircuit<E>>(cs, &self.ram_bus_circuit, &());
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_table_circuit(
        &self,
        cs: &ZKVMConstraintSystem<E>,
        shard_ctx: &ShardContext,
        witness: &mut ZKVMWitnesses<E>,
        reg_final: &[MemFinalRecord],
        static_mem_final: &[MemFinalRecord],
        io_cycles: &[Cycle],
        hints_final: &[MemFinalRecord],
        stack_final: &[MemFinalRecord],
        heap_final: &[MemFinalRecord],
    ) -> Result<(), ZKVMError> {
        witness.assign_table_circuit::<RegTableInitCircuit<E>>(
            cs,
            &self.reg_init_config,
            reg_final,
        )?;

        witness.assign_table_circuit::<StaticMemInitCircuit<E>>(
            cs,
            &self.static_mem_init_config,
            static_mem_final,
        )?;

        witness.assign_table_circuit::<PubIOCircuit<E>>(cs, &self.public_io_config, io_cycles)?;
        witness.assign_table_circuit::<HintsCircuit<E>>(cs, &self.hints_config, hints_final)?;
        witness.assign_table_circuit::<StackInitCircuit<E>>(
            cs,
            &self.stack_init_config,
            stack_final,
        )?;
        witness.assign_table_circuit::<HeapInitCircuit<E>>(
            cs,
            &self.heap_init_config,
            heap_final,
        )?;

        let all_records = vec![
            (InstancePaddingStrategy::Default, reg_final),
            (InstancePaddingStrategy::Default, static_mem_final),
            (
                InstancePaddingStrategy::Custom({
                    let params = cs.params.clone();
                    Arc::new(move |row: u64, _: u64| StackTable::addr(&params, row as usize) as u64)
                }),
                stack_final,
            ),
            (
                InstancePaddingStrategy::Custom({
                    let params = cs.params.clone();
                    Arc::new(move |row: u64, _: u64| HeapTable::addr(&params, row as usize) as u64)
                }),
                heap_final,
            ),
        ];
        // take all mem result and
        witness.assign_table_circuit::<LocalFinalCircuit<E>>(
            cs,
            &self.local_final_circuit,
            &(shard_ctx, all_records.as_slice()),
        )?;

        witness.assign_table_circuit::<RBCircuit<E>>(cs, &self.ram_bus_circuit, todo!())?;

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
        assert!(
            values.len() <= padded_len,
            "values.len() {} exceeds padded_len {}",
            values.len(),
            padded_len
        );
        let address_capacity = address_range.iter_addresses().len();
        assert!(
            padded_len <= address_capacity,
            "padded_len {} exceeds address_range capacity {}",
            padded_len,
            address_capacity
        );
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
        assert!(
            values.len() <= records.len(),
            "values.len() {} exceeds records.len() {}",
            values.len(),
            records.len()
        );
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
