//! CPU reference TensorBus records and segment lifetime.
//!
//! This is deliberately separate from the RISC-V RAM bus. It provides the
//! offline relation that future TensorBus AIR/tower code will consume; it does
//! not make ephemeral values guest-memory bytes.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, ensure};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TensorHandle {
    pub tensor_id: u64,
    pub version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorBusMeta {
    pub byte_len: usize,
    pub shape: Vec<u32>,
    pub quantization_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TensorBusSyscall {
    Import,
    Export,
    Operator(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorWriteRecord {
    pub segment_id: u64,
    pub handle: TensorHandle,
    pub meta: TensorBusMeta,
    pub producer: TensorBusSyscall,
    pub order: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorReadRecord {
    pub segment_id: u64,
    pub handle: TensorHandle,
    pub meta: TensorBusMeta,
    pub consumer: TensorBusSyscall,
    pub order: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TensorBusRecord {
    Write(TensorWriteRecord),
    Read(TensorReadRecord),
}

impl TensorBusRecord {
    /// Canonical, endian-stable offline/tower input. Shape length is explicit
    /// so metadata cannot be reinterpreted by a later relation revision.
    pub fn serialize(&self) -> Vec<u8> {
        let (tag, segment_id, handle, meta, syscall, order) = match self {
            Self::Write(record) => (
                0u32,
                record.segment_id,
                record.handle,
                &record.meta,
                record.producer,
                record.order,
            ),
            Self::Read(record) => (
                1u32,
                record.segment_id,
                record.handle,
                &record.meta,
                record.consumer,
                record.order,
            ),
        };
        let syscall = match syscall {
            TensorBusSyscall::Import => 0u32,
            TensorBusSyscall::Export => 1,
            TensorBusSyscall::Operator(code) => {
                code.checked_add(2).expect("TensorBus syscall id overflow")
            }
        };
        let mut bytes = Vec::with_capacity(48 + meta.shape.len() * 4);
        for word in [
            tag,
            syscall,
            handle.version,
            meta.quantization_id,
            meta.shape.len() as u32,
        ] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&segment_id.to_le_bytes());
        bytes.extend_from_slice(&handle.tensor_id.to_le_bytes());
        bytes.extend_from_slice(&(meta.byte_len as u64).to_le_bytes());
        bytes.extend_from_slice(&order.to_le_bytes());
        for dim in &meta.shape {
            bytes.extend_from_slice(&dim.to_le_bytes());
        }
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TensorValue {
    meta: TensorBusMeta,
    words: Vec<i32>,
}

/// CPU reference for one explicit TensorBus segment. Every record has a
/// canonical order slot, so this relation remains independent of RAM records.
#[derive(Debug)]
pub struct TensorBusSegment {
    segment_id: u64,
    next_tensor_id: u64,
    values: BTreeMap<TensorHandle, TensorValue>,
    records: Vec<TensorBusRecord>,
}

impl TensorBusSegment {
    pub fn begin(segment_id: u64) -> Result<Self> {
        ensure!(segment_id != 0, "tensor segment id zero is reserved");
        Ok(Self {
            segment_id,
            next_tensor_id: 1,
            values: BTreeMap::new(),
            records: Vec::new(),
        })
    }

    pub fn segment_id(&self) -> u64 {
        self.segment_id
    }

    pub fn records(&self) -> &[TensorBusRecord] {
        &self.records
    }

    pub fn import(&mut self, meta: TensorBusMeta, words: Vec<i32>) -> Result<TensorHandle> {
        self.write(meta, words, TensorBusSyscall::Import)
    }

    /// Consume one opaque handle and create one new single-assignment handle.
    pub fn apply<F>(
        &mut self,
        input: TensorHandle,
        output_meta: TensorBusMeta,
        operator: u32,
        transform: F,
    ) -> Result<TensorHandle>
    where
        F: FnOnce(&[i32]) -> Result<Vec<i32>>,
    {
        let input_words = self.read(input, TensorBusSyscall::Operator(operator))?;
        let output_words = transform(&input_words)?;
        self.write(
            output_meta,
            output_words,
            TensorBusSyscall::Operator(operator),
        )
    }

    pub fn export(&mut self, input: TensorHandle) -> Result<Vec<i32>> {
        self.read(input, TensorBusSyscall::Export)
    }

    pub fn end(self) -> Result<Vec<TensorBusRecord>> {
        verify_tensor_bus_records(&self.records)?;
        Ok(self.records)
    }

    fn write(
        &mut self,
        meta: TensorBusMeta,
        words: Vec<i32>,
        producer: TensorBusSyscall,
    ) -> Result<TensorHandle> {
        validate_value(&meta, &words)?;
        let handle = TensorHandle {
            tensor_id: self.next_tensor_id,
            version: 0,
        };
        self.next_tensor_id = self
            .next_tensor_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("tensor handle space exhausted"))?;
        let order = self.records.len() as u64;
        self.values.insert(
            handle,
            TensorValue {
                meta: meta.clone(),
                words,
            },
        );
        self.records.push(TensorBusRecord::Write(TensorWriteRecord {
            segment_id: self.segment_id,
            handle,
            meta,
            producer,
            order,
        }));
        Ok(handle)
    }

    fn read(&mut self, handle: TensorHandle, consumer: TensorBusSyscall) -> Result<Vec<i32>> {
        let value = self
            .values
            .get(&handle)
            .ok_or_else(|| anyhow!("unknown TensorBus handle {handle:?}"))?
            .clone();
        self.records.push(TensorBusRecord::Read(TensorReadRecord {
            segment_id: self.segment_id,
            handle,
            meta: value.meta,
            consumer,
            order: self.records.len() as u64,
        }));
        Ok(value.words)
    }
}

/// Offline TensorBus read/write relation. This is intentionally independent of
/// normal RAM consistency: only explicit import/export bridge the domains.
pub fn verify_tensor_bus_records(records: &[TensorBusRecord]) -> Result<()> {
    let mut writes = BTreeMap::<(u64, TensorHandle), (&TensorBusMeta, u64)>::new();
    let mut next_order = BTreeMap::<u64, u64>::new();
    for record in records {
        match record {
            TensorBusRecord::Write(write) => {
                ensure!(
                    write.segment_id != 0,
                    "TensorBus segment id zero is reserved"
                );
                let expected_order = next_order.entry(write.segment_id).or_default();
                ensure!(
                    write.order == *expected_order,
                    "TensorBus write order mismatch"
                );
                *expected_order += 1;
                ensure!(
                    write.handle.tensor_id != 0,
                    "TensorBus tensor id zero is reserved"
                );
                ensure!(
                    writes
                        .insert((write.segment_id, write.handle), (&write.meta, write.order))
                        .is_none(),
                    "TensorBus handle/version written more than once"
                );
            }
            TensorBusRecord::Read(read) => {
                ensure!(
                    read.segment_id != 0,
                    "TensorBus segment id zero is reserved"
                );
                let expected_order = next_order.entry(read.segment_id).or_default();
                ensure!(
                    read.order == *expected_order,
                    "TensorBus read order mismatch"
                );
                *expected_order += 1;
                let (written_meta, write_order) = writes
                    .get(&(read.segment_id, read.handle))
                    .ok_or_else(|| anyhow!("TensorBus read has no prior write"))?;
                ensure!(
                    *write_order < read.order,
                    "TensorBus read precedes its write"
                );
                ensure!(
                    *written_meta == &read.meta,
                    "TensorBus read metadata mismatch"
                );
            }
        }
    }
    Ok(())
}

/// Proof-side/offline ingestion seam for traced syscall witnesses. It never
/// consults RAM records, so a valid RAM trace cannot mask TensorBus tampering.
pub fn verify_tensor_bus_witnesses(witnesses: &[crate::SyscallWitness]) -> Result<()> {
    let records = witnesses
        .iter()
        .flat_map(|witness| witness.tensor_bus_records.iter().cloned())
        .collect::<Vec<_>>();
    verify_tensor_bus_records(&records)
}

fn validate_value(meta: &TensorBusMeta, words: &[i32]) -> Result<()> {
    ensure!(!meta.shape.is_empty(), "TensorBus shape must be nonempty");
    ensure!(
        meta.byte_len == words.len() * std::mem::size_of::<i32>(),
        "TensorBus byte length does not match words"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(words: usize) -> TensorBusMeta {
        TensorBusMeta {
            byte_len: words * 4,
            shape: vec![words as u32],
            quantization_id: 16,
        }
    }

    fn records() -> Vec<TensorBusRecord> {
        let mut segment = TensorBusSegment::begin(7).unwrap();
        let input = segment.import(meta(2), vec![3, 5]).unwrap();
        let output = segment
            .apply(input, meta(2), 42, |words| {
                Ok(words.iter().map(|word| word * 2).collect())
            })
            .unwrap();
        assert_eq!(segment.export(output).unwrap(), vec![6, 10]);
        segment.end().unwrap()
    }

    #[test]
    fn records_are_independent_from_ram_and_close_at_segment_end() {
        let records = records();
        assert_eq!(records.len(), 4);
        verify_tensor_bus_records(&records).unwrap();
    }

    #[test]
    fn rejects_version_tampering() {
        let mut records = records();
        let TensorBusRecord::Read(read) = &mut records[1] else {
            panic!("expected operator read");
        };
        read.handle.version = 1;
        assert!(verify_tensor_bus_records(&records).is_err());
    }

    #[test]
    fn rejects_metadata_tampering() {
        let mut records = records();
        let TensorBusRecord::Read(read) = &mut records[1] else {
            panic!("expected operator read");
        };
        read.meta.quantization_id = 20;
        assert!(verify_tensor_bus_records(&records).is_err());
    }

    #[test]
    fn rejects_order_tampering() {
        let mut records = records();
        let TensorBusRecord::Read(read) = &mut records[3] else {
            panic!("expected export read");
        };
        read.order = 1;
        assert!(verify_tensor_bus_records(&records).is_err());
    }

    #[test]
    fn serialization_binds_segment_order_version_and_metadata() {
        let records = records();
        let encoded = records[1].serialize();
        let mut version = records[1].clone();
        let TensorBusRecord::Read(read) = &mut version else {
            panic!("expected read");
        };
        read.handle.version = 1;
        assert_ne!(encoded, version.serialize());
        let mut meta = records[1].clone();
        let TensorBusRecord::Read(read) = &mut meta else {
            panic!("expected read");
        };
        read.meta.quantization_id = 20;
        assert_ne!(encoded, meta.serialize());
        let mut order = records[1].clone();
        let TensorBusRecord::Read(read) = &mut order else {
            panic!("expected read");
        };
        read.order += 1;
        assert_ne!(encoded, order.serialize());
    }
}
