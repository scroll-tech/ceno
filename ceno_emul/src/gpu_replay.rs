use crate::{GpuReplayChunk, GpuReplayFallbackRecord, GpuReplayOrdinaryRecord, InsnKind, Program};
use std::{
    fmt,
    sync::{Arc, Mutex, mpsc::sync_channel},
    thread,
};
use strum::EnumCount;

#[derive(Debug)]
pub struct GpuReplayRoutedChunk {
    pub sequence: u32,
    pub families: Vec<Vec<GpuReplayOrdinaryRecord>>,
    pub fallback: Vec<GpuReplayFallbackRecord>,
    pub unsupported: Vec<GpuReplayOrdinaryRecord>,
}

#[derive(Debug)]
pub struct GpuReplayShardArenas {
    pub families: Vec<Vec<GpuReplayOrdinaryRecord>>,
    pub fallback: Vec<GpuReplayFallbackRecord>,
    pub unsupported: Vec<GpuReplayOrdinaryRecord>,
}

impl GpuReplayShardArenas {
    pub fn validate_supported(&self) -> Result<(), GpuReplayRoutingError> {
        if self.unsupported.is_empty() {
            Ok(())
        } else {
            Err(GpuReplayRoutingError {
                unsupported: self.unsupported.len(),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuReplayRoutingError {
    pub unsupported: usize,
}

impl fmt::Display for GpuReplayRoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GPU replay contains {} unsupported ordinary records; select complete legacy mode",
            self.unsupported
        )
    }
}

impl std::error::Error for GpuReplayRoutingError {}

/// Route sealed chunks on a bounded worker queue and concatenate worker-local
/// family arenas in canonical chunk order.
///
/// The caller remains the only producer. `sync_channel` applies backpressure
/// only while handing off a complete chunk; workers never append to shared
/// record vectors.
pub fn route_gpu_replay_chunks(
    chunks: impl IntoIterator<Item = GpuReplayChunk>,
    program: Arc<Program>,
    worker_count: usize,
    queue_depth: usize,
) -> GpuReplayShardArenas {
    assert!((2..=4).contains(&worker_count));
    assert!((2..=4).contains(&queue_depth));

    let (input_tx, input_rx) = sync_channel::<GpuReplayChunk>(queue_depth);
    let input_rx = Arc::new(Mutex::new(input_rx));
    let (output_tx, output_rx) = std::sync::mpsc::channel();

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let input_rx = input_rx.clone();
            let output_tx = output_tx.clone();
            let program = program.clone();
            scope.spawn(move || {
                loop {
                    let chunk = {
                        let receiver = input_rx.lock().expect("GPU replay queue poisoned");
                        receiver.recv()
                    };
                    let Ok(chunk) = chunk else { break };
                    output_tx
                        .send(route_chunk(chunk, &program))
                        .expect("GPU replay result receiver dropped");
                }
            });
        }
        drop(output_tx);
        for chunk in chunks {
            input_tx
                .send(chunk)
                .expect("GPU replay worker queue closed");
        }
        drop(input_tx);
    });

    let mut routed = output_rx.into_iter().collect::<Vec<_>>();
    routed.sort_unstable_by_key(|chunk| chunk.sequence);
    let mut family_counts = vec![0usize; InsnKind::COUNT];
    let mut fallback_count = 0usize;
    let mut unsupported_count = 0usize;
    for chunk in &routed {
        for (count, family) in family_counts.iter_mut().zip(&chunk.families) {
            *count += family.len();
        }
        fallback_count += chunk.fallback.len();
        unsupported_count += chunk.unsupported.len();
    }
    let mut arenas = GpuReplayShardArenas {
        families: family_counts.into_iter().map(Vec::with_capacity).collect(),
        fallback: Vec::with_capacity(fallback_count),
        unsupported: Vec::with_capacity(unsupported_count),
    };
    for chunk in routed {
        for (target, source) in arenas.families.iter_mut().zip(chunk.families) {
            target.extend(source);
        }
        arenas.fallback.extend(chunk.fallback);
        arenas.unsupported.extend(chunk.unsupported);
    }
    arenas
}

fn route_chunk(chunk: GpuReplayChunk, program: &Program) -> GpuReplayRoutedChunk {
    let mut families = (0..InsnKind::COUNT).map(|_| Vec::new()).collect::<Vec<_>>();
    let mut unsupported = Vec::new();
    for record in chunk.ordinary {
        let relative_pc = record.pc_before.wrapping_sub(program.base_address);
        let Some(instruction) = program.instructions.get((relative_pc / 4) as usize) else {
            unsupported.push(record);
            continue;
        };
        if instruction.raw != record.raw_instruction || instruction.kind == InsnKind::ECALL {
            unsupported.push(record);
            continue;
        }
        families[instruction.kind as usize].push(record);
    }
    GpuReplayRoutedChunk {
        sequence: chunk.sequence,
        families,
        fallback: chunk.fallback,
        unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CENO_PLATFORM, FullTracer, encode_rv32};

    fn chunk(sequence: u32, ordinal: u32, pc: u32, raw_instruction: u32) -> GpuReplayChunk {
        GpuReplayChunk {
            sequence,
            shard_start_cycle: FullTracer::SUBCYCLES_PER_INSN,
            ordinary: vec![GpuReplayOrdinaryRecord {
                ordinal,
                pc_before: pc,
                raw_instruction,
                ..Default::default()
            }],
            fallback: Vec::new(),
        }
    }

    #[test]
    fn bounded_router_concatenates_in_chunk_order() {
        let add = encode_rv32(InsnKind::ADD, 3, 1, 2, 0);
        let sub = encode_rv32(InsnKind::SUB, 3, 1, 2, 0);
        let program = Arc::new(Program::from([add, sub].as_slice()));
        let base = CENO_PLATFORM.pc_base();
        let arenas = route_gpu_replay_chunks(
            [chunk(1, 1, base + 4, sub.raw), chunk(0, 0, base, add.raw)],
            program,
            2,
            2,
        );
        arenas.validate_supported().unwrap();
        assert_eq!(arenas.families[InsnKind::ADD as usize][0].ordinal, 0);
        assert_eq!(arenas.families[InsnKind::SUB as usize][0].ordinal, 1);
    }

    #[test]
    fn router_retains_unrecognized_records_explicitly() {
        let add = encode_rv32(InsnKind::ADD, 3, 1, 2, 0);
        let program = Arc::new(Program::from([add].as_slice()));
        let arenas = route_gpu_replay_chunks(
            [chunk(0, 0, CENO_PLATFORM.pc_base(), add.raw ^ 1)],
            program,
            2,
            2,
        );
        assert_eq!(arenas.unsupported.len(), 1);
        assert_eq!(arenas.validate_supported().unwrap_err().unsupported, 1);
    }
}
