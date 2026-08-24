use crate::{GpuReplayFallbackRecord, GpuTypedSoaArena, InsnKind};
use std::fmt;
use strum::EnumCount;

#[derive(Debug)]
pub struct GpuReplayTypedRange {
    pub sequence: u32,
    pub typed: Vec<Option<GpuTypedSoaArena>>,
    pub fallback: Vec<GpuReplayFallbackRecord>,
}

#[derive(Debug)]
pub struct GpuReplayShardArenas {
    /// Immutable, sequence-ordered exact range ownership. Fields remain SoA;
    /// replay validates cursors without appending, concatenating, sorting rows, or packing.
    pub ranges: Vec<GpuReplayTypedRange>,
    pub fallback: Vec<GpuReplayFallbackRecord>,
    pub unsupported: usize,
    family_totals: [usize; InsnKind::COUNT],
}

impl GpuReplayShardArenas {
    pub fn validate_supported(&self) -> Result<(), GpuReplayRoutingError> {
        if self.unsupported == 0 {
            Ok(())
        } else {
            Err(GpuReplayRoutingError {
                unsupported: self.unsupported,
            })
        }
    }

    pub fn family_total(&self, kind: InsnKind) -> usize {
        self.family_totals[kind as usize]
    }

    pub fn provisional(family_totals: [usize; InsnKind::COUNT]) -> Self {
        Self {
            ranges: Vec::new(),
            fallback: Vec::new(),
            unsupported: 0,
            family_totals,
        }
    }

    pub fn from_ranges(mut ranges: Vec<GpuReplayTypedRange>) -> Self {
        ranges.sort_unstable_by_key(|range| range.sequence);
        for (sequence, range) in ranges.iter().enumerate() {
            assert_eq!(range.sequence as usize, sequence, "GPU replay range gap");
            assert_eq!(range.typed.len(), InsnKind::COUNT);
        }
        let fallback_capacity = ranges.iter().map(|range| range.fallback.len()).sum();
        let mut fallback = Vec::with_capacity(fallback_capacity);
        let mut family_totals = [0usize; InsnKind::COUNT];
        for range in &mut ranges {
            for (kind, arena) in range.typed.iter().enumerate() {
                family_totals[kind] = family_totals[kind]
                    .checked_add(arena.as_ref().map_or(0, GpuTypedSoaArena::len))
                    .expect("GPU replay family total overflow");
            }
            fallback.append(&mut range.fallback);
        }
        Self {
            ranges,
            fallback,
            unsupported: 0,
            family_totals,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GpuReplayFallbackRecord;

    fn empty_typed() -> Vec<Option<GpuTypedSoaArena>> {
        (0..InsnKind::COUNT).map(|_| None).collect()
    }

    #[test]
    fn ranges_are_canonical_and_family_totals_are_exact() {
        let mut add = GpuTypedSoaArena::new(InsnKind::ADD, 1).unwrap();
        add.push_step(0, &Default::default()).unwrap();
        let mut typed = empty_typed();
        typed[InsnKind::ADD as usize] = Some(add);
        let ranges = vec![
            GpuReplayTypedRange {
                sequence: 1,
                typed: empty_typed(),
                fallback: vec![GpuReplayFallbackRecord {
                    ordinal: 9,
                    record: Default::default(),
                }],
            },
            GpuReplayTypedRange {
                sequence: 0,
                typed,
                fallback: Vec::new(),
            },
        ];
        let arenas = GpuReplayShardArenas::from_ranges(ranges);
        assert_eq!(
            arenas
                .ranges
                .iter()
                .map(|range| range.sequence)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(arenas.family_total(InsnKind::ADD), 1);
        assert_eq!(arenas.family_total(InsnKind::SUB), 0);
        assert_eq!(
            arenas
                .fallback
                .iter()
                .map(|record| record.ordinal)
                .collect::<Vec<_>>(),
            [9]
        );
        assert!(arenas.validate_supported().is_ok());
    }

    #[test]
    fn range_gap_and_unsupported_records_reject_without_repair() {
        let gap = std::panic::catch_unwind(|| {
            GpuReplayShardArenas::from_ranges(vec![GpuReplayTypedRange {
                sequence: 1,
                typed: empty_typed(),
                fallback: Vec::new(),
            }])
        });
        assert!(gap.is_err());

        let mut arenas = GpuReplayShardArenas::provisional([0; InsnKind::COUNT]);
        arenas.unsupported = 2;
        assert_eq!(arenas.validate_supported().unwrap_err().unsupported, 2);
        assert_eq!(arenas.unsupported, 2);
    }
}
