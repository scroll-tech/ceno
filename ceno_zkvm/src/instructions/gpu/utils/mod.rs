//! Host-side operations for GPU-CPU hybrid witness generation.
//!
//! Contains lookup/shard lk_shardram collection abstractions and CPU fallback paths.

mod emit;
mod fallback;
mod lk_ops;
mod sink;

// Re-export all public types for convenience
pub use emit::*;
pub use fallback::*;
pub use lk_ops::*;
pub use sink::*;

#[cfg(feature = "gpu")]
pub mod colmap_base;
#[cfg(feature = "gpu")]
pub mod d2h;
#[cfg(feature = "gpu")]
pub mod debug_compare;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::LkMultiplicity;
    use gkr_iop::tables::LookupTable;

    #[test]
    fn test_lk_op_encodings_match_cpu_multiplicity() {
        let ops = [
            LkOp::AssertU16 { value: 7 },
            LkOp::DynamicRange { value: 11, bits: 8 },
            LkOp::AssertU14 { value: 5 },
            LkOp::Fetch { pc: 0x1234 },
            LkOp::DoubleU8 { a: 1, b: 2 },
            LkOp::And { a: 3, b: 4 },
            LkOp::Or { a: 5, b: 6 },
            LkOp::Xor { a: 7, b: 8 },
            LkOp::Ltu { a: 9, b: 10 },
            LkOp::Pow2 { value: 12 },
            LkOp::ShrByte {
                shift: 3,
                carry: 17,
                bits: 2,
            },
        ];

        let mut lk = LkMultiplicity::default();
        for op in ops {
            for (table, key) in op.encode_all() {
                lk.increment(table, key);
            }
        }

        let finalized = lk.into_finalize_result();
        assert_eq!(finalized[LookupTable::Dynamic as usize].len(), 3);
        assert_eq!(finalized[LookupTable::Instruction as usize].len(), 1);
        assert_eq!(finalized[LookupTable::DoubleU8 as usize].len(), 3);
        assert_eq!(finalized[LookupTable::And as usize].len(), 1);
        assert_eq!(finalized[LookupTable::Or as usize].len(), 1);
        assert_eq!(finalized[LookupTable::Xor as usize].len(), 1);
        assert_eq!(finalized[LookupTable::Ltu as usize].len(), 1);
        assert_eq!(finalized[LookupTable::Pow as usize].len(), 1);
    }
}
