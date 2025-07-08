//! Definition of the ops tables and their circuits.

mod ops_impl;

mod ops_circuit;
use gkr_iop::tables::ops::{AndTable, LtuTable, OrTable, PowTable, XorTable};
pub use ops_circuit::OpsTableCircuit;

pub type AndTableCircuit<E> = OpsTableCircuit<E, AndTable>;
pub type OrTableCircuit<E> = OpsTableCircuit<E, OrTable>;
pub type XorTableCircuit<E> = OpsTableCircuit<E, XorTable>;
pub type LtuTableCircuit<E> = OpsTableCircuit<E, LtuTable>;
pub type PowTableCircuit<E> = OpsTableCircuit<E, PowTable>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        structs::ProgramParams,
        tables::TableCircuit,
    };
    use ff_ext::{GoldilocksExt2 as E, SmallField};
    use gkr_iop::tables::OpsTable;

    #[test]
    fn test_ops_pow_table_assign() {
        let mut cs = ConstraintSystem::<E>::new(|| "riscv");
        let mut cb = CircuitBuilder::new(&mut cs);

        let config =
            PowTableCircuit::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let fixed = PowTableCircuit::<E>::generate_fixed_traces(&config, cb.cs.num_fixed, &());

        for (i, row) in fixed.iter_rows().enumerate() {
            let (base, exp) = PowTable::unpack(i as u64);
            assert_eq!(PowTable::pack(base, exp), i as u64);
            assert_eq!(base, row[0].to_canonical_u64());
            assert_eq!(exp, row[1].to_canonical_u64());
            assert_eq!(base.pow(exp.try_into().unwrap()), row[2].to_canonical_u64());
        }
    }
}
